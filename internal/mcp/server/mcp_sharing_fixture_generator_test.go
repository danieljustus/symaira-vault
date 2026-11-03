package server

// MCP-003 sharing corpus: request_share, approve_share, revoke_share and
// list_shares driven through the real Go protocol handler over a seeded share
// store, so the parity evidence survives the removal of the Go implementation.
//
// The Go server never attaches a ShareStore in production (the nil pin in
// authz-matrix.json), so the corpus attaches one the way the in-package
// handler tests do and keeps the nil-store behaviour as explicit go_defect
// cases. Everything that differs per run is canonicalised here and by the
// Rust replay with the same rules (see Normalizations in the fixture).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

const sharingOracleCommit = "ac481774bad3cf5c3445c2fbd680d3b29940e723"

type sharingFixture struct {
	SchemaVersion  int           `json:"schema_version"`
	Oracle         sharingOracle `json:"oracle"`
	ServerName     string        `json:"server_name"`
	ServerVersion  string        `json:"server_version"`
	Normalizations []string      `json:"normalizations"`
	Cases          []sharingCase `json:"cases"`
}

type sharingOracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	SourceFiles     []string `json:"source_files"`
	SourceHash      string   `json:"source_hash"`
	SourcePinDigest string   `json:"source_pin_digest"`
	GoVersion       string   `json:"go_version"`
	CorekitVersion  string   `json:"corekit_version"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorHash   string   `json:"generator_hash"`
}

type sharingApproval struct {
	TTY   bool   `json:"tty"`
	Reply string `json:"reply,omitempty"`
	// Error is "", "timeout", "read:<text>" or "raw:<text>".
	Error string `json:"error,omitempty"`
}

type sharingStep struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
	Response  map[string]any `json:"response,omitempty"`
	GoPanic   string         `json:"go_panic,omitempty"`
	Prompt    string         `json:"prompt,omitempty"`
}

type sharingAuditRow struct {
	Action string `json:"action"`
	Path   string `json:"path,omitempty"`
	OK     bool   `json:"ok"`
}

type sharingCase struct {
	Name         string            `json:"name"`
	Kind         string            `json:"kind"`
	Agent        string            `json:"agent"`
	AllowedPaths []string          `json:"allowed_paths"`
	SigningKey   bool              `json:"signing_key"`
	NoShareStore bool              `json:"no_share_store,omitempty"`
	Seed         []map[string]any  `json:"seed"`
	Approval     sharingApproval   `json:"approval"`
	Steps        []sharingStep     `json:"steps"`
	IDShapes     []string          `json:"id_shapes,omitempty"`
	Store        []map[string]any  `json:"store"`
	Audit        []sharingAuditRow `json:"audit"`
}

var sharingTimeKeys = []string{"created_at", "approved_at", "revoked_at", "expires_at"}

var (
	sharingHexID  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	sharingHMACID = regexp.MustCompile(`^[0-9a-f]{32}:[0-9a-f]{64}$`)
)

func sharingSeedGrant(id, from, to, path, status string, extra map[string]any) map[string]any {
	g := map[string]any{
		"id": id, "from_agent": from, "to_agent": to, "secret_path": path,
		"status": status, "created_at": "2026-01-02T03:04:05Z",
	}
	for k, v := range extra {
		g[k] = v
	}
	return g
}

func sharingSeedAll() []map[string]any {
	const hour = int64(3600) * int64(time.Second)
	return []map[string]any{
		sharingSeedGrant("g-pend-in01", "bob", "alice", "prod/a", "pending", nil),
		sharingSeedGrant("g-pend-ttl1", "bob", "alice", "prod/b", "pending", map[string]any{"secret_field": "password", "ttl": hour}),
		sharingSeedGrant("g-pend-self", "alice", "bob", "prod/self", "pending", nil),
		sharingSeedGrant("g-appr-out1", "alice", "bob", "prod/c", "approved", map[string]any{"approved_at": "2026-01-02T04:00:00Z", "approved_by": "alice", "expires_at": "2099-01-01T00:00:00Z"}),
		sharingSeedGrant("g-appr-in01", "bob", "alice", "prod/d", "approved", map[string]any{"approved_at": "2026-01-02T04:00:00Z", "approved_by": "alice"}),
		sharingSeedGrant("g-revk-out1", "alice", "bob", "prod/e", "revoked", map[string]any{"revoked_at": "2026-01-02T05:00:00Z"}),
		sharingSeedGrant("g-rejt-in01", "bob", "alice", "prod/f", "rejected", nil),
		sharingSeedGrant("g-expd-out1", "alice", "bob", "prod/g", "expired", map[string]any{"expires_at": "2020-01-01T00:00:00Z"}),
		sharingSeedGrant("g-pend-old1", "bob", "alice", "prod/h", "pending", map[string]any{"expires_at": "2020-01-01T00:00:00Z", "ttl": int64(60) * int64(time.Second)}),
		sharingSeedGrant("g-private-1", "mallory", "eve", "prod/x", "approved", map[string]any{"approved_at": "2026-01-02T04:00:00Z", "approved_by": "eve"}),
		sharingSeedGrant("0123456789abcdef0123456789abcdef", "bob", "alice", "prod/long", "pending", map[string]any{"secret_field": "api key", "ttl": int64(90061) * int64(time.Second), "nonce": "00ff"}),
		sharingSeedGrant("ünï-grant-1", "bób→üser", "alice", "prod/ünï/日本", "pending", nil),
		sharingSeedGrant("ééééé-xyz1", "bob", "alice", "prod/mid", "pending", nil),
		sharingSeedGrant("g-recipient1", "alice", "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp", "prod/recipient", "pending", nil),
	}
}

func sharingStepOf(tool string, kv ...any) sharingStep {
	args := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		args[kv[i].(string)] = kv[i+1]
	}
	return sharingStep{Tool: tool, Arguments: args}
}

func sharingCases() []sharingCase {
	yes := sharingApproval{TTY: true, Reply: "y"}
	handler := func(name string, steps ...sharingStep) sharingCase {
		return sharingCase{Name: name, Kind: "handler", Agent: "alice", AllowedPaths: []string{"prod"}, Seed: sharingSeedAll(), Approval: yes, Steps: steps}
	}
	empty := func(name string, steps ...sharingStep) sharingCase {
		c := handler(name, steps...)
		c.Seed = []map[string]any{}
		return c
	}
	ls := func(kv ...any) sharingStep { return sharingStepOf("list_shares", kv...) }
	ap := func(id any) sharingStep { return sharingStepOf("approve_share", "grant_id", id) }
	rv := func(id any) sharingStep { return sharingStepOf("revoke_share", "grant_id", id) }
	rq := func(kv ...any) sharingStep { return sharingStepOf("request_share", kv...) }
	with := func(c sharingCase, f func(*sharingCase)) sharingCase { f(&c); return c }

	var cases []sharingCase
	add := func(c ...sharingCase) { cases = append(cases, c...) }

	// ---- list_shares -----------------------------------------------------
	add(
		with(handler("list_no_store_file", ls()), func(c *sharingCase) { c.Seed = nil }),
		empty("list_empty_store", ls()),
		handler("list_scoped_to_caller_unfiltered", ls()),
		handler("list_filter_status_approved", ls("status", "approved")),
		handler("list_filter_status_pending", ls("status", "pending")),
		handler("list_filter_status_revoked_rejected_expired", ls("status", "revoked"), ls("status", "rejected"), ls("status", "expired")),
		handler("list_filter_status_unknown_is_empty", ls("status", "bogus"), ls("status", "APPROVED")),
		handler("list_filter_empty_strings_are_no_filter", ls("status", "", "from_agent", "", "to_agent", "", "secret_path", "")),
		handler("list_filter_from_agent", ls("from_agent", "bob"), ls("from_agent", "alice"), ls("from_agent", "nobody")),
		handler("list_filter_to_agent", ls("to_agent", "bob"), ls("to_agent", "alice")),
		handler("list_filter_secret_path", ls("secret_path", "prod/a"), ls("secret_path", "prod/A"), ls("secret_path", "prod/")),
		handler("list_filter_combined", ls("status", "pending", "from_agent", "bob", "to_agent", "alice", "secret_path", "prod/b"), ls("status", "pending", "from_agent", "alice", "to_agent", "alice")),
		handler("list_filter_cannot_reach_other_agents_grants", ls("from_agent", "mallory"), ls("to_agent", "eve"), ls("secret_path", "prod/x")),
		handler("list_non_string_filters_are_ignored", ls("status", 5, "from_agent", true, "to_agent", []any{"x"}, "secret_path", map[string]any{"a": 1})),
		handler("list_unknown_argument_is_ignored", ls("extra", "x", "status", "approved")),
		with(handler("list_as_recipient_only_agent", ls()), func(c *sharingCase) { c.Agent = "bob" }),
		with(handler("list_as_other_party_sees_only_own", ls()), func(c *sharingCase) { c.Agent = "eve" }),
		with(handler("list_as_unknown_agent_is_empty", ls()), func(c *sharingCase) { c.Agent = "zed" }),
		with(handler("list_unicode_agent_sees_unicode_grant", ls()), func(c *sharingCase) { c.Agent = "bób→üser" }),
		with(handler("list_recipient_key_format_agent", ls()), func(c *sharingCase) {
			c.Agent = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp"
		}),
	)

	// ---- request_share ---------------------------------------------------
	add(
		empty("request_basic_random_hex_id", rq("to_agent", "bob", "secret_path", "prod/new"), ls()),
		with(empty("request_basic_hmac_id", rq("to_agent", "bob", "secret_path", "prod/new"), ls()), func(c *sharingCase) { c.SigningKey = true }),
		empty("request_with_field_and_ttl", rq("to_agent", "bob", "secret_path", "prod/new", "secret_field", "password", "ttl", "1h"), ls("status", "pending")),
		empty("request_ttl_valid_forms",
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "30m"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1h30m"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "90s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1.5h"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "0"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "0s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "+5m"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1ns"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1500ms"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "2h45m30.5s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", ".5s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "-0s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1µs"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1us"),
			ls(),
		),
		empty("request_ttl_invalid_forms",
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "-1s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "abc"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1d"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1h 30m"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "5"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1e3s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "9999999h"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", " 1h"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "h"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1.s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "--1s"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "1H"),
			rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", "ünï"),
			ls(),
		),
		empty("request_ttl_non_string_is_ignored", rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", 3600), rq("to_agent", "b", "secret_path", "prod/ttl", "ttl", true), ls()),
		empty("request_invalid_arguments",
			rq("secret_path", "prod/x"),
			rq("to_agent", "bob"),
			rq(),
			rq("to_agent", 5, "secret_path", "prod/x"),
			rq("to_agent", "bob", "secret_path", 5),
			rq("to_agent", nil, "secret_path", "prod/x"),
			rq("to_agent", "bob", "secret_path", []any{"prod/x"}),
			ls(),
		),
		empty("request_empty_string_arguments_are_accepted", rq("to_agent", "", "secret_path", "prod/empty-agent"), rq("to_agent", "bob", "secret_path", ""), ls()),
		empty("request_scope_normalization",
			rq("to_agent", "bob", "secret_path", "prod"),
			rq("to_agent", "bob", "secret_path", "prod/"),
			rq("to_agent", "bob", "secret_path", "prod//a"),
			rq("to_agent", "bob", "secret_path", "/prod/a"),
			rq("to_agent", "bob", "secret_path", "prod/./a"),
			rq("to_agent", "bob", "secret_path", "prod/sub/../a"),
			rq("to_agent", "bob", "secret_path", "production"),
			rq("to_agent", "bob", "secret_path", "prod/../other"),
			rq("to_agent", "bob", "secret_path", "PROD/a"),
			rq("to_agent", "bob", "secret_path", "other/a"),
			rq("to_agent", "bob", "secret_path", "pro"),
			rq("to_agent", "bob", "secret_path", "prod\\a"),
			ls(),
		),
		with(empty("request_wildcard_scope", rq("to_agent", "bob", "secret_path", "anything/at/all"), rq("to_agent", "bob", "secret_path", ""), ls()), func(c *sharingCase) { c.AllowedPaths = []string{"*"} }),
		with(empty("request_no_allowed_paths_denies_everything", rq("to_agent", "bob", "secret_path", "prod/a"), ls()), func(c *sharingCase) { c.AllowedPaths = []string{} }),
		empty("request_recipient_formats",
			rq("to_agent", "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp", "secret_path", "prod/r1"),
			rq("to_agent", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ4n comment", "secret_path", "prod/r2"),
			rq("to_agent", "bob@example.com", "secret_path", "prod/r3"),
			rq("to_agent", "a/b/c", "secret_path", "prod/r4"),
			rq("to_agent", "  bob  ", "secret_path", "prod/r5"),
			rq("to_agent", "bob\nalice", "secret_path", "prod/r6"),
			rq("to_agent", "日本語エージェント", "secret_path", "prod/r7"),
			rq("to_agent", "<script>&\"quotes\"</script>", "secret_path", "prod/r8"),
			rq("to_agent", "alice", "secret_path", "prod/self-share"),
			rq("to_agent", strings.Repeat("x", 300), "secret_path", "prod/r9"),
			ls(),
		),
		empty("request_field_forms",
			rq("to_agent", "bob", "secret_path", "prod/f", "secret_field", ""),
			rq("to_agent", "bob", "secret_path", "prod/f", "secret_field", "password"),
			rq("to_agent", "bob", "secret_path", "prod/f", "secret_field", "api key"),
			rq("to_agent", "bob", "secret_path", "prod/f", "secret_field", "日本"),
			rq("to_agent", "bob", "secret_path", "prod/f", "secret_field", 5),
			ls(),
		),
		empty("request_duplicates_create_distinct_grants", rq("to_agent", "bob", "secret_path", "prod/dup"), rq("to_agent", "bob", "secret_path", "prod/dup"), ls("secret_path", "prod/dup")),
		with(empty("request_hmac_many_ids", rq("to_agent", "bob", "secret_path", "prod/h1"), rq("to_agent", "bob", "secret_path", "prod/h2", "secret_field", "f", "ttl", "10m"), ls()), func(c *sharingCase) { c.SigningKey = true }),
		handler("request_into_seeded_store_keeps_existing_grants", rq("to_agent", "bob", "secret_path", "prod/added", "ttl", "2h"), ls("status", "pending", "from_agent", "alice")),
		with(handler("request_then_list_as_target_after_switch_is_scoped", rq("to_agent", "zed", "secret_path", "prod/zz"), ls("to_agent", "zed")), func(c *sharingCase) { c.Agent = "bob" }),
	)

	// ---- approve_share ---------------------------------------------------
	add(
		handler("approve_pending_grant", ap("g-pend-in01"), ls("secret_path", "prod/a")),
		handler("approve_pending_with_field_and_ttl_sets_expiry_from_approval", ap("g-pend-ttl1"), ls("secret_path", "prod/b")),
		handler("approve_long_hex_id_field_and_day_ttl", ap("0123456789abcdef0123456789abcdef"), ls("secret_path", "prod/long")),
		handler("approve_unicode_grant_prompt_and_state", ap("ünï-grant-1"), ls("secret_path", "prod/ünï/日本")),
		handler("approve_recipient_key_format_grant", ap("g-recipient1")),
		with(handler("approve_declined_rejects_grant", ap("g-pend-in01"), ls("status", "rejected")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: true, Reply: "n"} }),
		with(handler("approve_reply_variants_yes", ap("g-pend-in01")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: true, Reply: "  YES  "} }),
		with(handler("approve_reply_remember_counts_as_approval", ap("g-pend-in01")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: true, Reply: "r"} }),
		with(handler("approve_reply_maybe_rejects", ap("g-pend-in01")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: true, Reply: "maybe"} }),
		with(handler("approve_reply_empty_rejects", ap("g-pend-in01")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: true, Reply: ""} }),
		with(handler("approve_without_tty_is_denied_and_grant_stays_pending", ap("g-pend-in01"), ls("secret_path", "prod/a")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: false} }),
		with(handler("approve_prompt_timeout", ap("g-pend-in01"), ls("secret_path", "prod/a")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: true, Error: "timeout"} }),
		with(handler("approve_prompt_read_error", ap("g-pend-in01")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: true, Error: "read:boom"} }),
		with(handler("approve_prompt_raw_mode_error", ap("g-pend-in01")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: true, Error: "raw:raw boom"} }),
		handler("approve_self_requested_grant_is_refused_before_prompt", ap("g-pend-self"), ls("secret_path", "prod/self")),
		handler("approve_unknown_and_empty_ids", ap("nope"), ap(""), ap("G-PEND-IN01"), ap(" g-pend-in01")),
		handler("approve_not_pending_statuses", ap("g-appr-in01"), ap("g-revk-out1"), ap("g-rejt-in01"), ap("g-expd-out1"), ap("g-private-1")),
		handler("approve_pending_grant_with_past_expiry_is_still_approved", ap("g-pend-old1"), ls("secret_path", "prod/h")),
		handler("approve_twice_second_is_not_pending", ap("g-pend-in01"), ap("g-pend-in01")),
		handler("approve_then_revoke_then_approve", ap("g-pend-in01"), rv("g-pend-in01"), ap("g-pend-in01")),
		handler("approve_invalid_arguments", sharingStepOf("approve_share"), ap(5), ap(nil), ap(true), ap([]any{"g-pend-in01"}), sharingStepOf("approve_share", "other", "x")),
		empty("approve_requested_grant_by_same_agent_is_refused", rq("to_agent", "bob", "secret_path", "prod/new"), ap("@GRANT_1@"), ls()),
		with(empty("approve_hmac_grant_by_same_agent_is_refused", rq("to_agent", "bob", "secret_path", "prod/new"), ap("@GRANT_1@")), func(c *sharingCase) { c.SigningKey = true }),
		with(handler("approve_other_agent_may_approve_third_party_grant", ap("g-pend-in01"), ap("g-pend-self"), ls("secret_path", "prod/self")), func(c *sharingCase) { c.Agent = "zed" }),
		with(handler("approve_by_requester_of_everything_is_refused", ap("g-pend-self")), func(c *sharingCase) { c.Agent = "alice" }),
		with(handler("approve_multibyte_id_prefix_is_cut_by_bytes", ap("ééééé-xyz1")), func(c *sharingCase) {}),
		handler("approve_state_after_all_outcomes", ap("g-pend-in01"), ap("g-pend-ttl1"), ap("g-pend-old1"), ls()),
	)

	// ---- revoke_share ----------------------------------------------------
	add(
		handler("revoke_approved_outgoing_grant", rv("g-appr-out1"), ls("status", "revoked")),
		handler("revoke_pending_outgoing_grant", rv("g-pend-self"), ls("secret_path", "prod/self")),
		handler("revoke_expired_status_grant_is_allowed", rv("g-expd-out1"), ls("secret_path", "prod/g")),
		handler("revoke_already_revoked", rv("g-revk-out1")),
		handler("revoke_twice", rv("g-appr-out1"), rv("g-appr-out1")),
		handler("revoke_non_source_agent_is_denied", rv("g-pend-in01"), rv("g-appr-in01"), ls("secret_path", "prod/a")),
		handler("revoke_cross_agent_grant_is_denied", rv("g-private-1")),
		handler("revoke_rejected_grant_by_source", rv("g-rejt-in01")),
		with(handler("revoke_rejected_grant_by_its_source_agent", rv("g-rejt-in01"), rv("g-pend-in01"), rv("g-appr-in01")), func(c *sharingCase) { c.Agent = "bob" }),
		handler("revoke_unknown_and_empty_ids", rv("missing"), rv(""), rv("G-APPR-OUT1")),
		handler("revoke_invalid_arguments", sharingStepOf("revoke_share"), rv(5), rv(nil), rv(false), rv(map[string]any{})),
		handler("revoke_unicode_id_by_non_source", rv("ünï-grant-1")),
		with(handler("revoke_unicode_id_by_source", rv("ünï-grant-1"), ls("secret_path", "prod/ünï/日本")), func(c *sharingCase) { c.Agent = "bób→üser" }),
		empty("revoke_requested_grant_roundtrip", rq("to_agent", "bob", "secret_path", "prod/new", "ttl", "1h"), rv("@GRANT_1@"), ls(), rv("@GRANT_1@")),
		with(empty("revoke_hmac_requested_grant_roundtrip", rq("to_agent", "bob", "secret_path", "prod/new"), rv("@GRANT_1@"), ls("status", "revoked")), func(c *sharingCase) { c.SigningKey = true }),
		with(handler("revoke_without_tty_does_not_need_a_terminal", rv("g-appr-out1")), func(c *sharingCase) { c.Approval = sharingApproval{TTY: false} }),
	)

	// ---- full lifecycle --------------------------------------------------
	add(
		with(empty("lifecycle_request_list_revoke_with_signing_key", rq("to_agent", "bob", "secret_path", "prod/life", "secret_field", "token", "ttl", "15m"), ls("status", "pending"), ls("from_agent", "alice"), rv("@GRANT_1@"), ls("status", "revoked"), ls("status", "pending")), func(c *sharingCase) { c.SigningKey = true }),
		empty("lifecycle_many_requests_then_filtered_lists",
			rq("to_agent", "bob", "secret_path", "prod/m1"),
			rq("to_agent", "carol", "secret_path", "prod/m2", "secret_field", "pw"),
			rq("to_agent", "bob", "secret_path", "prod/m3", "ttl", "5m"),
			rq("to_agent", "dave", "secret_path", "prod/m1"),
			ls(), ls("to_agent", "bob"), ls("secret_path", "prod/m1"), ls("to_agent", "bob", "secret_path", "prod/m3"), ls("status", "pending", "to_agent", "nobody"),
		),
	)

	// ---- defects of the Go oracle ---------------------------------------
	nilStore := func(name string, step sharingStep) sharingCase {
		c := handler(name, step)
		c.Kind = "go_defect"
		c.NoShareStore = true
		c.Seed = nil
		return c
	}
	add(
		nilStore("go_defect_production_new_leaves_share_store_nil_list_shares", ls()),
		nilStore("go_defect_production_new_leaves_share_store_nil_request_share", rq("to_agent", "bob", "secret_path", "prod/a")),
		nilStore("go_defect_production_new_leaves_share_store_nil_approve_share", ap("g-pend-in01")),
		nilStore("go_defect_production_new_leaves_share_store_nil_revoke_share", rv("g-pend-in01")),
		with(handler("go_defect_approve_short_grant_id_panics", ap("pending")), func(c *sharingCase) {
			c.Kind = "go_defect"
			c.Seed = []map[string]any{sharingSeedGrant("pending", "bob", "alice", "prod/a", "pending", nil)}
		}),
	)
	return cases
}

func sharingMaskStrings(v any, mask func(string) string) any {
	switch value := v.(type) {
	case string:
		return mask(value)
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = sharingMaskStrings(item, mask)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, item := range value {
			out[key] = sharingMaskStrings(item, mask)
		}
		return out
	default:
		return v
	}
}

type sharingRun struct {
	t        *testing.T
	ids      map[string]string // real id -> @GRANT_n@
	order    []string
	seedTime map[string]map[string]string
	start    time.Time
}

func (r *sharingRun) maskID(s string) string {
	for _, real := range r.order {
		s = strings.ReplaceAll(s, real, r.ids[real])
	}
	for _, real := range r.order {
		// HMAC ids are nonce:mac and the store keeps the nonce on the grant.
		if nonce, _, ok := strings.Cut(real, ":"); ok {
			s = strings.ReplaceAll(s, nonce, strings.TrimSuffix(r.ids[real], "@")+"_NONCE@")
		}
	}
	for _, real := range r.order {
		if len(real) >= 8 {
			s = strings.ReplaceAll(s, real[:8], strings.TrimSuffix(r.ids[real], "@")+"_ID8@")
		}
	}
	return s
}

func (r *sharingRun) unplace(args map[string]any) map[string]any {
	reverse := map[string]string{}
	for _, real := range r.order {
		reverse[r.ids[real]] = real
	}
	return sharingMaskStrings(args, func(s string) string {
		if real, ok := reverse[s]; ok {
			return real
		}
		return s
	}).(map[string]any)
}

// canonicalList sorts a list_shares array by masked id, keeps every element's
// exact Go bytes and replaces generated timestamps.
func (r *sharingRun) canonicalList(text string) string {
	var elems []json.RawMessage
	if err := json.Unmarshal([]byte(text), &elems); err != nil {
		return text
	}
	type item struct{ key, text string }
	items := make([]item, 0, len(elems))
	for _, raw := range elems {
		var grant map[string]any
		if err := json.Unmarshal(raw, &grant); err != nil {
			r.t.Fatalf("decode listed grant: %v", err)
		}
		id, _ := grant["id"].(string)
		element := string(raw)
		for _, key := range sharingTimeKeys {
			value, ok := grant[key].(string)
			if !ok || r.seedTime[id][key] == value {
				continue
			}
			element = strings.ReplaceAll(element, `"`+key+`":"`+value+`"`, `"`+key+`":"@TS@"`)
		}
		element = r.maskID(element)
		items = append(items, item{key: r.maskID(id), text: element})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].key < items[j].key })
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = it.text
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func sharingParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("parse timestamp %q: %v", value, err)
	}
	return parsed
}

func (r *sharingRun) canonicalStore(path string, end time.Time) []map[string]any {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}
		}
		r.t.Fatalf("read share store: %v", err)
	}
	var file struct {
		Version int              `json:"version"`
		Grants  []map[string]any `json:"grants"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		r.t.Fatalf("decode share store: %v", err)
	}
	if file.Version != 1 {
		r.t.Fatalf("share store version = %d", file.Version)
	}
	window := func(value time.Time) {
		if value.Before(r.start.Add(-time.Second)) || value.After(end.Add(time.Second)) {
			r.t.Fatalf("generated timestamp %s is outside the run window", value)
		}
	}
	out := make([]map[string]any, 0, len(file.Grants))
	for _, grant := range file.Grants {
		id, _ := grant["id"].(string)
		masked := map[string]any{}
		for key, value := range grant {
			masked[key] = value
		}
		for _, key := range sharingTimeKeys {
			value, ok := grant[key].(string)
			if !ok || r.seedTime[id][key] == value {
				continue
			}
			when := sharingParseTime(r.t, value)
			if key != "expires_at" {
				window(when)
				masked[key] = "@NOW@"
				continue
			}
			ttl := time.Duration(0)
			if raw, ok := grant["ttl"].(float64); ok {
				ttl = time.Duration(int64(raw))
			}
			switch {
			case ttl > 0 && grant["approved_at"] != nil && sharingParseTime(r.t, grant["approved_at"].(string)).Add(ttl).Equal(when):
				masked[key] = "@APPROVED_AT+TTL@"
			case ttl > 0 && sharingParseTime(r.t, grant["created_at"].(string)).Add(ttl).Equal(when):
				masked[key] = "@CREATED_AT+TTL@"
			default:
				r.t.Fatalf("unexplained generated expires_at %s for %s (ttl %s)", value, id, ttl)
			}
		}
		out = append(out, sharingMaskStrings(masked, r.maskID).(map[string]any))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	return out
}

func sharingCall(t *testing.T, handler *ProtocolHandler, line string) (response any, panicText string) {
	t.Helper()
	var msg transport.Message
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		t.Fatalf("decode request %s: %v", line, err)
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			panicText = fmt.Sprint(recovered)
			response = nil
		}
	}()
	out, err := handler.HandleMessage(context.Background(), &msg)
	if err != nil {
		t.Fatalf("handle %s: %v", line, err)
	}
	return out, ""
}

func runSharingCase(t *testing.T, spec sharingCase, serverName, serverVersion string) sharingCase {
	t.Helper()
	vaultDir, identity := mcpDeleteEntryFixtureVault(t)
	profile := config.AgentProfile{
		Name: spec.Agent, Tier: config.StrPtr("admin"), AllowedPaths: spec.AllowedPaths,
		CanWrite: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
	}
	srv := newTestServerWithVault(t, profile, "stdio", vaultDir)
	srv.vault.Identity = identity
	auditDir := t.TempDir()
	auditLog, err := audit.New(spec.Agent, auditDir, nil)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	srv.auditLog = auditLog

	storePath := filepath.Join(vaultDir, "mcp-shares.json")
	seedTime := map[string]map[string]string{}
	if spec.Seed != nil {
		data, err := json.Marshal(map[string]any{"version": 1, "grants": spec.Seed})
		if err != nil {
			t.Fatalf("encode seed: %v", err)
		}
		if err := os.WriteFile(storePath, data, 0o600); err != nil {
			t.Fatalf("write seed: %v", err)
		}
		for _, grant := range spec.Seed {
			id := grant["id"].(string)
			seedTime[id] = map[string]string{}
			for _, key := range sharingTimeKeys {
				if value, ok := grant[key].(string); ok {
					seedTime[id][key] = value
				}
			}
		}
	}
	if !spec.NoShareStore {
		store := NewShareStore(storePath)
		if err := store.Load(); err != nil {
			t.Fatalf("load seeded share store: %v", err)
		}
		if spec.SigningKey {
			store.SetSigningKey(bytes.Repeat([]byte{42}, 32))
		}
		srv.shareStore = store
	}

	promptFile, err := os.CreateTemp(t.TempDir(), "sharing-approval-*")
	if err != nil {
		t.Fatalf("create approval output: %v", err)
	}
	originalTTY := openTTYDevice
	openTTYDevice = func() (ttyDevice, error) {
		if !spec.Approval.TTY {
			return nil, fmt.Errorf("no tty")
		}
		device := &mockTTYDevice{
			output: promptFile,
			raw:    func() (func(), error) { return func() {}, nil },
			readString: func() (string, error) {
				switch {
				case spec.Approval.Error == "timeout":
					return "", os.ErrDeadlineExceeded
				case strings.HasPrefix(spec.Approval.Error, "read:"):
					return "", fmt.Errorf("%s", strings.TrimPrefix(spec.Approval.Error, "read:"))
				}
				return spec.Approval.Reply, nil
			},
		}
		if strings.HasPrefix(spec.Approval.Error, "raw:") {
			text := strings.TrimPrefix(spec.Approval.Error, "raw:")
			device.raw = func() (func(), error) { return nil, fmt.Errorf("%s", text) }
		}
		return device, nil
	}
	t.Cleanup(func() { openTTYDevice = originalTTY; _ = promptFile.Close() })

	run := &sharingRun{t: t, ids: map[string]string{}, seedTime: seedTime, start: time.Now().UTC()}
	handler := NewProtocolHandler(serverName, serverVersion, srv)
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	} {
		sharingCall(t, handler, line)
	}

	observed := spec
	observed.Steps = make([]sharingStep, 0, len(spec.Steps))
	for index, step := range spec.Steps {
		real := run.unplace(step.Arguments)
		request, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": index + 2, "method": "tools/call",
			"params": map[string]any{"name": step.Tool, "arguments": real},
		})
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		if err := promptFile.Truncate(0); err != nil {
			t.Fatalf("reset prompt capture: %v", err)
		}
		if _, err := promptFile.Seek(0, 0); err != nil {
			t.Fatalf("rewind prompt capture: %v", err)
		}
		response, panicText := sharingCall(t, handler, string(request))
		recorded := sharingStep{Tool: step.Tool, Arguments: step.Arguments}
		if panicText != "" {
			recorded.GoPanic = panicText
			observed.Steps = append(observed.Steps, recorded)
			continue
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(encoded, &parsed); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		// Register a freshly issued id before any masking.
		if text := sharingResultText(parsed); step.Tool == "request_share" && text != "" && !sharingIsError(parsed) {
			var issued struct {
				GrantID string `json:"grant_id"`
			}
			if err := json.Unmarshal([]byte(text), &issued); err != nil || issued.GrantID == "" {
				t.Fatalf("request_share result %q has no grant_id", text)
			}
			switch {
			case sharingHexID.MatchString(issued.GrantID):
				observed.IDShapes = append(observed.IDShapes, "hex32")
			case sharingHMACID.MatchString(issued.GrantID):
				observed.IDShapes = append(observed.IDShapes, "hmac")
			default:
				t.Fatalf("unexpected grant id shape %q", issued.GrantID)
			}
			run.order = append(run.order, issued.GrantID)
			run.ids[issued.GrantID] = fmt.Sprintf("@GRANT_%d@", len(run.order))
		}
		if step.Tool == "list_shares" && !sharingIsError(parsed) {
			sharingSetResultText(parsed, run.canonicalList(sharingResultText(parsed)))
		}
		recorded.Response = sharingMaskStrings(parsed, run.maskID).(map[string]any)
		prompt, err := os.ReadFile(promptFile.Name())
		if err != nil {
			t.Fatalf("read prompt capture: %v", err)
		}
		recorded.Prompt = run.maskID(strings.ToValidUTF8(string(prompt), "\uFFFD"))
		observed.Steps = append(observed.Steps, recorded)
	}
	end := time.Now().UTC()
	observed.Store = run.canonicalStore(storePath, end)

	auditLog.Flush()
	observed.Audit = []sharingAuditRow{}
	files, err := filepath.Glob(filepath.Join(auditDir, "audit-*.log"))
	if err != nil || len(files) != 1 {
		t.Fatalf("locate audit log: %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry audit.LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode audit row %q: %v", line, err)
		}
		observed.Audit = append(observed.Audit, sharingAuditRow{Action: entry.Action, Path: run.maskID(entry.Path), OK: entry.OK})
	}
	return observed
}

func sharingResultText(response map[string]any) string {
	result, _ := response["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		return ""
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text
}

func sharingSetResultText(response map[string]any, text string) {
	first := response["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	first["text"] = text
}

func sharingIsError(response map[string]any) bool {
	result, _ := response["result"].(map[string]any)
	flag, _ := result["isError"].(bool)
	return flag || response["error"] != nil
}

var sharingGeneratorFiles = []string{"internal/mcp/server/mcp_sharing_fixture_generator_test.go"}

func TestGenerateMCPSharingFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_SHARING_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_SHARING_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_SHARING_FIXTURE=1 or SYMAIRA_CHECK_MCP_SHARING_FIXTURE=1")
	}
	// The audit HMAC key and grant signing key must never reach the real OS
	// keyring from a fixture run.
	t.Setenv("SYMVAULT_TEST_KEYRING", "memory")
	root := executeAPIRequestRepoRoot(t)
	sourceFiles := slices.Clone(mcpDeleteEntrySourceFiles)
	sourcePin := localMCPOracleSourcePin(t, root, sharingOracleCommit, sourceFiles)
	sourceHash := executeAPIRequestWorkingDigest(t, root, sourceFiles)

	const serverName, serverVersion = "symvault", "0.0.0-sharing-fixture"
	specs := sharingCases()
	cases := make([]sharingCase, 0, len(specs))
	seen := map[string]bool{}
	for _, spec := range specs {
		if seen[spec.Name] {
			t.Fatalf("duplicate case %s", spec.Name)
		}
		seen[spec.Name] = true
		cases = append(cases, runSharingCase(t, spec, serverName, serverVersion))
	}

	fixture := sharingFixture{
		SchemaVersion: 1,
		Oracle: sharingOracle{
			Commit: sharingOracleCommit[:8], CommitSHA: sharingOracleCommit,
			SourceFiles: sourceFiles, SourceHash: sourceHash, SourcePinDigest: sourcePin,
			GoVersion: runtime.Version(), CorekitVersion: localMCPOracleCorekitVersion,
			GeneratorFiles: sharingGeneratorFiles,
			GeneratorHash:  executeAPIRequestWorkingDigest(t, root, sharingGeneratorFiles),
		},
		ServerName: serverName, ServerVersion: serverVersion,
		Normalizations: []string{
			"Grant ids issued by request_share are random (hex32) or HMAC (nonce:mac) and appear as @GRANT_n@ in creation order; their first eight bytes appear as @GRANT_n_ID8@. The recorded id shape is asserted separately.",
			"list_shares result text keeps each element's exact Go bytes but is sorted by id: Go ranges a map, so its order is unspecified (upstream-go-bugs.md).",
			"Timestamps produced by the running clock are @TS@ inside list_shares text and @NOW@, @CREATED_AT+TTL@ or @APPROVED_AT+TTL@ in the store snapshot, which is sorted by id; seeded timestamps stay literal.",
			"The approval prompt is the exact bytes Go wrote to the controlling terminal (box, rows, echo); the Rust replay renders the same box from the request it receives.",
			"Steps with go_panic recorded a Go runtime panic escaping the dispatcher; the Rust replay asserts the documented difference instead of equality.",
			"The audit rows are (action, path, ok) as written to the Go audit log, in order.",
		},
		Cases: cases,
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata", "port", "mcp", "tools-sharing.json")
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("MCP sharing fixture is stale; run with SYMAIRA_GENERATE_MCP_SHARING_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
