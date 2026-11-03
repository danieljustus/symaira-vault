// Command deviceenrollgen freezes the PAIRING-001 / APPROVAL-001 server-side
// device enrollment routes (/api/v1/devices/enroll-code and
// /api/v1/devices/enroll) from the production Go implementation.
//
// It builds the exact handlers the Go server mounts (cmd/mcp/serve_deps.go:
// approval.NewEnrollCodeHTTPHandler / NewEnrollHTTPHandler over one shared
// pairing.TokenStore and the real pairing.DeviceSessionStore;
// internal/mcp/serverbootstrap/http.go: the registrations in an http.ServeMux),
// serves them on a real loopback listener and drives them with raw HTTP/1.1
// requests, recording every status, contract header and body byte.
//
// Values Go randomises (pairing codes, bearer tokens, device ids, queue ids)
// and wall-clock values (expiry instants) are replaced by fixed canonical
// values after their shape and distance from "now" have been asserted;
// everything else (field order, error texts, status codes) is the recorded Go
// bytes. Request timestamps and proofs are generated per request from
// placeholders so the proof window is exercised against the live clock. The
// Rust replay (crates/symvault-mcp/tests/device_enroll_replay.rs) rebuilds
// the same scenarios against the Rust MCP HTTP server with no Go.
//
// Modes:
//
//	deviceenrollgen            regenerate testdata/port/approval/device-enroll.json
//	deviceenrollgen --check    regenerate in memory and require byte equality
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	mcputil "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/pairing"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

// oracleCommit is the last commit that touched any pinned source; every file
// in oracleSources must be byte-identical to its blob there.
const oracleCommit = "bfa4e2440bd8338f177bb739f469794948efa519"

var oracleSources = []string{
	"cmd/mcp/serve_deps.go",
	"internal/approval/enroll.go",
	"internal/approval/http.go",
	"internal/approval/queue.go",
	"internal/mcp/auth/token.go",
	"internal/mcp/serverbootstrap/http.go",
	"internal/mcp/util.go",
	"internal/pairing/devicesession.go",
	"internal/pairing/token.go",
}

const generatorFile = "scripts/rust-port/cmd/deviceenrollgen/main.go"

// mountEvidence are the source lines the generator's mux replicates. They are
// checked against the working tree (which provenance pins to oracleCommit) so a
// changed mounting cannot go unnoticed.
var mountEvidence = []struct{ file, line string }{
	{"cmd/mcp/serve_deps.go", "approvalHandler := approval.NewHTTPHandler(ApprovalQueue, sessionStore)"},
	{"cmd/mcp/serve_deps.go", "enrollCodeHandler := approval.NewEnrollCodeHTTPHandler(EnrollCodes, fingerprint, mcputil.IsLoopbackHost, enrollSecret)"},
	{"cmd/mcp/serve_deps.go", "enrollHandler := approval.NewEnrollHTTPHandler(EnrollCodes, sessionStore)"},
	{"cmd/mcp/serve_deps.go", "serverbootstrap.WithDeviceEnrollAPI(enrollHandler)"},
	{"cmd/mcp/serve_deps.go", "serverbootstrap.WithDeviceEnrollCodeAPI(enrollCodeHandler)"},
	{"internal/mcp/serverbootstrap/http.go", "mux.Handle(approval.PathApprovals, approvalChain)"},
	{"internal/mcp/serverbootstrap/http.go", "mux.Handle(approval.PathApprovalAction, approvalChain)"},
	{"internal/mcp/serverbootstrap/http.go", "mux.Handle(approval.PathDeviceEnroll, enrollChain)"},
	{"internal/mcp/serverbootstrap/http.go", "mux.Handle(approval.PathDeviceEnrollCode, enrollCodeChain)"},
}

const (
	fixtureRel = "testdata/port/approval/device-enroll.json"

	// fixtureSecret is the vault enroll secret every handler is built with.
	fixtureSecret = "device-enroll-fixture-secret-0001"
	// fixtureFingerprint stands in for the SHA-256 of the server certificate.
	fixtureFingerprint = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63206cbd67d3b8a0e"

	canonicalExpires = "2026-01-02T03:09:05.123456789Z"
	canonicalCreated = "2026-01-02T03:04:05.123456789Z"
	canonicalDecided = "2026-01-02T03:04:07.25Z"
	zeroTime         = "0001-01-01T00:00:00Z"

	pathCode   = "/api/v1/devices/enroll-code"
	pathEnroll = "/api/v1/devices/enroll"
)

// ---------------------------------------------------------------- fixture

type oracleMeta struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type constants struct {
	Secret                string `json:"secret"`
	Fingerprint           string `json:"fingerprint"`
	CodeTTLSeconds        int    `json:"code_ttl_seconds"`
	SessionTTLSeconds     int    `json:"session_ttl_seconds"`
	ProofWindowSeconds    int    `json:"proof_window_seconds"`
	MaxFailedAttempts     int    `json:"max_failed_attempts"`
	FailedCooldownSeconds int    `json:"failed_cooldown_seconds"`
}

type queueSpec struct {
	Key    string `json:"key"`
	Agent  string `json:"agent_name"`
	Path   string `json:"path"`
	Write  bool   `json:"write"`
	Reason string `json:"reason"`
}

type requestRecord struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Header map[string]string `json:"headers,omitempty"`
	// ExtraHeaderLines are written verbatim after Headers, to record repeated
	// headers (Go's Header.Get reads the first value).
	ExtraHeaderLines []string `json:"extra_header_lines,omitempty"`
	Body             string   `json:"body,omitempty"`
}

type responseRecord struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type step struct {
	// Action is "request", "sleep" or "revoke_external" (a second store
	// instance revokes Device, as `symvault device approval-revoke` does).
	Action   string          `json:"action"`
	SleepMS  int             `json:"sleep_ms,omitempty"`
	Device   string          `json:"device,omitempty"`
	Request  *requestRecord  `json:"request,omitempty"`
	Response *responseRecord `json:"response,omitempty"`
}

type storedSession struct {
	DeviceID  string `json:"device_id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Revoked   bool   `json:"revoked"`
}

type caseRecord struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	// NonLoopbackPeer builds the mint handler with a loopback predicate that
	// refuses every peer. A non-loopback TCP peer cannot be produced portably;
	// the replay answers these cases through the handler function directly.
	NonLoopbackPeer bool `json:"non_loopback_peer,omitempty"`
	// NoFingerprint builds the mint handler without a certificate
	// fingerprint (TLS unavailable).
	NoFingerprint bool `json:"no_fingerprint,omitempty"`
	// CodeTTLMS overrides pairing.TokenTTL for the case.
	CodeTTLMS  int             `json:"code_ttl_ms,omitempty"`
	Queue      []queueSpec     `json:"queue,omitempty"`
	Steps      []step          `json:"steps"`
	StoreAfter []storedSession `json:"store_after"`
}

type fixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        oracleMeta        `json:"oracle"`
	Mounting      []string          `json:"mounting"`
	Constants     constants         `json:"constants"`
	Canonical     map[string]string `json:"canonical"`
	Scope         map[string]string `json:"scope"`
	Counts        map[string]int    `json:"counts"`
	Cases         []caseRecord      `json:"cases"`
}

// ---------------------------------------------------------------- cases

func rq(method, path string, headers map[string]string, body string) step {
	return step{Action: "request", Request: &requestRecord{Method: method, Path: path, Header: headers, Body: body}}
}

func sleepStep(ms int) step { return step{Action: "sleep", SleepMS: ms} }

// proofHeaders are the vault-ownership headers for a timestamp written in the
// given form, n seconds from now, with a proof over that instant.
func proofHeaders(form string, n int) map[string]string {
	return map[string]string{
		"X-Enroll-Timestamp": fmt.Sprintf("{ts:%s:%d}", form, n),
		"X-Enroll-Proof":     fmt.Sprintf("{proof:%d}", n),
	}
}

func mint() step { return rq("POST", pathCode, proofHeaders("utc", 0), "") }

func mintWith(h map[string]string) step { return rq("POST", pathCode, h, "") }

func redeemBody(body string) step { return rq("POST", pathEnroll, nil, body) }

func redeemCode(k int, name string) step {
	return redeemBody(fmt.Sprintf(`{"code":"{code:%d}","device_name":%q}`, k, name))
}

func redeemBad() step { return redeemBody(`{"code":"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"}`) }

func bearer(k int) map[string]string {
	return map[string]string{"Authorization": fmt.Sprintf("Bearer {token:%d}", k)}
}

func repeat(n int, s step) []step {
	out := make([]step, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func join(parts ...[]step) []step {
	var out []step
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func one(s step) []step { return []step{s} }

func mints(n int) []step { return repeat(n, mint()) }

func cases() []caseRecord {
	var out []caseRecord
	add := func(c caseRecord) { out = append(out, c) }

	// ---- enroll-code ----
	add(caseRecord{ID: "mint_ok", Description: "a proven loopback POST mints a fresh code; the body carries code, expires_at and the certificate fingerprint in key order",
		Steps: join(mints(3), one(rq("POST", pathCode, proofHeaders("utc", 0), `{"ignored":true}`)))})
	add(caseRecord{ID: "mint_wrong_method_is_mux_404_before_everything", Description: "any method but POST is the handler's NotFound, before the loopback and proof checks",
		Steps: []step{
			rq("GET", pathCode, proofHeaders("utc", 0), ""),
			rq("PUT", pathCode, proofHeaders("utc", 0), ""),
			rq("DELETE", pathCode, proofHeaders("utc", 0), ""),
			rq("PATCH", pathCode, proofHeaders("utc", 0), ""),
			rq("GET", pathCode, nil, ""),
			rq("OPTIONS", pathCode, nil, ""),
		}})
	add(caseRecord{ID: "mint_non_loopback_peer_forbidden", Description: "a peer the loopback predicate refuses is 403 before the proof is looked at; wrong methods are still 404",
		NonLoopbackPeer: true,
		Steps: []step{
			rq("POST", pathCode, proofHeaders("utc", 0), ""),
			rq("POST", pathCode, nil, ""),
			rq("POST", pathCode, map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{badproof:0}"}, ""),
			rq("GET", pathCode, proofHeaders("utc", 0), ""),
		}})
	add(caseRecord{ID: "mint_proof_required", Description: "401 for every missing, empty or wrong proof; header names are case-insensitive; the first of repeated headers is used",
		Steps: []step{
			rq("POST", pathCode, nil, ""),
			rq("POST", pathCode, map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}"}, ""),
			rq("POST", pathCode, map[string]string{"X-Enroll-Proof": "{proof:0}"}, ""),
			rq("POST", pathCode, map[string]string{"X-Enroll-Timestamp": "", "X-Enroll-Proof": "{proof:0}"}, ""),
			rq("POST", pathCode, map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": ""}, ""),
			rq("POST", pathCode, map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{badproof:0}"}, ""),
			rq("POST", pathCode, map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{proof:-5}"}, ""),
			rq("POST", pathCode, map[string]string{"x-enroll-timestamp": "{ts:utc:0}", "x-enroll-proof": "{proof:0}"}, ""),
			{Action: "request", Request: &requestRecord{Method: "POST", Path: pathCode, Header: proofHeaders("utc", 0), ExtraHeaderLines: []string{"X-Enroll-Proof: " + strings.Repeat("0", 64)}}},
			{Action: "request", Request: &requestRecord{Method: "POST", Path: pathCode, Header: map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": strings.Repeat("0", 64)}, ExtraHeaderLines: []string{"X-Enroll-Proof: {proof:0}"}}},
			{Action: "request", Request: &requestRecord{Method: "POST", Path: pathCode, Header: map[string]string{"X-Enroll-Proof": "{proof:0}"}, ExtraHeaderLines: []string{"X-Enroll-Timestamp: {ts:utc:0}", "X-Enroll-Timestamp: not-a-time"}}},
		}})
	add(caseRecord{ID: "mint_proof_window", Description: "the proof is accepted within thirty seconds either side of the server clock and refused beyond",
		Steps: []step{
			mintWith(proofHeaders("utc", -20)),
			mintWith(proofHeaders("utc", 20)),
			mintWith(proofHeaders("utc", -35)),
			mintWith(proofHeaders("utc", 35)),
			mintWith(proofHeaders("utc", -3600)),
			mintWith(proofHeaders("utc", 86400)),
			mintWith(proofHeaders("epoch", 0)),
			mintWith(proofHeaders("far", 0)),
		}})
	var forms []step
	for _, f := range []string{"utc", "plus2", "minus0530", "plus00", "frac", "frac9", "comma", "lower_t", "lower_z", "space_sep", "no_colon", "lead_space", "trail_space", "frac12", "frac_dot", "no_zone", "feb30", "hour24", "leap60", "plus2400", "minus2400", "plus2500", "plus0060", "plus0061", "plus0160", "single_digit", "hour1"} {
		forms = append(forms, mintWith(proofHeaders(f, 0)))
	}
	add(caseRecord{ID: "mint_timestamp_forms", Description: "which spellings of the timestamp header Go's time.Parse(RFC3339) accepts; the proof is always over the UTC second",
		Steps: forms})
	add(caseRecord{ID: "mint_proof_hex_forms", Description: "the proof is compared as lower-case hex text",
		Steps: []step{
			mintWith(map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{proof:0:upper}"}),
			mintWith(map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{proof:0:short}"}),
			mintWith(map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{proof:0:long}"}),
			mintWith(map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{proof:0:nonhex}"}),
			mintWith(map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{proof:0:padded}"}),
			mintWith(proofHeaders("utc", 0)),
		}})
	add(caseRecord{ID: "mint_tls_unavailable", Description: "without a certificate fingerprint a proven request is 503; the proof is checked first",
		NoFingerprint: true,
		Steps: []step{
			mint(),
			rq("POST", pathCode, nil, ""),
			rq("POST", pathCode, map[string]string{"X-Enroll-Timestamp": "{ts:utc:0}", "X-Enroll-Proof": "{badproof:0}"}, ""),
			rq("GET", pathCode, proofHeaders("utc", 0), ""),
		}})
	add(caseRecord{ID: "mint_ignores_body_query_and_content_type", Description: "the request body, query string and content type play no part",
		Steps: []step{
			rq("POST", pathCode+"?x=1&y=2", proofHeaders("utc", 0), ""),
			rq("POST", pathCode, proofHeaders("utc", 0), "{not json"),
			rq("POST", pathCode, mergeHeaders(proofHeaders("utc", 0), map[string]string{"Content-Type": "text/plain"}), "plain body"),
			rq("POST", pathCode, mergeHeaders(proofHeaders("utc", 0), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}), "a=b"),
		}})
	add(caseRecord{ID: "mint_route_matching", Description: "the mux matches the exact path only; unclean paths are redirected, escaped hyphens decode",
		Steps: []step{
			rq("POST", pathCode+"/", proofHeaders("utc", 0), ""),
			rq("POST", pathCode+"2", proofHeaders("utc", 0), ""),
			rq("POST", "/API/V1/DEVICES/ENROLL-CODE", proofHeaders("utc", 0), ""),
			rq("POST", "/api/v1/devices/enroll%2Dcode", proofHeaders("utc", 0), ""),
			rq("POST", "//api/v1/devices/enroll-code", proofHeaders("utc", 0), ""),
			rq("POST", "/api/v1/devices/./enroll-code", proofHeaders("utc", 0), ""),
			rq("POST", "/api/v1/devices/enroll-code/..", proofHeaders("utc", 0), ""),
			rq("POST", "/api/v1/devices", proofHeaders("utc", 0), ""),
		}})

	// ---- enroll ----
	add(caseRecord{ID: "redeem_ok", Description: "a minted code is exchanged for a device id and a bearer token the approval API accepts; the session is persisted by hash",
		Steps: []step{
			mint(),
			redeemCode(1, "Alice's <phone> & co"),
			rq("GET", "/api/v1/approvals", bearer(1), ""),
		}})
	add(caseRecord{ID: "redeem_single_use", Description: "a code redeems once; a second code is independent",
		Steps: []step{
			mint(), mint(),
			redeemCode(1, "first"),
			redeemCode(1, "again"),
			redeemCode(2, "second"),
			redeemCode(2, "second again"),
		}})
	add(caseRecord{ID: "redeem_unknown_codes", Description: "401 for a code that was never minted, or is not exactly a minted code",
		Steps: join(mints(2), []step{
			redeemBad(),
			redeemBody(`{"code":"{code:1:lower}"}`),
			redeemBody(`{"code":"{code:1:cut}"}`),
			redeemBody(`{"code":"{code:1:plus}"}`),
			redeemCode(1, "survivor"),
			redeemBody(`{"code":"{code:2:dashed}"}`),
			redeemBody(`{"code":"{code:2}\u0000"}`),
			redeemCode(2, "second survivor"),
		})})
	var trimmed []step
	trimmed = append(trimmed, mints(7)...)
	for i, ws := range []string{`  `, `\t\n`, `\u00a0`, `\u3000`, `\u0085`, `\u2028`, `\u200b`} {
		trimmed = append(trimmed, redeemBody(fmt.Sprintf(`{"code":"%s{code:%d}%s"}`, ws, i+1, ws)))
	}
	add(caseRecord{ID: "redeem_code_whitespace_trimmed", Description: "strings.TrimSpace on the code: ASCII and Unicode spaces are trimmed, a zero-width space is not",
		Steps: trimmed})
	add(caseRecord{ID: "redeem_missing_code_is_400", Description: "an absent, empty, blank or null code is 400 and consumes nothing",
		Steps: join(one(mint()), []step{
			redeemBody(`{}`),
			redeemBody(`{"code":""}`),
			redeemBody(`{"code":"   "}`),
			redeemBody(`{"code":"\t\n "}`),
			redeemBody(`{"code":null}`),
			redeemBody(`{"device_name":"x"}`),
			redeemBody(`null`),
			redeemBody("  null \n"),
			redeemCode(1, "after the 400s"),
		})})
	add(caseRecord{ID: "redeem_malformed_bodies", Description: "400 malformed request body for anything the JSON decoder rejects, including a wrongly typed field, which consumes nothing",
		Steps: join(one(mint()), []step{
			redeemBody(``),
			redeemBody(`{`),
			redeemBody(`{"code":`),
			redeemBody(`not json`),
			redeemBody(`[]`),
			redeemBody(`"str"`),
			redeemBody(`5`),
			redeemBody(`true`),
			redeemBody(`[{"code":"x"}]`),
			redeemBody(`{"code":5}`),
			redeemBody(`{"code":["a"]}`),
			redeemBody(`{"code":true}`),
			redeemBody(`{"code":{"a":1}}`),
			redeemBody(`{"code":"{code:1}","device_name":5}`),
			redeemBody(`{"code":"{code:1}","device_name":{"a":1}}`),
			redeemBody(`{"code":"{code:1}","device_name":["x"]}`),
			redeemBody(`{"code":"x",}`),
			redeemBody(`{'code':'x'}`),
			redeemBody("\xef\xbb\xbf" + `{"code":"{code:1}"}`),
			redeemBody("   \n\t "),
			redeemBody(`{"code":"{code:1}"`),
			redeemBody(`{"code":"bad\q"}`),
			redeemCode(1, "after the 400s"),
		})})
	add(caseRecord{ID: "redeem_json_leniency", Description: "encoding/json semantics: unknown keys ignored, keys match case-insensitively, the last duplicate wins, only the first value is read, null leaves a field alone",
		Steps: join(mints(10), []step{
			redeemBody(`{"code":"{code:1}","device_name":"a","extra":{"deep":[1,2,{"x":null}]},"other":1e999}`),
			redeemBody(`{"CODE":"{code:2}","Device_Name":"b"}`),
			redeemBody(`{"Code":"{code:3}","DEVICE_NAME":"c"}`),
			redeemBody(`{"code":"bad","code":"{code:4}"}`),
			redeemBody(`{"code":"{code:5}","code":"bad"}`),
			redeemBody(`{"code":"{code:5}"} trailing garbage`),
			redeemBody(`{"code":"{code:6}","device_name":"d"}{"code":"{code:7}"}`),
			redeemBody(`{"\u0063ode":"{code:7}","device_name":"e"}`),
			redeemBody(`{"code":"{code:8}","device_name":null}`),
			redeemBody(`{"code":"bad","code":null,"CODE":"{code:9}"}`),
			redeemBody("\n\t {\n \"code\" : \"{code:10}\" ,\n \"device_name\" : \"f\"\n}\n"),
		})})
	add(caseRecord{ID: "redeem_device_names", Description: "the device name is stored verbatim (empty names omitted from the file); public_key stays empty",
		Steps: join(mints(8), []step{
			redeemBody(`{"code":"{code:1}"}`),
			redeemCode(2, ""),
			redeemCode(3, "Phone \u00e9\u4e16\u754c \U0001F4F1"),
			redeemCode(4, "<script>alert(1)</script> & \"quotes\" \\ back"),
			redeemBody(`{"code":"{code:5}","device_name":"nul\u0000char\u0007bell\ttab\nnewline"}`),
			redeemBody(`{"code":"{code:6}","device_name":"line\u2028sep\u2029para"}`),
			redeemBody(`{"code":"{code:7}","device_name":"{pad:4096}"}`),
			redeemBody(`{"code":"{code:8}","device_name":"{pad:900000}"}`),
		})})
	add(caseRecord{ID: "redeem_wrong_method_is_404", Description: "any method but POST is the handler's NotFound and consumes nothing",
		Steps: join(one(mint()), []step{
			rq("GET", pathEnroll, nil, ""),
			rq("PUT", pathEnroll, nil, `{"code":"{code:1}"}`),
			rq("DELETE", pathEnroll, nil, `{"code":"{code:1}"}`),
			rq("PATCH", pathEnroll, nil, `{"code":"{code:1}"}`),
			rq("GET", pathEnroll, nil, `{"code":"{code:1}"}`),
			redeemCode(1, "post works"),
		})})
	add(caseRecord{ID: "redeem_route_matching", Description: "the mux matches the exact path only; the query string is ignored",
		Steps: join(one(mint()), []step{
			rq("POST", pathEnroll+"/", nil, `{"code":"{code:1}"}`),
			rq("POST", "/api/v1/devices/enrol", nil, `{"code":"{code:1}"}`),
			rq("POST", pathEnroll+"x", nil, `{"code":"{code:1}"}`),
			rq("POST", "/API/V1/DEVICES/ENROLL", nil, `{"code":"{code:1}"}`),
			rq("POST", "//api/v1/devices/enroll", nil, `{"code":"{code:1}"}`),
			rq("POST", "/api/v1/devices/%65nroll", nil, `{"code":"{code:1}"}`),
			mint(),
			rq("POST", pathEnroll+"?x=1", nil, `{"code":"{code:2}","device_name":"query"}`),
		})})
	add(caseRecord{ID: "redeem_expired_code", Description: "a code past its lifetime is refused (and removed); a fresh code still works", CodeTTLMS: 300,
		Steps: []step{
			mint(),
			sleepStep(700),
			redeemCode(1, "late"),
			mint(),
			redeemCode(2, "in time"),
		}})
	add(caseRecord{ID: "redeem_failed_attempts_trigger_cooldown", Description: "five failures in a row put the store into a global cooldown in which even a valid code is refused (and kept); minting stays possible",
		Steps: join(one(mint()), repeat(4, redeemBad()), one(redeemBad()), []step{
			redeemCode(1, "valid but cooling down"),
			mint(),
			redeemCode(2, "new code, still cooling down"),
			redeemBad(),
		})})
	add(caseRecord{ID: "redeem_success_resets_the_failure_count", Description: "a successful redemption clears the failure counter; four failures are tolerated every time",
		Steps: join(mints(3), repeat(4, redeemBad()), one(redeemCode(1, "first")), repeat(4, redeemBad()), one(redeemCode(2, "second")),
			repeat(4, redeemBad()), one(redeemBad()), one(redeemCode(3, "cooling down")))})
	add(caseRecord{ID: "redeem_expired_codes_count_as_failures", Description: "an expired code is a failed attempt; five of them start the cooldown", CodeTTLMS: 300,
		Steps: join(mints(5), one(sleepStep(700)),
			[]step{redeemCode(1, "x"), redeemCode(2, "x"), redeemCode(3, "x"), redeemCode(4, "x"), redeemCode(5, "x")},
			one(mint()), one(redeemCode(6, "fresh but cooling down")))})
	add(caseRecord{ID: "enrolled_device_decides_approvals", Description: "the enrolled bearer authorises the device approval API; decided_by is the new device id",
		Queue: []queueSpec{{Key: "a", Agent: "agent-a", Path: "notes/a.md", Write: true, Reason: "approve me"}, {Key: "b", Agent: "agent-b", Path: "notes/b.md", Reason: "deny me"}},
		Steps: []step{
			mint(), mint(),
			rq("GET", "/api/v1/approvals", map[string]string{"Authorization": "Bearer {code:1}"}, ""),
			redeemCode(1, "phone"),
			redeemCode(2, "tablet"),
			rq("GET", "/api/v1/approvals", bearer(1), ""),
			rq("POST", "/api/v1/approvals/{id:a}/approve", bearer(1), ""),
			rq("POST", "/api/v1/approvals/{id:b}/deny", bearer(2), ""),
			rq("GET", "/api/v1/approvals", bearer(2), ""),
		}})
	add(caseRecord{ID: "enrolled_devices_are_independent_and_revocable", Description: "every redemption yields a distinct device id and token; revoking one device (a second store instance) leaves the other working",
		Steps: []step{
			mint(), mint(),
			redeemCode(1, "phone"),
			redeemCode(2, "tablet"),
			rq("GET", "/api/v1/approvals", bearer(1), ""),
			rq("GET", "/api/v1/approvals", bearer(2), ""),
			{Action: "revoke_external", Device: "{device:1}"},
			rq("GET", "/api/v1/approvals", bearer(1), ""),
			rq("GET", "/api/v1/approvals", bearer(2), ""),
		}})
	add(caseRecord{ID: "redeem_body_over_one_mib", Description: "Go reads only the first JSON value and sets no body limit: a body above one MiB is served",
		Steps: join(one(mint()), []step{
			redeemBody(`{"code":"{code:1}","device_name":"big","pad":"{pad:1200000}"}`),
		})})
	return out
}

func mergeHeaders(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------- main

func main() {
	log.SetFlags(0)
	check := flag.Bool("check", false, "regenerate in memory and require byte equality with the committed fixture")
	output := flag.String("output", "", "override fixture path (default "+fixtureRel+")")
	flag.Parse()

	root, err := repoRoot()
	must(err)
	path := *output
	if path == "" {
		path = filepath.Join(root, filepath.FromSlash(fixtureRel))
	}
	data, err := generate(root)
	must(err)
	if *check {
		committed, err := os.ReadFile(path) // #nosec G304 -- fixed repository fixture path.
		must(err)
		if !bytes.Equal(committed, data) {
			log.Fatalf("deviceenrollgen: %s differs from regenerated oracle output\n%s", path, firstDifference(committed, data))
		}
		fmt.Printf("deviceenrollgen: %s reproduced byte-for-byte (%d bytes)\n", path, len(data))
		return
	}
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, data, 0o644)) // #nosec G306 -- public test fixture.
	fmt.Printf("deviceenrollgen: wrote %s (%d bytes)\n", path, len(data))
}

func must(err error) {
	if err != nil {
		log.Fatalf("deviceenrollgen: %v", err)
	}
}

func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("locate repository root: %w", err)
	}
	return filepath.EvalSymlinks(strings.TrimSpace(string(out)))
}

func firstDifference(a, b []byte) string {
	var av, bv fixture
	if json.Unmarshal(a, &av) == nil && json.Unmarshal(b, &bv) == nil {
		if av.Oracle.SourceDigest != bv.Oracle.SourceDigest {
			return "source_digest differs"
		}
		if av.Oracle.GeneratorDigest != bv.Oracle.GeneratorDigest {
			return "generator_digest differs (regenerate after editing the generator)"
		}
		for i := range av.Cases {
			if i >= len(bv.Cases) {
				return "case " + av.Cases[i].ID + " missing from regeneration"
			}
			x, _ := json.Marshal(av.Cases[i])
			y, _ := json.Marshal(bv.Cases[i])
			if !bytes.Equal(x, y) {
				return "first differing case: " + av.Cases[i].ID + "\n committed:   " + string(x) + "\n regenerated: " + string(y)
			}
		}
	}
	return "byte offset differs"
}

func generate(root string) ([]byte, error) {
	sha, err := provenance.Verify(root, oracleCommit, oracleSources)
	if err != nil {
		return nil, err
	}
	digest, err := provenance.Digest(root, oracleSources)
	if err != nil {
		return nil, err
	}
	generatorDigest, err := provenance.Digest(root, []string{generatorFile})
	if err != nil {
		return nil, err
	}
	var mounting []string
	for _, ev := range mountEvidence {
		working, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ev.file))) // #nosec G304 -- pinned source list.
		if err != nil {
			return nil, err
		}
		if !bytes.Contains(working, []byte(ev.line)) {
			return nil, fmt.Errorf("%s no longer contains %q; the generator's mounting is stale", ev.file, ev.line)
		}
		mounting = append(mounting, ev.file+": "+ev.line)
	}

	var records []caseRecord
	requests := 0
	for _, spec := range cases() {
		record, err := runCase(spec)
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", spec.ID, err)
		}
		for _, s := range record.Steps {
			if s.Action == "request" {
				requests++
			}
		}
		records = append(records, record)
	}

	f := fixture{
		SchemaVersion: 1,
		Oracle: oracleMeta{Commit: oracleCommit, CommitSHA: sha, SourceFiles: oracleSources, SourceDigest: digest,
			GeneratorFiles: []string{generatorFile}, GeneratorDigest: generatorDigest},
		Mounting: mounting,
		Constants: constants{
			Secret:                fixtureSecret,
			Fingerprint:           fixtureFingerprint,
			CodeTTLSeconds:        int(pairing.TokenTTL / time.Second),
			SessionTTLSeconds:     int(pairing.DefaultSessionTTL / time.Second),
			ProofWindowSeconds:    30,
			MaxFailedAttempts:     5,
			FailedCooldownSeconds: 30,
		},
		Canonical: map[string]string{
			"codes":      "minted pairing codes are replaced by C0DE<28-digit index> (1-based by first appearance in a case); Go draws 20 random bytes, base32-hex, 32 characters of [0-9A-V]",
			"tokens":     "device bearer tokens are replaced by T0KE<28-digit index>; same shape as codes",
			"device_ids": "device ids are replaced by dev-<16-digit hex index>; Go draws 8 random bytes (dev- plus 16 lower-case hex digits)",
			"expires_at": canonicalExpires + " (asserted to be within 3 s of now plus the code lifetime, or plus the session lifetime for an enrolment)",
			"queue_ids":  "request ids are replaced by apr-a<11-digit index>",
			"created_at": canonicalCreated,
			"decided_at": canonicalDecided + " (the undecided zero time " + zeroTime + " is kept)",
		},
		Scope: map[string]string{
			"transport":      "raw HTTP/1.1 over a loopback TCP listener serving the Go http.ServeMux; only Content-Type, X-Content-Type-Options and Location response headers are contract, Date/Content-Length/Connection are HTTP-library artefacts",
			"mounting":       "the Go server mounts the four handlers on a ServeMux; the generator rebuilds that mux and pins the mounting source lines (mounting)",
			"rate_limit":     "serverbootstrap wraps both enrolment routes in auth.RateLimiterMiddleware (default 60 requests/minute/IP); this recording drives the handlers on a bare mux, so no throttling is recorded here and the replay disables the Rust limiter (rate_limit 0); throttling of the enrolment routes is recorded by http002ratelimitgen",
			"non_loopback":   "cases flagged non_loopback_peer use a loopback predicate that refuses every peer, because a non-loopback TCP peer cannot be produced portably; the replay answers them through the handler function with a documentation-range peer address",
			"cooldown_end":   "the end of the 30 s failure cooldown is not recorded (it would need a 30 s sleep); the Rust TokenStore pins it with an injected clock (symvault-sync pairing tests)",
			"timing":         "code lifetime cases use a 300 ms lifetime and a 700 ms pause; proof windows use +-20 s (accepted) and +-35 s (refused) so the second boundary cannot flip a result",
			"not_recorded":   "HEAD requests, TLS/mTLS (owned by HTTP-001..004 fixtures), peers other than loopback over a real socket and request bodies that are not UTF-8",
			"sessions_after": "store_after is read back from the persisted device-sessions.json through a fresh store: names, public keys and revocation; the raw bearer token is asserted absent from the file",
		},
		Counts: map[string]int{"cases": len(records), "requests": requests},
		Cases:  records,
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(f); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// ---------------------------------------------------------------- execution

type world struct {
	spec     caseRecord
	dir      string
	addr     string
	srv      *http.Server
	secret   []byte
	queue    *approval.Queue
	queueIDs map[string]string // key -> real id
	queueOrd map[string]string // real id -> canonical id
	codes    []string          // index-1 -> real code
	tokens   []string
	devices  []string
	codeCan  map[string]string
	tokCan   map[string]string
	devCan   map[string]string
}

func canonCode(n int) string  { return fmt.Sprintf("C0DE%028d", n) }
func canonToken(n int) string { return fmt.Sprintf("T0KE%028d", n) }
func canonDev(n int) string   { return fmt.Sprintf("dev-%016x", n) }
func canonQueue(n int) string { return fmt.Sprintf("apr-a%011d", n) }

func runCase(spec caseRecord) (caseRecord, error) {
	dir, err := os.MkdirTemp("", "deviceenrollgen-*")
	if err != nil {
		return spec, err
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		return spec, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if spec.CodeTTLMS > 0 {
		previous := pairing.TokenTTL
		pairing.TokenTTL = time.Duration(spec.CodeTTLMS) * time.Millisecond
		defer func() { pairing.TokenTTL = previous }()
	}

	w := &world{spec: spec, dir: dir, secret: []byte(fixtureSecret), queue: approval.NewQueue(),
		queueIDs: map[string]string{}, queueOrd: map[string]string{},
		codeCan: map[string]string{}, tokCan: map[string]string{}, devCan: map[string]string{}}
	defer w.queue.Close()

	sessions, err := pairing.NewDeviceSessionStore(dir)
	if err != nil {
		return spec, err
	}
	codes := pairing.NewTokenStore()
	for i, q := range spec.Queue {
		id, err := w.queue.Enqueue(approval.Request{AgentName: q.Agent, Path: q.Path, Write: q.Write, Reason: q.Reason})
		if err != nil {
			return spec, err
		}
		w.queueIDs[q.Key] = id
		w.queueOrd[id] = canonQueue(i + 1)
		time.Sleep(6 * time.Millisecond)
	}

	fingerprint := fixtureFingerprint
	if spec.NoFingerprint {
		fingerprint = ""
	}
	loopback := mcputil.IsLoopbackHost
	if spec.NonLoopbackPeer {
		loopback = func(string) bool { return false }
	}
	approvalHandler := approval.NewHTTPHandler(w.queue, sessions)
	mux := http.NewServeMux()
	mux.Handle(approval.PathApprovals, approvalHandler)
	mux.Handle(approval.PathApprovalAction, approvalHandler)
	mux.Handle(approval.PathDeviceEnroll, approval.NewEnrollHTTPHandler(codes, sessions))
	mux.Handle(approval.PathDeviceEnrollCode, approval.NewEnrollCodeHTTPHandler(codes, fingerprint, loopback, w.secret))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return spec, err
	}
	w.addr = listener.Addr().String()
	w.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = w.srv.Serve(listener) }()
	defer func() { _ = w.srv.Close() }()

	out := spec
	out.Steps = nil
	for _, s := range spec.Steps {
		switch s.Action {
		case "sleep":
			time.Sleep(time.Duration(s.SleepMS) * time.Millisecond)
			out.Steps = append(out.Steps, s)
		case "revoke_external":
			other, err := pairing.NewDeviceSessionStore(dir)
			if err != nil {
				return spec, err
			}
			other.Revoke(w.expand(s.Device, time.Now()))
			out.Steps = append(out.Steps, s)
		case "request":
			resp, err := w.send(*s.Request)
			if err != nil {
				return spec, err
			}
			rec := s
			rec.Response = resp
			out.Steps = append(out.Steps, rec)
		default:
			return spec, fmt.Errorf("unknown action %q", s.Action)
		}
	}
	out.StoreAfter, err = w.storeAfter()
	if err != nil {
		return spec, err
	}
	return out, nil
}

// storeAfter reads the persisted sessions back through a fresh store and
// asserts the file holds no raw bearer token.
func (w *world) storeAfter() ([]storedSession, error) {
	raw, err := os.ReadFile(filepath.Join(w.dir, ".symvault", "device-sessions.json")) // #nosec G304 -- temp dir owned by the generator.
	if err != nil {
		if os.IsNotExist(err) {
			return []storedSession{}, nil
		}
		return nil, err
	}
	for _, token := range w.tokens {
		if bytes.Contains(raw, []byte(token)) {
			return nil, fmt.Errorf("a raw bearer token was persisted")
		}
	}
	store, err := pairing.NewDeviceSessionStore(w.dir)
	if err != nil {
		return nil, err
	}
	out := []storedSession{}
	for _, session := range store.List() {
		canon, ok := w.devCan[session.DeviceID]
		if !ok {
			return nil, fmt.Errorf("persisted session for unknown device %q", session.DeviceID)
		}
		out = append(out, storedSession{DeviceID: canon, Name: compactName(session.Name), PublicKey: session.PublicKey, Revoked: session.Revoked})
		if !strings.HasPrefix(w.tokenOf(session.DeviceID), session.Prefix) || len(session.Prefix) != 4 {
			return nil, fmt.Errorf("session prefix %q is not the token prefix", session.Prefix)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

func (w *world) tokenOf(deviceID string) string {
	for i, d := range w.devices {
		if d == deviceID && i < len(w.tokens) {
			return w.tokens[i]
		}
	}
	return ""
}

var placeholder = regexp.MustCompile(`\{(code|token|device|ts|proof|badproof|pad|id):([^{}]*)\}`)

// expand resolves placeholders against one clock reading so a timestamp and
// its proof always describe the same second.
func (w *world) expand(s string, now time.Time) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		parts := placeholder.FindStringSubmatch(m)
		kind, arg := parts[1], parts[2]
		switch kind {
		case "code":
			return w.expandCode(arg)
		case "token":
			n, _ := strconv.Atoi(arg)
			return w.tokens[n-1]
		case "device":
			n, _ := strconv.Atoi(arg)
			return w.devices[n-1]
		case "id":
			return w.queueIDs[arg]
		case "pad":
			n, _ := strconv.Atoi(arg)
			return strings.Repeat("a", n)
		case "ts":
			form, offset, _ := strings.Cut(arg, ":")
			n, _ := strconv.Atoi(offset)
			return tsForm(form, now.Add(time.Duration(n)*time.Second).UTC().Truncate(time.Second))
		case "proof", "badproof":
			offset, transform, _ := strings.Cut(arg, ":")
			n, _ := strconv.Atoi(offset)
			secret := w.secret
			if kind == "badproof" {
				secret = []byte("a-different-enroll-secret-value!")
			}
			proof := approval.EnrollProof(secret, now.Add(time.Duration(n)*time.Second).UTC().Truncate(time.Second))
			switch transform {
			case "upper":
				return strings.ToUpper(proof)
			case "short":
				return proof[:63]
			case "long":
				return proof + "0"
			case "nonhex":
				return "g" + proof[1:]
			case "padded":
				return " " + proof + " "
			}
			return proof
		}
		return m
	})
}

func (w *world) expandCode(arg string) string {
	index, transform, _ := strings.Cut(arg, ":")
	n, _ := strconv.Atoi(index)
	code := w.codes[n-1]
	switch transform {
	case "lower":
		return strings.ToLower(code)
	case "cut":
		return code[:31]
	case "plus":
		return code + "A"
	case "dashed":
		return code[:8] + "-" + code[8:]
	}
	return code
}

// tsForm spells the instant t (UTC, whole seconds) in the named way.
func tsForm(form string, t time.Time) string {
	const layout = "2006-01-02T15:04:05"
	switch form {
	case "utc":
		return t.Format(time.RFC3339)
	case "plus2":
		return t.In(time.FixedZone("", 7200)).Format(time.RFC3339)
	case "minus0530":
		return t.In(time.FixedZone("", -(5*3600 + 30*60))).Format(time.RFC3339)
	case "plus00":
		return t.Format(layout) + "+00:00"
	case "frac":
		return t.Format(layout) + ".5Z"
	case "frac9":
		return t.Format(layout) + ".123456789Z"
	case "comma":
		return t.Format(layout) + ",5Z"
	case "lower_t":
		return strings.Replace(t.Format(time.RFC3339), "T", "t", 1)
	case "lower_z":
		return strings.Replace(t.Format(time.RFC3339), "Z", "z", 1)
	case "space_sep":
		return strings.Replace(t.Format(time.RFC3339), "T", " ", 1)
	case "no_colon":
		return t.In(time.FixedZone("", 7200)).Format("2006-01-02T15:04:05-0700")
	case "lead_space":
		return " " + t.Format(time.RFC3339)
	case "trail_space":
		return t.Format(time.RFC3339) + " "
	case "no_zone":
		return t.Format(layout)
	case "feb30":
		return "2026-02-30T00:00:00Z"
	case "hour24":
		return "2026-01-02T24:00:00Z"
	case "leap60":
		return "2026-06-30T23:59:60Z"
	case "frac12":
		return t.Format(layout) + ".123456789012Z"
	case "frac_dot":
		return t.Format(layout) + ".Z"
	case "plus2400":
		return t.Add(24*time.Hour).Format(layout) + "+24:00"
	case "minus2400":
		return t.Add(-24*time.Hour).Format(layout) + "-24:00"
	case "plus2500":
		return t.Add(25*time.Hour).Format(layout) + "+25:00"
	case "plus0060":
		return t.Add(time.Hour).Format(layout) + "+00:60"
	case "plus0061":
		return t.Add(time.Hour+time.Minute).Format(layout) + "+00:61"
	case "plus0160":
		return t.Add(2*time.Hour).Format(layout) + "+01:60"
	case "hour1":
		// A zone chosen so the written wall clock has a one-digit hour
		// (Go's "15" takes one or two digits).
		shift := 5 - t.Hour()
		sign, magnitude := "+", shift
		if shift < 0 {
			sign, magnitude = "-", -shift
		}
		local := t.Add(time.Duration(shift) * time.Hour)
		return fmt.Sprintf("%d-%02d-%02dT%d:%02d:%02d%s%02d:00", local.Year(), int(local.Month()), local.Day(), local.Hour(), local.Minute(), local.Second(), sign, magnitude)
	case "single_digit":
		return fmt.Sprintf("%d-%d-%dT%d:%d:%dZ", t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second())
	case "epoch":
		return "0001-01-01T00:00:00Z"
	case "far":
		return "9999-12-31T23:59:59Z"
	}
	panic("unknown timestamp form " + form)
}

var (
	codeFieldRE    = regexp.MustCompile(`"code":"([^"]*)"`)
	tokenFieldRE   = regexp.MustCompile(`"token":"([^"]*)"`)
	deviceFieldRE  = regexp.MustCompile(`"device_id":"([^"]*)"`)
	expiresRE      = regexp.MustCompile(`"expires_at":"([^"]*)"`)
	createdRE      = regexp.MustCompile(`"created_at":"[^"]*"`)
	decidedRE      = regexp.MustCompile(`"decided_at":"[^"]*"`)
	tokenShapeRE   = regexp.MustCompile(`^[0-9A-V]{32}$`)
	deviceShapeRE  = regexp.MustCompile(`^dev-[0-9a-f]{16}$`)
	instantShapeRE = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d*[1-9])?Z$`)
)

// canonical replaces everything Go draws at random or reads from the clock,
// after asserting its shape.
func (w *world) canonical(s string, sent time.Time) (string, error) {
	var failure error
	fail := func(format string, args ...any) string {
		if failure == nil {
			failure = fmt.Errorf(format, args...)
		}
		return ""
	}
	s = codeFieldRE.ReplaceAllStringFunc(s, func(m string) string {
		real := codeFieldRE.FindStringSubmatch(m)[1]
		if !tokenShapeRE.MatchString(real) {
			return fail("pairing code %q has an unexpected shape", real)
		}
		canon, ok := w.codeCan[real]
		if !ok {
			w.codes = append(w.codes, real)
			canon = canonCode(len(w.codes))
			w.codeCan[real] = canon
		}
		return `"code":"` + canon + `"`
	})
	s = tokenFieldRE.ReplaceAllStringFunc(s, func(m string) string {
		real := tokenFieldRE.FindStringSubmatch(m)[1]
		if !tokenShapeRE.MatchString(real) {
			return fail("bearer token has an unexpected shape")
		}
		w.tokens = append(w.tokens, real)
		canon := canonToken(len(w.tokens))
		w.tokCan[real] = canon
		return `"token":"` + canon + `"`
	})
	s = deviceFieldRE.ReplaceAllStringFunc(s, func(m string) string {
		real := deviceFieldRE.FindStringSubmatch(m)[1]
		if !deviceShapeRE.MatchString(real) {
			return fail("device id %q has an unexpected shape", real)
		}
		w.devices = append(w.devices, real)
		canon := canonDev(len(w.devices))
		w.devCan[real] = canon
		return `"device_id":"` + canon + `"`
	})
	enrolment := strings.Contains(s, `"token"`)
	minted := strings.Contains(s, `"fingerprint"`)
	s = expiresRE.ReplaceAllStringFunc(s, func(m string) string {
		real := expiresRE.FindStringSubmatch(m)[1]
		switch {
		case minted:
			if err := w.checkExpiry(real, sent, pairing.TokenTTL); err != nil {
				return fail("%v", err)
			}
			return `"expires_at":"` + canonicalExpires + `"`
		case enrolment:
			if err := w.checkExpiry(real, sent, pairing.DefaultSessionTTL); err != nil {
				return fail("%v", err)
			}
			return `"expires_at":"` + canonicalExpires + `"`
		}
		if !instantShapeRE.MatchString(real) {
			return fail("expires_at %q has an unexpected shape", real)
		}
		return `"expires_at":"` + canonicalExpires + `"`
	})
	for real, canon := range w.queueOrd {
		s = strings.ReplaceAll(s, real, canon)
	}
	// decided_by carries the enrolled device id.
	for real, canon := range w.devCan {
		s = strings.ReplaceAll(s, real, canon)
	}
	s = createdRE.ReplaceAllString(s, `"created_at":"`+canonicalCreated+`"`)
	s = decidedRE.ReplaceAllStringFunc(s, func(m string) string {
		if m == `"decided_at":"`+zeroTime+`"` {
			return m
		}
		return `"decided_at":"` + canonicalDecided + `"`
	})
	return s, failure
}

func (w *world) checkExpiry(value string, sent time.Time, ttl time.Duration) error {
	if !instantShapeRE.MatchString(value) {
		return fmt.Errorf("expires_at %q is not RFC3339Nano in UTC with trimmed fraction", value)
	}
	at, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return err
	}
	if diff := at.Sub(sent.Add(ttl)); diff > 3*time.Second || diff < -3*time.Second {
		return fmt.Errorf("expires_at %s is %s away from now+%s", value, diff, ttl)
	}
	return nil
}

func (w *world) send(r requestRecord) (*responseRecord, error) {
	now := time.Now()
	path := w.expand(r.Path, now)
	body := w.expand(r.Body, now)
	conn, err := net.DialTimeout("tcp", w.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, path, w.addr)
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "%s: %s\r\n", name, w.expand(r.Header[name], now))
	}
	for _, line := range r.ExtraHeaderLines {
		fmt.Fprintf(&b, "%s\r\n", w.expand(line, now))
	}
	if body != "" {
		// The default content type is not repeated when the case sets its own.
		if !hasHeader(r.Header, "Content-Type") {
			b.WriteString("Content-Type: application/json\r\n")
		}
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	for _, name := range []string{"Content-Type", "X-Content-Type-Options", "Location"} {
		if v := resp.Header.Get(name); v != "" {
			headers[name] = v
		}
	}
	canonicalBody, err := w.canonical(string(raw), now)
	if err != nil {
		return nil, err
	}
	// A redirect's Location may carry a query string; it is part of the contract.
	return &responseRecord{Status: resp.StatusCode, Headers: headers, Body: canonicalBody}, nil
}

// compactName records a long run of "a" as its {pad:N} placeholder so the
// fixture does not carry the padding.
func compactName(name string) string {
	if len(name) > 64 && strings.Trim(name, "a") == "" {
		return fmt.Sprintf("{pad:%d}", len(name))
	}
	return name
}

func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}
