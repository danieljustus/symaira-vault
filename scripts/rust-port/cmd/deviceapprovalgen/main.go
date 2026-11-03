// Command deviceapprovalgen freezes the APPROVAL-001 device-token approval
// endpoint (/api/v1/approvals) from the production Go implementation.
//
// It builds the exact stack the Go server mounts (cmd/mcp/serve_deps.go:
// approval.NewHTTPHandler(ApprovalQueue, sessionStore) with the real
// pairing.DeviceSessionStore; internal/mcp/serverbootstrap/http.go: the handler
// registered on approval.PathApprovals and approval.PathApprovalAction in an
// http.ServeMux), serves it on a real loopback listener and drives it with raw
// HTTP/1.1 requests, recording every status, contract header and body byte.
//
// Values Go randomises (queue ids, wall-clock timestamps, bearer tokens) are
// replaced by fixed canonical values; everything else (field order, HTML
// escaping, trailing newline, error texts) is the recorded Go bytes. The Rust
// replay (crates/symvault-mcp/tests/device_approvals_replay.rs) rebuilds the
// same scenarios against the Rust MCP HTTP server with no Go.
//
// Modes:
//
//	deviceapprovalgen            regenerate testdata/port/approval/device-approvals.json
//	deviceapprovalgen --check    regenerate in memory and require byte equality
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	"github.com/danieljustus/symaira-vault/internal/pairing"
)

// oracleCommit is the revision whose sources this fixture freezes. Every file
// in oracleSources must be byte-identical to its blob at this commit.
const oracleCommit = "8d2e5e156cd95f04e608182ab8179fdd49f1884a"

var oracleSources = []string{
	"cmd/mcp/serve_deps.go",
	"internal/approval/http.go",
	"internal/approval/queue.go",
	"internal/mcp/auth/token.go",
	"internal/mcp/serverbootstrap/http.go",
	"internal/pairing/devicesession.go",
}

var generatorFiles = []string{"scripts/rust-port/cmd/deviceapprovalgen/main.go"}

// mountEvidence are the source lines the generator's mux replicates. They are
// checked against the pinned sources so a changed mounting cannot go unnoticed.
var mountEvidence = []struct{ file, line string }{
	{"cmd/mcp/serve_deps.go", "approvalHandler := approval.NewHTTPHandler(ApprovalQueue, sessionStore)"},
	{"cmd/mcp/serve_deps.go", "serverbootstrap.WithApprovalAPI(approvalHandler)"},
	{"internal/mcp/serverbootstrap/http.go", "mux.Handle(approval.PathApprovals, approvalChain)"},
	{"internal/mcp/serverbootstrap/http.go", "mux.Handle(approval.PathApprovalAction, approvalChain)"},
}

const (
	fixtureRel = "testdata/port/approval/device-approvals.json"

	canonicalCreated = "2026-01-02T03:04:05.123456789Z"
	canonicalExpires = "2026-01-02T03:09:05.123456789Z"
	canonicalDecided = "2026-01-02T03:04:07.25Z"
	zeroTime         = "0001-01-01T00:00:00Z"
	unknownID        = "apr-ffffffffffff"
)

// ---------------------------------------------------------------- fixture

type sourceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type oracleMeta struct {
	Commit          string       `json:"commit"`
	Release         string       `json:"release"`
	SourceFiles     []sourceFile `json:"source_files"`
	SourceDigest    string       `json:"source_digest"`
	GeneratorFiles  []string     `json:"generator_files"`
	GeneratorDigest string       `json:"generator_digest"`
}

// deviceSpec enrols one approval device before the server starts.
type deviceSpec struct {
	Name     string `json:"name"`
	DeviceID string `json:"device_id"`
	// State is "active", "revoked" (revoked through the store before the
	// server starts) or "expired" (expires_at rewritten into the past in the
	// persisted store before the server loads it).
	State string `json:"state"`
}

// queueSpec enqueues one request, in order, before the first step.
type queueSpec struct {
	Key    string `json:"key"`
	Agent  string `json:"agent_name"`
	Path   string `json:"path"`
	Write  bool   `json:"write"`
	Reason string `json:"reason"`
	// TTLMillis, when non-zero, sets the request's own expiry.
	TTLMillis int `json:"ttl_ms,omitempty"`
}

type requestRecord struct {
	Method string `json:"method"`
	// Path is the raw request target; {id:<key>} is a queue placeholder.
	Path string `json:"path"`
	// AuthHeaderName defaults to Authorization.
	AuthHeaderName string `json:"auth_header_name,omitempty"`
	// Authorization is the header value ("" = header absent); {token:<name>}
	// is a device bearer placeholder.
	Authorization string `json:"authorization"`
	Body          string `json:"body,omitempty"`
}

type responseRecord struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type step struct {
	// Action is "request", "revoke_external" (a second store instance revokes
	// Device, as `symvault device approval-revoke` does) or "sleep".
	Action   string          `json:"action"`
	Device   string          `json:"device,omitempty"`
	SleepMS  int             `json:"sleep_ms,omitempty"`
	Request  *requestRecord  `json:"request,omitempty"`
	Response *responseRecord `json:"response,omitempty"`
}

type caseRecord struct {
	ID          string       `json:"id"`
	Description string       `json:"description"`
	Devices     []deviceSpec `json:"devices"`
	Queue       []queueSpec  `json:"queue"`
	// SettleMS is the pause after enqueueing, so short-lived requests expire.
	SettleMS int    `json:"settle_ms,omitempty"`
	Steps    []step `json:"steps"`
}

type fixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        oracleMeta        `json:"oracle"`
	Mounting      []string          `json:"mounting"`
	Canonical     map[string]string `json:"canonical"`
	Scope         map[string]string `json:"scope"`
	Counts        map[string]int    `json:"counts"`
	Cases         []caseRecord      `json:"cases"`
}

// ---------------------------------------------------------------- cases

var (
	phone  = deviceSpec{Name: "phone", DeviceID: "dev-phone", State: "active"}
	tablet = deviceSpec{Name: "tablet", DeviceID: "dev-tablet", State: "active"}

	qA = queueSpec{Key: "a", Agent: "agent-a", Path: "notes/a.md", Write: true, Reason: "approve me"}
	qB = queueSpec{Key: "b", Agent: "agent-b", Path: "notes/b <draft>.md", Write: false, Reason: `needs "review" & <care>`}
	qC = queueSpec{Key: "c", Agent: "agent-c", Path: "notes/c.md", Write: false, Reason: "third"}
)

func req(method, path, auth string) *requestRecord {
	return &requestRecord{Method: method, Path: path, Authorization: auth}
}

func do(method, path, auth string) step {
	return step{Action: "request", Request: req(method, path, auth)}
}

const (
	bearerPhone  = "Bearer {token:phone}"
	bearerTablet = "Bearer {token:tablet}"
	list         = "/api/v1/approvals"
	action       = "/api/v1/approvals/"
)

func cases() []caseRecord {
	devs := []deviceSpec{phone}
	devs2 := []deviceSpec{phone, tablet}
	q3 := []queueSpec{qA, qB, qC}
	return []caseRecord{
		{ID: "list_empty", Description: "empty queue lists {\"requests\":[]}", Devices: devs,
			Steps: []step{do("GET", list, bearerPhone)}},
		{ID: "list_nonempty_newest_first", Description: "pending requests newest first, Go HTML escaping, undecided decided_at is the zero time", Devices: devs, Queue: q3,
			Steps: []step{do("GET", list, bearerPhone)}},
		{ID: "list_query_string_ignored", Description: "r.URL.Path excludes the query", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{do("GET", list+"?x=1&y=2", bearerPhone)}},
		{ID: "list_excludes_decided_and_expired", Description: "approved and expired requests leave the pending list", Devices: devs,
			Queue:    []queueSpec{qA, qB, {Key: "e", Agent: "agent-e", Path: "notes/e.md", Reason: "short lived", TTLMillis: 150}},
			SettleMS: 450,
			Steps: []step{
				do("POST", action+"{id:a}/approve", bearerPhone),
				do("GET", list, bearerPhone),
			}},
		{ID: "approve_records_device_id", Description: "decided_by is the device id of the bearer, not its name; two devices", Devices: devs2, Queue: q3,
			Steps: []step{
				do("POST", action+"{id:a}/approve", bearerPhone),
				do("POST", action+"{id:b}/deny", bearerTablet),
				do("GET", list, bearerTablet),
			}},
		{ID: "approve_trailing_slash", Description: "one trailing slash after the action is trimmed", Devices: devs, Queue: q3,
			Steps: []step{
				do("POST", action+"{id:a}/approve/", bearerPhone),
				do("POST", action+"{id:b}/deny/", bearerPhone),
			}},
		{ID: "decide_body_ignored", Description: "no request body is read: malformed JSON (and any other body) does not change the decision", Devices: devs, Queue: q3,
			Steps: []step{
				{Action: "request", Request: &requestRecord{Method: "POST", Path: action + "{id:a}/approve", Authorization: bearerPhone, Body: "{not json"}},
				{Action: "request", Request: &requestRecord{Method: "POST", Path: action + "{id:b}/deny", Authorization: bearerPhone, Body: `{"status":"approved","decided_by":"attacker"}`}},
			}},
		{ID: "decide_repeat_conflicts", Description: "a decided request cannot be decided again; the conflict names the first decision", Devices: devs, Queue: q3,
			Steps: []step{
				do("POST", action+"{id:a}/approve", bearerPhone),
				do("POST", action+"{id:a}/approve", bearerPhone),
				do("POST", action+"{id:a}/deny", bearerPhone),
				do("POST", action+"{id:b}/deny", bearerPhone),
				do("POST", action+"{id:b}/approve", bearerPhone),
				do("GET", list, bearerPhone),
			}},
		{ID: "decide_expired_conflicts", Description: "an expired request is not decidable", Devices: devs,
			Queue:    []queueSpec{{Key: "e", Agent: "agent-e", Path: "notes/e.md", Reason: "short lived", TTLMillis: 150}},
			SettleMS: 450,
			Steps: []step{
				do("POST", action+"{id:e}/approve", bearerPhone),
				do("POST", action+"{id:e}/deny", bearerPhone),
			}},
		{ID: "decide_unknown_id", Description: "unknown id is 404 for approve and deny; nested ids are not special", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{
				do("POST", action+"apr-ffffffffffff/approve", bearerPhone),
				do("POST", action+"apr-ffffffffffff/deny", bearerPhone),
				do("POST", action+"a/b/approve", bearerPhone),
				do("POST", action+"{id:a}/x/approve", bearerPhone),
				do("GET", list, bearerPhone),
			}},
		{ID: "decide_percent_encoded_id", Description: "the handler sees the decoded path", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{do("POST", action+"%61{idtail:a}/approve", bearerPhone)}},
		{ID: "decide_missing_id", Description: "an authenticated POST to the bare subtree root has no id", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{do("POST", action, bearerPhone)}},
		{ID: "decide_unknown_action", Description: "an id without /approve or /deny suffix is an unknown action", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{
				do("POST", action+"{id:a}", bearerPhone),
				do("POST", action+"{id:a}/reject", bearerPhone),
				do("POST", action+"{id:a}/approved", bearerPhone),
				do("POST", action+"approve", bearerPhone),
				do("POST", action+"deny/", bearerPhone),
				do("GET", list, bearerPhone),
			}},
		{ID: "auth_missing_or_malformed_bearer", Description: "401 for every Authorization value that is not exactly \"Bearer <token>\", list and decide", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{
				do("GET", list, ""),
				do("POST", action+"{id:a}/approve", ""),
				do("GET", list, "Bearer"),
				do("GET", list, "Bearer "),
				do("POST", action+"{id:a}/approve", "Bearer "),
				do("GET", list, "bearer {token:phone}"),
				do("GET", list, "BEARER {token:phone}"),
				do("GET", list, "Basic {token:phone}"),
				do("GET", list, "Token {token:phone}"),
				do("GET", list, "{token:phone}"),
				do("GET", list, "Bearer  {token:phone}"),
				do("GET", list, "Bearer {token:phone} extra"),
				do("POST", action+"{id:a}/approve", "{token:phone}"),
				do("GET", list, bearerPhone),
			}},
		{ID: "auth_header_name_case_insensitive", Description: "header names are case-insensitive", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{{Action: "request", Request: &requestRecord{Method: "GET", Path: list, AuthHeaderName: "authorization", Authorization: bearerPhone}}}},
		{ID: "auth_unknown_token", Description: "a token no device holds, including other bearer shapes (MCP legacy/scoped tokens are not device tokens)", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{
				do("GET", list, "Bearer not-a-device-token"),
				do("POST", action+"{id:a}/approve", "Bearer not-a-device-token"),
				do("GET", list, "Bearer symvault_mcp_legacy_0123456789abcdef"),
				do("GET", list, "Bearer "+strings.Repeat("A", 8192)),
				do("GET", list, bearerPhone),
			}},
		{ID: "auth_revoked_before_start", Description: "a device revoked before the server loads its store is rejected; the other device still works", Devices: []deviceSpec{{Name: "phone", DeviceID: "dev-phone", State: "revoked"}, tablet}, Queue: []queueSpec{qA},
			Steps: []step{
				do("GET", list, bearerPhone),
				do("POST", action+"{id:a}/approve", bearerPhone),
				do("GET", list, bearerTablet),
			}},
		{ID: "auth_expired_before_start", Description: "a session whose expires_at has passed is rejected", Devices: []deviceSpec{{Name: "phone", DeviceID: "dev-phone", State: "expired"}, tablet}, Queue: []queueSpec{qA},
			Steps: []step{
				do("GET", list, bearerPhone),
				do("POST", action+"{id:a}/approve", bearerPhone),
				do("GET", list, bearerTablet),
			}},
		{ID: "auth_revoked_while_running", Description: "a revocation written by another store instance (the approval-revoke CLI) takes effect on the running server", Devices: devs2, Queue: q3,
			Steps: []step{
				do("GET", list, bearerPhone),
				do("POST", action+"{id:a}/approve", bearerPhone),
				{Action: "revoke_external", Device: "phone"},
				do("GET", list, bearerPhone),
				do("POST", action+"{id:b}/approve", bearerPhone),
				do("POST", action+"{id:b}/deny", bearerTablet),
				do("GET", list, bearerTablet),
			}},
		{ID: "auth_precedes_route_errors", Description: "an unauthenticated decide is 401 before the 400/404/409 route errors and never decides", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{
				do("POST", action, ""),
				do("POST", action+"{id:a}", "Bearer wrong"),
				do("POST", action+"apr-ffffffffffff/approve", "Bearer wrong"),
				do("POST", action+"{id:a}/approve", "Bearer wrong"),
				do("GET", list, bearerPhone),
			}},
		{ID: "method_and_path_not_found", Description: "only GET on the list path and POST below the subtree root are served; everything else is the mux 404 before authentication", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{
				do("POST", list, bearerPhone),
				do("POST", list, ""),
				do("PUT", list, bearerPhone),
				do("DELETE", list, bearerPhone),
				do("GET", action, bearerPhone),
				do("GET", action+"{id:a}/approve", bearerPhone),
				do("GET", action+"{id:a}/approve", ""),
				do("PUT", action+"{id:a}/approve", bearerPhone),
				do("DELETE", action+"{id:a}/deny", bearerPhone),
				do("PATCH", action+"{id:a}/deny", bearerPhone),
				do("GET", "/api/v1/approvalsx", bearerPhone),
				do("GET", "/api/v1/approval", bearerPhone),
				do("POST", "/api/v1/approvalsx/{id:a}/approve", bearerPhone),
				do("GET", list, bearerPhone),
			}},
		{ID: "path_cleaning_redirects", Description: "ServeMux redirects an unclean path to its clean form before the handler runs", Devices: devs, Queue: []queueSpec{qA},
			Steps: []step{
				do("POST", action+"/{id:a}/approve", bearerPhone),
				do("GET", "/api/v1/approvals/../approvals", bearerPhone),
				do("GET", "/api/v1//approvals", bearerPhone),
				do("GET", list, bearerPhone),
			}},
	}
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
			log.Fatalf("deviceapprovalgen: %s differs from regenerated oracle output\n%s", path, firstDifference(committed, data))
		}
		fmt.Printf("deviceapprovalgen: %s reproduced byte-for-byte (%d bytes)\n", path, len(data))
		return
	}
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, data, 0o644)) // #nosec G306 -- public test fixture.
	fmt.Printf("deviceapprovalgen: wrote %s (%d bytes)\n", path, len(data))
}

func must(err error) {
	if err != nil {
		log.Fatalf("deviceapprovalgen: %v", err)
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
	oracle, err := pinOracle(root)
	if err != nil {
		return nil, err
	}
	var mounting []string
	for _, ev := range mountEvidence {
		pinned, err := exec.Command("git", "-C", root, "show", oracleCommit+":"+ev.file).Output()
		if err != nil {
			return nil, fmt.Errorf("read pinned %s: %w", ev.file, err)
		}
		if !bytes.Contains(pinned, []byte(ev.line)) {
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
		Oracle:        oracle,
		Mounting:      mounting,
		Canonical: map[string]string{
			"queue_ids":  "request ids are replaced by apr-a0000000000N (N = 1-based enqueue order); apr-ffffffffffff is a literal unknown id; Go draws 6 random bytes",
			"created_at": canonicalCreated,
			"expires_at": canonicalExpires,
			"decided_at": canonicalDecided + " (the undecided zero time " + zeroTime + " is kept)",
			"tokens":     "device bearer tokens are the placeholder {token:<device name>}; Go draws 20 random bytes per enrolment",
		},
		Scope: map[string]string{
			"transport":      "raw HTTP/1.1 over a loopback TCP listener serving the Go http.ServeMux; only Content-Type, X-Content-Type-Options and Location response headers are contract, Date/Content-Length/Connection are HTTP-library artefacts",
			"mounting":       "the Go server mounts the handler on both patterns of an http.ServeMux when the approval handler option is given; the generator rebuilds that mux and pins the mounting source lines (mounting)",
			"rate_limit":     "serverbootstrap wraps the chain in auth.RateLimiterMiddleware (default 60 requests/minute/IP); the Rust server has no rate limiter on any route, so no throttling case is recorded",
			"store_cleanup":  "Go also runs DeviceSessionStore.StartCleanup every 15 minutes; Validate rejects expired sessions regardless, so only the expiry itself is recorded",
			"expiry_cases":   "request expiry uses a 150 ms lifetime and a 450 ms settle pause; the recorded outcome (409 already expired / absent from the list) is not timing dependent beyond that margin",
			"decision_order": "listing order is newest first by creation instant; requests are enqueued in order with at least 5 ms between them",
			"not_recorded":   "HEAD requests, request bodies above the server limit and TLS/mTLS (transport layers owned by HTTP-001..004 fixtures)",
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

func pinOracle(root string) (oracleMeta, error) {
	meta := oracleMeta{Commit: oracleCommit, Release: "unreleased", GeneratorFiles: generatorFiles}
	digest := sha256.New()
	for _, rel := range oracleSources {
		pinned, err := exec.Command("git", "-C", root, "show", oracleCommit+":"+rel).Output()
		if err != nil {
			return meta, fmt.Errorf("read pinned %s: %w", rel, err)
		}
		working, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- pinned repository source list.
		if err != nil {
			return meta, err
		}
		if !bytes.Equal(pinned, working) {
			return meta, fmt.Errorf("%s differs from its blob at oracle commit %s; advance the pin and refreeze", rel, oracleCommit)
		}
		sum := sha256.Sum256(pinned)
		meta.SourceFiles = append(meta.SourceFiles, sourceFile{Path: rel, SHA256: hex.EncodeToString(sum[:])})
		digest.Write([]byte(rel))
		digest.Write(sum[:])
	}
	meta.SourceDigest = hex.EncodeToString(digest.Sum(nil))
	generatorDigest := sha256.New()
	for _, rel := range generatorFiles {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- generator file list.
		if err != nil {
			return meta, err
		}
		generatorDigest.Write([]byte(rel))
		sum := sha256.Sum256(data)
		generatorDigest.Write(sum[:])
	}
	meta.GeneratorDigest = hex.EncodeToString(generatorDigest.Sum(nil))
	return meta, nil
}

// ---------------------------------------------------------------- execution

type world struct {
	dir    string
	queue  *approval.Queue
	tokens map[string]string // device name -> raw token
	ids    map[string]string // queue key -> real id
	idOrd  map[string]string // real id -> canonical id
	addr   string
	srv    *http.Server
}

func canonicalID(n int) string { return fmt.Sprintf("apr-a%011d", n) }

func runCase(spec caseRecord) (caseRecord, error) {
	dir, err := os.MkdirTemp("", "deviceapprovalgen-*")
	if err != nil {
		return spec, err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return spec, err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	w := &world{dir: dir, queue: approval.NewQueue(), tokens: map[string]string{}, ids: map[string]string{}, idOrd: map[string]string{}}
	defer w.queue.Close()

	// Enrol every device against a first store, then apply the pre-start states.
	seed, err := pairing.NewDeviceSessionStore(dir)
	if err != nil {
		return spec, err
	}
	for _, d := range spec.Devices {
		token, err := seed.Enroll(d.DeviceID, d.Name, "pk-"+d.Name)
		if err != nil {
			return spec, err
		}
		w.tokens[d.Name] = token
	}
	for _, d := range spec.Devices {
		switch d.State {
		case "active":
		case "revoked":
			seed.Revoke(d.DeviceID)
		case "expired":
			if err := expireDevice(dir, d.DeviceID); err != nil {
				return spec, err
			}
		default:
			return spec, fmt.Errorf("unknown device state %q", d.State)
		}
	}
	// The server loads the store from disk, like a restart (or the CLI process).
	store, err := pairing.NewDeviceSessionStore(dir)
	if err != nil {
		return spec, err
	}

	for i, q := range spec.Queue {
		ttl := time.Time{}
		if q.TTLMillis > 0 {
			ttl = time.Now().Add(time.Duration(q.TTLMillis) * time.Millisecond)
		}
		id, err := w.queue.Enqueue(approval.Request{AgentName: q.Agent, Path: q.Path, Write: q.Write, Reason: q.Reason, ExpiresAt: ttl})
		if err != nil {
			return spec, err
		}
		w.ids[q.Key] = id
		w.idOrd[id] = canonicalID(i + 1)
		time.Sleep(6 * time.Millisecond)
	}
	if spec.SettleMS > 0 {
		time.Sleep(time.Duration(spec.SettleMS) * time.Millisecond)
	}

	handler := approval.NewHTTPHandler(w.queue, store)
	mux := http.NewServeMux()
	mux.Handle(approval.PathApprovals, handler)
	mux.Handle(approval.PathApprovalAction, handler)
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
		case "revoke_external":
			other, err := pairing.NewDeviceSessionStore(dir)
			if err != nil {
				return spec, err
			}
			other.Revoke(deviceID(spec, s.Device))
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
	return out, nil
}

func deviceID(spec caseRecord, name string) string {
	for _, d := range spec.Devices {
		if d.Name == name {
			return d.DeviceID
		}
	}
	return name
}

// expireDevice rewrites the persisted expires_at of a device's sessions into
// the past; the real store then decides the session is expired.
func expireDevice(dir, device string) error {
	path := filepath.Join(dir, ".symvault", "device-sessions.json")
	data, err := os.ReadFile(path) // #nosec G304 -- temp dir owned by the generator.
	if err != nil {
		return err
	}
	var sessions map[string]map[string]any
	if err := json.Unmarshal(data, &sessions); err != nil {
		return err
	}
	for _, session := range sessions {
		if session["device_id"] == device {
			session["expires_at"] = "2000-01-01T00:00:00Z"
		}
	}
	data, err = json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

var placeholder = regexp.MustCompile(`\{(id|idtail|token):([a-z]+)\}`)

func (w *world) expand(s string) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		parts := placeholder.FindStringSubmatch(m)
		switch parts[1] {
		case "id":
			return w.ids[parts[2]]
		case "idtail":
			return strings.TrimPrefix(w.ids[parts[2]], "a")
		default:
			return w.tokens[parts[2]]
		}
	})
}

var (
	createdRE = regexp.MustCompile(`"created_at":"[^"]*"`)
	expiresRE = regexp.MustCompile(`"expires_at":"[^"]*"`)
	decidedRE = regexp.MustCompile(`"decided_at":"[^"]*"`)
)

// canonical replaces everything Go draws at random or reads from the clock.
func (w *world) canonical(s string) string {
	for real, canon := range w.idOrd {
		s = strings.ReplaceAll(s, real, canon)
	}
	s = createdRE.ReplaceAllString(s, `"created_at":"`+canonicalCreated+`"`)
	s = expiresRE.ReplaceAllString(s, `"expires_at":"`+canonicalExpires+`"`)
	s = decidedRE.ReplaceAllStringFunc(s, func(m string) string {
		if m == `"decided_at":"`+zeroTime+`"` {
			return m
		}
		return `"decided_at":"` + canonicalDecided + `"`
	})
	return s
}

func (w *world) send(r requestRecord) (*responseRecord, error) {
	conn, err := net.DialTimeout("tcp", w.addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	path := w.expand(r.Path)
	body := w.expand(r.Body)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, path, w.addr)
	if r.Authorization != "" {
		name := r.AuthHeaderName
		if name == "" {
			name = "Authorization"
		}
		fmt.Fprintf(&b, "%s: %s\r\n", name, w.expand(r.Authorization))
	}
	if body != "" {
		fmt.Fprintf(&b, "Content-Type: application/json\r\nContent-Length: %s\r\n", strconv.Itoa(len(body)))
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
			headers[name] = w.canonical(v)
		}
	}
	return &responseRecord{Status: resp.StatusCode, Headers: headers, Body: w.canonical(string(raw))}, nil
}
