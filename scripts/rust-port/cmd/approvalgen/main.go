// Command approvalgen freezes the APPROVAL-001 local approval CLI wire contract
// from the production Go implementation.
//
// It runs the production `approval.LocalHTTPHandler` (HMAC vault-ownership
// proof, loopback gate, queue) behind a TLS listener, drives the real Go CLI
// binary (`symvault approval list|decide`) against it, and records every HTTP
// exchange plus the CLI outcome. Values the Go side randomises (queue ids,
// timestamps, the listener port, temp paths) are replaced by fixed canonical
// values, and the Go CLI is then run a second time against a stub that serves
// exactly the canonical responses, so each recorded stdout/stderr/exit is the
// Go CLI's own rendering of the frozen bytes rather than a text substitution.
//
// The Rust replay (crates/symvault-cli/tests/approval_queue_replay.rs) serves
// the recorded responses over mTLS with the same fixture certificates and
// asserts the Rust CLI's requests and outcomes against the recording, so the
// evidence survives deletion of the Go tree.
//
// Modes:
//
//	approvalgen --init-certs   write the long-lived fixture certificates (once)
//	approvalgen                regenerate testdata/port/approval/queue.json
//	approvalgen --check        regenerate in memory and require byte equality
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
)

// oracleCommit is the revision whose approval sources this fixture freezes.
// Every file in oracleSources must be byte-identical to its blob at this
// commit; the generator refuses to run otherwise.
const oracleCommit = "8d2e5e156cd95f04e608182ab8179fdd49f1884a"

var oracleSources = []string{
	"cmd/approval.go",
	"internal/approval/enroll.go",
	"internal/approval/http.go",
	"internal/approval/local.go",
	"internal/approval/queue.go",
	"internal/cli/port_utils.go",
	"internal/mcp/serverbootstrap/tls.go",
}

var generatorFiles = []string{"scripts/rust-port/cmd/approvalgen/main.go"}

const (
	fixtureRel = "testdata/port/approval/queue.json"
	certsRel   = "testdata/port/approval/certs"

	proofWindow = 30 * time.Second

	canonicalCreated = "2026-01-02T03:04:05.123456789Z"
	canonicalExpires = "2026-01-02T03:09:05.123456789Z"
	canonicalDecided = "2026-01-02T03:04:07.25Z"
	zeroTime         = "0001-01-01T00:00:00Z"
)

// Fixed ownership-proof secrets. The valid secret is what the Go handler holds;
// the wrong secret models a local process that does not own the vault.
var (
	validSecret = func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}()
	wrongSecret = bytes.Repeat([]byte{0xA5}, 32)
)

var certFiles = []string{
	"server.pem", "server.key", "other-server.pem", "other-server.key",
	"client-ca.pem", "client.pem", "client.key",
}

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

type runtimeSpec struct {
	// Port is "listener" (the live test listener), "absent" (no .runtime-port),
	// or "non_loopback_bind".
	Port string `json:"port"`
	// TLS selects the .runtime-tls-cert record: mtls_full, mtls_missing_identity,
	// mtls_reused_server_identity, mtls_wrong_ca, mtls_wrong_key, tls_only
	// (certificate only), tls_unrelated_server (certificate of another server).
	TLS string `json:"tls"`
}

type requestRecord struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	// Headers holds every header Go sent, with the per-invocation values
	// replaced by class placeholders.
	Headers map[string]string `json:"headers"`
	// ProofSecret names the secret the X-Enroll-Proof was computed with.
	ProofSecret string `json:"proof_secret"`
	// ClientCertificateCN is the verified mTLS peer identity, or "" when none.
	ClientCertificateCN string `json:"client_certificate_cn"`
	BodyBytes           int    `json:"body_bytes"`
}

type responseRecord struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

type exchange struct {
	Request  requestRecord  `json:"request"`
	Response responseRecord `json:"response"`
}

type outcome struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	// StderrCompare is "exact", or "prefix" when the Go text embeds a
	// library/OS error that is not a Rust parity target.
	StderrCompare string `json:"stderr_compare"`
	// StderrPrefix is the compared prefix when StderrCompare is "prefix".
	StderrPrefix string `json:"stderr_prefix,omitempty"`
}

type caseRecord struct {
	ID        string      `json:"id"`
	Args      []string    `json:"args"`
	Secret    string      `json:"secret"`
	Runtime   runtimeSpec `json:"runtime"`
	ServerTLS string      `json:"server_tls"`
	Exchanges []exchange  `json:"exchanges"`
	Outcome   outcome     `json:"outcome"`
}

type fixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        oracleMeta        `json:"oracle"`
	SecretHex     map[string]string `json:"secret_hex"`
	Certs         []sourceFile      `json:"certs"`
	Canonical     map[string]string `json:"canonical"`
	Scope         map[string]string `json:"scope"`
	Cases         []caseRecord      `json:"cases"`
}

// ---------------------------------------------------------------- cases

type caseSpec struct {
	id        string
	args      []string // may contain {approve_id} etc.
	secret    string   // "valid" | "wrong"
	runtime   runtimeSpec
	serverTLS string // "mtls" | "tls"
	pre       string // "", "enqueue_expiring", "enqueue_tls"
	stderrKey string // "" exact, else prefix
}

var knownIDs = map[string]string{
	"approve_id":  "apr-a00000000001",
	"deny_id":     "apr-a00000000002",
	"quiet_id":    "apr-a00000000003",
	"tls_id":      "apr-a00000000004",
	"expired_id":  "apr-a00000000005",
	"unknown_id":  "apr-ffffffffffff",
	"unknown_raw": "apr-ffffffffffff",
}

func cases() []caseSpec {
	mtls := runtimeSpec{Port: "listener", TLS: "mtls_full"}
	v, w := "valid", "wrong"
	return []caseSpec{
		{id: "list_json", args: []string{"approval", "list", "--json"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "list_text", args: []string{"approval", "list"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "list_yaml", args: []string{"approval", "list", "--output", "yaml"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "list_quiet", args: []string{"approval", "list", "--quiet"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "approve_json", args: []string{"approval", "decide", "{approve_id}", "--approve", "--json"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "deny_text", args: []string{"approval", "decide", "{deny_id}", "--deny"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "deny_quiet", args: []string{"approval", "decide", "{quiet_id}", "--deny", "--quiet"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "decide_repeat_conflict", args: []string{"approval", "decide", "{approve_id}", "--approve"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "decide_unknown_id", args: []string{"approval", "decide", "{unknown_id}", "--deny"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "list_empty", args: []string{"approval", "list"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "decide_expired", args: []string{"approval", "decide", "{expired_id}", "--approve"}, secret: v, runtime: mtls, serverTLS: "mtls", pre: "enqueue_expiring"},
		{id: "tls_only_list", args: []string{"approval", "list", "--json"}, secret: v, runtime: runtimeSpec{Port: "listener", TLS: "tls_only"}, serverTLS: "tls", pre: "enqueue_tls"},
		{id: "tls_only_decide_yaml", args: []string{"approval", "decide", "{tls_id}", "--approve", "--output", "yaml"}, secret: v, runtime: runtimeSpec{Port: "listener", TLS: "tls_only"}, serverTLS: "tls"},
		{id: "bad_hmac_list", args: []string{"approval", "list", "--json"}, secret: w, runtime: mtls, serverTLS: "mtls"},
		{id: "bad_hmac_decide", args: []string{"approval", "decide", "{approve_id}", "--approve"}, secret: w, runtime: mtls, serverTLS: "mtls"},
		{id: "runtime_absent", args: []string{"approval", "list"}, secret: v, runtime: runtimeSpec{Port: "absent", TLS: "mtls_full"}, serverTLS: "mtls"},
		{id: "non_loopback_bind", args: []string{"approval", "list"}, secret: v, runtime: runtimeSpec{Port: "non_loopback_bind", TLS: "mtls_full"}, serverTLS: "mtls"},
		{id: "decide_no_flag", args: []string{"approval", "decide", "apr-test"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "decide_both_flags", args: []string{"approval", "decide", "apr-test", "--approve", "--deny"}, secret: v, runtime: mtls, serverTLS: "mtls"},
		{id: "mtls_missing_identity", args: []string{"approval", "list"}, secret: v, runtime: runtimeSpec{Port: "listener", TLS: "mtls_missing_identity"}, serverTLS: "mtls"},
		{id: "mtls_reused_server_identity", args: []string{"approval", "list"}, secret: v, runtime: runtimeSpec{Port: "listener", TLS: "mtls_reused_server_identity"}, serverTLS: "mtls"},
		{id: "mtls_wrong_ca", args: []string{"approval", "list"}, secret: v, runtime: runtimeSpec{Port: "listener", TLS: "mtls_wrong_ca"}, serverTLS: "mtls"},
		{id: "mtls_wrong_key", args: []string{"approval", "list"}, secret: v, runtime: runtimeSpec{Port: "listener", TLS: "mtls_wrong_key"}, serverTLS: "mtls"},
		// The runtime record claims no client auth while the listener demands
		// it: the TLS handshake is refused before any HTTP exchange exists.
		{id: "mtls_handshake_rejected", args: []string{"approval", "list"}, secret: v, runtime: runtimeSpec{Port: "listener", TLS: "tls_only"}, serverTLS: "mtls", stderrKey: "connect to local approval server:"},
		{id: "untrusted_server_certificate", args: []string{"approval", "list"}, secret: v, runtime: runtimeSpec{Port: "listener", TLS: "tls_unrelated_server"}, serverTLS: "tls", stderrKey: "connect to local approval server:"},
	}
}

// ---------------------------------------------------------------- main

func main() {
	log.SetFlags(0)
	check := flag.Bool("check", false, "regenerate in memory and require byte equality with the committed fixture")
	initCerts := flag.Bool("init-certs", false, "write the long-lived fixture certificates and exit")
	output := flag.String("output", "", "override fixture path (default "+fixtureRel+")")
	flag.Parse()

	root, err := repoRoot()
	must(err)
	if *initCerts {
		must(writeCerts(filepath.Join(root, filepath.FromSlash(certsRel))))
		return
	}
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
			log.Fatalf("approvalgen: %s differs from regenerated oracle output\n%s", path, firstDifference(committed, data))
		}
		fmt.Printf("approvalgen: %s reproduced byte-for-byte (%d bytes)\n", path, len(data))
		return
	}
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, data, 0o644)) // #nosec G306 -- public test fixture.
	fmt.Printf("approvalgen: wrote %s (%d bytes)\n", path, len(data))
}

func must(err error) {
	if err != nil {
		log.Fatalf("approvalgen: %v", err)
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

// ---------------------------------------------------------------- generation

func generate(root string) ([]byte, error) {
	oracle, err := pinOracle(root)
	if err != nil {
		return nil, err
	}
	certsDir := filepath.Join(root, filepath.FromSlash(certsRel))
	certDigests, err := digestCerts(certsDir)
	if err != nil {
		return nil, err
	}

	tmp, err := os.MkdirTemp("", "approvalgen-*")
	if err != nil {
		return nil, err
	}
	tmp, err = filepath.EvalSymlinks(tmp)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	binary := filepath.Join(tmp, "symvault-go")
	build := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
	build.Dir = root
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		return nil, fmt.Errorf("build Go CLI oracle: %w\n%s", buildErr, out)
	}

	env := &runEnv{root: root, tmp: tmp, certs: certsDir, binary: binary}
	live, err := newLiveQueue()
	if err != nil {
		return nil, err
	}
	defer live.queue.Close()

	var records []caseRecord
	for _, spec := range cases() {
		record, runErr := env.runCase(spec, live)
		if runErr != nil {
			return nil, fmt.Errorf("case %s: %w", spec.id, runErr)
		}
		records = append(records, record)
	}

	f := fixture{
		SchemaVersion: 1,
		Oracle:        oracle,
		SecretHex: map[string]string{
			"valid": hex.EncodeToString(validSecret),
			"wrong": hex.EncodeToString(wrongSecret),
		},
		Certs: certDigests,
		Canonical: map[string]string{
			"queue_ids":          "request ids are replaced by apr-a0000000000N (apr-ffffffffffff for the unknown id); Go draws 6 random bytes",
			"created_at":         canonicalCreated,
			"expires_at":         canonicalExpires,
			"decided_at":         canonicalDecided + " (deliberately a trimmed-nanosecond form; the undecided zero time " + zeroTime + " is kept)",
			"port":               "the listener port is the literal {port} in recorded Host headers and Go error text",
			"paths":              "temp vault and certificate directories are {vault} and {certs}",
			"x_enroll_timestamp": "<rfc3339-utc-seconds>: validated within +-30s of the server clock, never frozen",
			"x_enroll_proof":     "<hmac-sha256-hex>: validated as HMAC-SHA256(secret, timestamp) with the secret named by proof_secret",
		},
		Scope: map[string]string{
			"cli_outcomes":    "stdout/stderr/exit are the real Go CLI's rendering of the canonical recorded responses (second Go run against a stub), not a textual substitution of the first run",
			"transport":       "User-Agent, Accept, Accept-Encoding, Content-Length and Connection are HTTP-library artefacts; Rust is held to the contract headers (Host, X-Enroll-Timestamp, X-Enroll-Proof), a forbidden-header list, method and path",
			"tls_text":        "Go/Rust TLS handshake and certificate-verification error text is a library message; those cases compare the CLI's own prefix only",
			"clock":           "the Go CLI reads the wall clock; no clock injection exists in Go, so the timestamp is checked against the +-30s proof window instead of frozen",
			"server_side":     "the Rust listener/queue are covered by crates/symvault-mcp tests; this fixture freezes the client side of the local approval wire contract",
			"not_covered":     "stale-timestamp rejection and non-loopback peers (the handler rejects them but the CLI cannot be made to send them without clock/peer injection) remain covered by internal/approval unit tests and crates/symvault-mcp",
			"cert_expiry":     "the fixture certificates are valid until 2126; the generator verifies this and fails closed",
			"windows_replay":  "the replay uses only std sockets and rustls and is OS independent; recorded Go outcomes were captured on one OS and contain no path separators or OS-specific text",
			"queue_semantics": "Pending() ordering is newest-first by CreatedAt; ids are random so ordering is frozen only through the canonical timestamps' recorded order",
		},
		Cases: records,
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

func digestCerts(dir string) ([]sourceFile, error) {
	var out []sourceFile
	for _, name := range certFiles {
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- fixed fixture names.
		if err != nil {
			return nil, fmt.Errorf("read fixture certificate %s (run --init-certs once): %w", name, err)
		}
		sum := sha256.Sum256(data)
		out = append(out, sourceFile{Path: certsRel + "/" + name, SHA256: hex.EncodeToString(sum[:])})
		if strings.HasSuffix(name, ".pem") {
			block, _ := pem.Decode(data)
			if block == nil {
				return nil, fmt.Errorf("%s is not PEM", name)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			if cert.NotAfter.Before(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)) {
				return nil, fmt.Errorf("%s expires %s; fixture certificates must outlive the port", name, cert.NotAfter)
			}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- live queue

type liveQueue struct {
	queue *approval.Queue
	ids   map[string]string // placeholder name -> real id
}

func newLiveQueue() (*liveQueue, error) {
	l := &liveQueue{queue: approval.NewQueue(), ids: map[string]string{}}
	for _, item := range []struct {
		key string
		req approval.Request
	}{
		{"approve_id", approval.Request{AgentName: "agent-e2e", Path: "notes/approve.md", Write: true, Reason: "approve fixture"}},
		{"deny_id", approval.Request{AgentName: "agent-e2e", Path: "notes/deny.md", Reason: "deny fixture"}},
		{"quiet_id", approval.Request{AgentName: "agent-e2e", Path: "notes/quiet.md", Reason: "quiet fixture"}},
	} {
		id, err := l.queue.Enqueue(item.req)
		if err != nil {
			return nil, err
		}
		l.ids[item.key] = id
		// Distinct CreatedAt values pin the newest-first listing order.
		time.Sleep(5 * time.Millisecond)
	}
	l.ids["unknown_id"] = knownIDs["unknown_raw"]
	return l, nil
}

func (l *liveQueue) pre(name string) error {
	switch name {
	case "":
		return nil
	case "enqueue_expiring":
		id, err := l.queue.Enqueue(approval.Request{
			AgentName: "agent-e2e", Path: "notes/expired.md", Reason: "expired fixture",
			ExpiresAt: time.Now().Add(150 * time.Millisecond),
		})
		if err != nil {
			return err
		}
		l.ids["expired_id"] = id
		time.Sleep(500 * time.Millisecond)
		return nil
	case "enqueue_tls":
		id, err := l.queue.Enqueue(approval.Request{AgentName: "agent-e2e", Path: "notes/tls.md", Write: true, Reason: "tls fixture"})
		if err != nil {
			return err
		}
		l.ids["tls_id"] = id
		return nil
	}
	return fmt.Errorf("unknown pre-action %q", name)
}

// ---------------------------------------------------------------- recording server

type seenRequest struct {
	method, path, rawQuery, host string
	header                       http.Header
	bodyBytes                    int
	clientCN                     string
	status                       int
	contentType, body            string
	at                           time.Time
}

type statusWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.body.Write(p)
	return w.ResponseWriter.Write(p)
}

type tlsServer struct {
	listener net.Listener
	server   *http.Server
	port     int
	mu       sync.Mutex
	seen     []seenRequest
}

// startServer serves handler (or, when nil, the recording wrapper around the
// production handler) over TLS with the fixture server certificate.
func startServer(certs, mode string, handler http.Handler) (*tlsServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tcp, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("unexpected listener address")
	}
	s := &tlsServer{listener: listener, port: tcp.Port}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if mode == "mtls" {
		pemBytes, readErr := os.ReadFile(filepath.Join(certs, "client-ca.pem")) // #nosec G304 -- fixture path.
		if readErr != nil {
			return nil, readErr
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("parse client CA")
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = pool
	}
	s.server = &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 2 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() {
		_ = s.server.ServeTLS(listener, filepath.Join(certs, "server.pem"), filepath.Join(certs, "server.key"))
	}()
	return s, nil
}

func (s *tlsServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.server.Shutdown(ctx)
}

func (s *tlsServer) record(r *http.Request, w *statusWriter) {
	cn := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cn = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	n, _ := io.Copy(io.Discard, r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, seenRequest{
		method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery, host: r.Host,
		header: r.Header.Clone(), bodyBytes: int(n), clientCN: cn,
		status: w.status, contentType: w.Header().Get("Content-Type"), body: w.body.String(), at: time.Now(),
	})
}

func (s *tlsServer) requests() []seenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seenRequest(nil), s.seen...)
}

// ---------------------------------------------------------------- case runner

type runEnv struct {
	root, tmp, certs, binary string
}

type cliResult struct {
	exit           int
	stdout, stderr string
}

func (e *runEnv) runCase(spec caseSpec, live *liveQueue) (caseRecord, error) {
	if err := live.pre(spec.pre); err != nil {
		return caseRecord{}, err
	}
	secret := validSecret
	if spec.secret == "wrong" {
		secret = wrongSecret
	}

	// Phase A: the real Go handler, recorded.
	handler := approval.NewLocalHTTPHandler(live.queue, validSecret, func(host string) bool { return host == "127.0.0.1" })
	var server *tlsServer
	recording := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		handler.ServeHTTP(sw, r)
		server.record(r, sw)
	})
	server, err := startServer(e.certs, spec.serverTLS, recording)
	if err != nil {
		return caseRecord{}, err
	}
	args := substitute(spec.args, live.ids)
	live1, err := e.runGoCLI(spec, secret, server.port, args)
	server.close()
	if err != nil {
		return caseRecord{}, err
	}
	raw := server.requests()

	// Canonicalise the recorded exchanges.
	idMap := map[string]string{}
	for key, real := range live.ids {
		idMap[real] = knownIDs[key]
	}
	var exchanges []exchange
	for _, seen := range raw {
		ex, convErr := canonicalExchange(seen, idMap, secret, spec.secret)
		if convErr != nil {
			return caseRecord{}, convErr
		}
		exchanges = append(exchanges, ex)
	}

	// Phase B: the Go CLI against a stub serving exactly the canonical bytes.
	canonArgs := substitute(spec.args, knownIDs)
	stub := &stubHandler{secret: validSecret, exchanges: exchanges}
	stubServer, err := startServer(e.certs, spec.serverTLS, stub)
	if err != nil {
		return caseRecord{}, err
	}
	live2, err := e.runGoCLI(spec, secret, stubServer.port, canonArgs)
	stubServer.close()
	if err != nil {
		return caseRecord{}, err
	}
	if stub.err != nil {
		return caseRecord{}, fmt.Errorf("canonical stub rejected the Go CLI request: %w", stub.err)
	}
	if stub.served != len(exchanges) {
		return caseRecord{}, fmt.Errorf("stub served %d of %d recorded exchanges", stub.served, len(exchanges))
	}
	if live1.exit != live2.exit {
		return caseRecord{}, fmt.Errorf("exit differs between live handler (%d) and canonical stub (%d)", live1.exit, live2.exit)
	}

	out := outcome{
		ExitCode: live2.exit, Stdout: live2.stdout, Stderr: live2.stderr, StderrCompare: "exact",
	}
	if spec.stderrKey != "" {
		if !strings.Contains(live2.stderr, spec.stderrKey) {
			return caseRecord{}, fmt.Errorf("stderr %q lacks expected prefix key %q", live2.stderr, spec.stderrKey)
		}
		out.StderrCompare = "prefix"
		out.StderrPrefix = live2.stderr[:strings.Index(live2.stderr, spec.stderrKey)+len(spec.stderrKey)]
	}
	return caseRecord{
		ID: spec.id, Args: canonArgs, Secret: spec.secret, Runtime: spec.runtime, ServerTLS: spec.serverTLS,
		Exchanges: nonNil(exchanges), Outcome: out,
	}, nil
}

func nonNil(e []exchange) []exchange {
	if e == nil {
		return []exchange{}
	}
	return e
}

func substitute(args []string, ids map[string]string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		for key, value := range ids {
			arg = strings.ReplaceAll(arg, "{"+key+"}", value)
		}
		out[i] = arg
	}
	return out
}

func (e *runEnv) runGoCLI(spec caseSpec, secret []byte, port int, args []string) (cliResult, error) {
	vault, err := os.MkdirTemp(e.tmp, "vault-*")
	if err != nil {
		return cliResult{}, err
	}
	home, err := os.MkdirTemp(e.tmp, "home-*")
	if err != nil {
		return cliResult{}, err
	}
	files := map[string][]byte{
		"identity.age":             []byte("test-only initialization marker"),
		"config.yaml":              []byte("{}\n"),
		"mcp-server.enroll-secret": secret,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(vault, name), data, 0o600); err != nil {
			return cliResult{}, err
		}
	}
	switch spec.runtime.Port {
	case "listener":
		err = os.WriteFile(filepath.Join(vault, ".runtime-port"), []byte(fmt.Sprintf(`{"port":%d,"bind":"127.0.0.1"}`, port)), 0o600)
	case "non_loopback_bind":
		err = os.WriteFile(filepath.Join(vault, ".runtime-port"), []byte(fmt.Sprintf(`{"port":%d,"bind":"0.0.0.0"}`, port)), 0o600)
	case "absent":
	default:
		err = fmt.Errorf("unknown runtime port mode %q", spec.runtime.Port)
	}
	if err != nil {
		return cliResult{}, err
	}
	record, err := runtimeTLSRecord(spec.runtime.TLS, e.certs)
	if err != nil {
		return cliResult{}, err
	}
	if err := os.WriteFile(filepath.Join(vault, ".runtime-tls-cert"), record, 0o600); err != nil {
		return cliResult{}, err
	}

	cmd := exec.Command(e.binary, append([]string{"--vault", vault}, args...)...) // #nosec G204 -- generator-built oracle binary.
	cmd.Env = []string{
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_DATA_HOME=" + filepath.Join(home, "data"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
		"CI=1",
		"PATH=" + os.Getenv("PATH"),
		"TMPDIR=" + e.tmp,
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	exit := 0
	if runErr := cmd.Run(); runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return cliResult{}, runErr
		}
		exit = exitErr.ExitCode()
	}
	norm := func(s string) string {
		s = strings.ReplaceAll(s, vault, "{vault}")
		s = strings.ReplaceAll(s, e.certs, "{certs}")
		s = strings.ReplaceAll(s, ":"+strconv.Itoa(port), ":{port}")
		return s
	}
	return cliResult{exit: exit, stdout: norm(stdout.String()), stderr: norm(stderr.String())}, nil
}

func runtimeTLSRecord(kind, certs string) ([]byte, error) {
	p := func(name string) string { return filepath.Join(certs, name) }
	type record struct {
		Certificate        string `json:"certificate"`
		ClientAuthRequired bool   `json:"client_auth_required,omitempty"`
		ClientCAFile       string `json:"client_ca_file,omitempty"`
		ClientCertificate  string `json:"client_certificate,omitempty"`
		ClientKey          string `json:"client_key,omitempty"`
	}
	var r record
	switch kind {
	case "mtls_full":
		r = record{p("server.pem"), true, p("client-ca.pem"), p("client.pem"), p("client.key")}
	case "mtls_missing_identity":
		r = record{Certificate: p("server.pem"), ClientAuthRequired: true}
	case "mtls_reused_server_identity":
		r = record{p("server.pem"), true, p("client-ca.pem"), p("server.pem"), p("server.key")}
	case "mtls_wrong_ca":
		r = record{p("server.pem"), true, p("server.pem"), p("client.pem"), p("client.key")}
	case "mtls_wrong_key":
		r = record{p("server.pem"), true, p("client-ca.pem"), p("client.pem"), p("server.key")}
	case "tls_only":
		r = record{Certificate: p("server.pem")}
	case "tls_unrelated_server":
		r = record{Certificate: p("other-server.pem")}
	default:
		return nil, fmt.Errorf("unknown runtime TLS kind %q", kind)
	}
	return json.Marshal(r)
}

// ---------------------------------------------------------------- canonicalisation

var (
	rfc3339Seconds = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	hexProof       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	timeFields     = regexp.MustCompile(`"(created_at|expires_at|decided_at)":"([^"]*)"`)
)

func canonicalExchange(seen seenRequest, idMap map[string]string, usedSecret []byte, secretName string) (exchange, error) {
	if seen.rawQuery != "" || seen.bodyBytes != 0 {
		return exchange{}, fmt.Errorf("unexpected query/body on %s %s", seen.method, seen.path)
	}
	headers := map[string]string{"Host": "127.0.0.1:{port}"}
	if !strings.HasPrefix(seen.host, "127.0.0.1:") {
		return exchange{}, fmt.Errorf("unexpected Host %q", seen.host)
	}
	for name, values := range seen.header {
		if len(values) != 1 {
			return exchange{}, fmt.Errorf("header %s repeated", name)
		}
		headers[name] = values[0]
	}
	timestamp := headers[approval.HeaderEnrollTimestamp]
	proof := headers[approval.HeaderEnrollProof]
	if !rfc3339Seconds.MatchString(timestamp) {
		return exchange{}, fmt.Errorf("timestamp %q is not RFC3339 UTC seconds", timestamp)
	}
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return exchange{}, err
	}
	if diff := seen.at.Sub(parsed); diff > proofWindow || diff < -proofWindow {
		return exchange{}, fmt.Errorf("timestamp %q outside the proof window", timestamp)
	}
	if !hexProof.MatchString(proof) {
		return exchange{}, fmt.Errorf("proof %q is not lowercase hex SHA-256", proof)
	}
	if approval.EnrollProof(usedSecret, parsed) != proof {
		return exchange{}, fmt.Errorf("proof does not equal HMAC(%s secret, timestamp)", secretName)
	}
	headers[approval.HeaderEnrollTimestamp] = "<rfc3339-utc-seconds>"
	headers[approval.HeaderEnrollProof] = "<hmac-sha256-hex>"
	if _, ok := headers["Authorization"]; ok {
		return exchange{}, errors.New("local approval CLI must not send Authorization")
	}
	path := seen.path
	for real, canonical := range idMap {
		path = strings.ReplaceAll(path, real, canonical)
	}
	body := seen.body
	for real, canonical := range idMap {
		body = strings.ReplaceAll(body, real, canonical)
	}
	body = timeFields.ReplaceAllStringFunc(body, func(match string) string {
		groups := timeFields.FindStringSubmatch(match)
		if groups[2] == zeroTime {
			return match
		}
		switch groups[1] {
		case "created_at":
			return `"created_at":"` + canonicalCreated + `"`
		case "expires_at":
			return `"expires_at":"` + canonicalExpires + `"`
		default:
			return `"decided_at":"` + canonicalDecided + `"`
		}
	})
	return exchange{
		Request: requestRecord{
			Method: seen.method, Path: path, Headers: headers, ProofSecret: secretName,
			ClientCertificateCN: seen.clientCN, BodyBytes: seen.bodyBytes,
		},
		Response: responseRecord{Status: seen.status, ContentType: seen.contentType, Body: body},
	}, nil
}

// stubHandler serves the canonical recorded responses to the Go CLI and checks
// the request it sends is the recorded one (modulo the placeholder fields).
type stubHandler struct {
	secret    []byte
	exchanges []exchange
	mu        sync.Mutex
	served    int
	err       error
}

func (s *stubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fail := func(format string, args ...any) {
		if s.err == nil {
			s.err = fmt.Errorf(format, args...)
		}
		http.Error(w, "stub mismatch", 599)
	}
	if s.served >= len(s.exchanges) {
		fail("unexpected extra request %s %s", r.Method, r.URL.Path)
		return
	}
	want := s.exchanges[s.served]
	if r.Method != want.Request.Method || r.URL.Path != want.Request.Path {
		fail("request %s %s, recorded %s %s", r.Method, r.URL.Path, want.Request.Method, want.Request.Path)
		return
	}
	ts, err := time.Parse(time.RFC3339, r.Header.Get(approval.HeaderEnrollTimestamp))
	if err != nil {
		fail("timestamp: %v", err)
		return
	}
	secret := validSecret
	if want.Request.ProofSecret == "wrong" {
		secret = wrongSecret
	}
	if approval.EnrollProof(secret, ts) != r.Header.Get(approval.HeaderEnrollProof) {
		fail("proof does not match recorded secret class %s", want.Request.ProofSecret)
		return
	}
	s.served++
	w.Header().Set("Content-Type", want.Response.ContentType)
	w.WriteHeader(want.Response.Status)
	_, _ = io.WriteString(w, want.Response.Body)
}

// ---------------------------------------------------------------- certificates

// writeCerts creates the long-lived fixture identities once. They are
// committed; the generator and the Rust replay both load them, so a Go run is
// never needed to obtain TLS material.
func writeCerts(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
		must(err)
		return n
	}
	writeKey := func(name string, key *ecdsa.PrivateKey) {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		must(err)
		must(os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	}
	writeCert := func(name string, der []byte) {
		must(os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)) // #nosec G306 -- public test certificate.
	}
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		return key
	}
	// Self-signed leaf servers, shaped like serverbootstrap.generateSelfSignedCert.
	for _, name := range []string{"server", "other-server"} {
		key := newKey()
		template := &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{CommonName: "symaira-vault-mcp " + name, Organization: []string{"Symaira Vault approval fixture"}},
			NotBefore:    notBefore, NotAfter: notAfter,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{"localhost"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		must(err)
		writeCert(name+".pem", der)
		writeKey(name+".key", key)
	}
	caKey := newKey()
	caTemplate := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "approval test CA"},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	must(err)
	writeCert("client-ca.pem", caDER)
	clientKey := newKey()
	clientTemplate := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "dedicated approval client"},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	must(err)
	writeCert("client.pem", clientDER)
	writeKey("client.key", clientKey)
	return nil
}
