// Command approvaltlsgen freezes the APPROVAL-001 mTLS listener settings
// validation contract from the production Go `symvault mcp` command.
//
// The local approval CLI is only usable when the HTTP server it talks to
// started, and the server refuses to start on unsafe or broken mTLS settings.
// This generator initialises a throw-away vault with the real Go CLI, writes
// each `MCP.*` TLS configuration of interest, runs `symvault mcp --port 0` and
// records the exit code, stdout and the `Error:` lines of the real Go binary.
//
// What is recorded and compared: the failure itself (exit code, empty stdout,
// the final `Error:` lines). What is deliberately not: the diagnostics Go
// prints before it reaches the failing check (`MCP server listening on ...`
// and the legacy-token migration warning with a random token id), because Go
// binds the listener and migrates the token registry before validating the
// client CA and key pair while the Rust server validates first and has no side
// effects to report; that ordering difference is declared in the fixture scope.
//
// The Rust test (crates/symvault-cli/tests/approval_e2e.rs) replays the same
// configurations against the real Rust `symvault mcp` process.
//
// Modes:
//
//	approvaltlsgen          regenerate testdata/port/approval/mtls_settings.json
//	approvaltlsgen --check  regenerate in memory and require byte equality
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// oracleCommit is the revision whose sources this fixture freezes. Every file
// in oracleSources must be byte-identical to its blob at this commit.
const oracleCommit = "8d2e5e156cd95f04e608182ab8179fdd49f1884a"

var oracleSources = []string{
	"cmd/mcp/serve.go",
	"cmd/mcp/serve_deps.go",
	"internal/mcp/serverbootstrap/http.go",
	"internal/mcp/serverbootstrap/tls.go",
}

var generatorFiles = []string{"scripts/rust-port/cmd/approvaltlsgen/main.go"}

const (
	fixtureRel = "testdata/port/approval/mtls_settings.json"
	certsRel   = "testdata/port/approval/certs"
	garbageRel = "garbage.pem" // inside the vault directory
	passphrase = "approvaltlsgen-fixture-passphrase"
)

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

type setting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type caseRecord struct {
	ID         string    `json:"id"`
	Note       string    `json:"note"`
	MCP        []setting `json:"mcp"`
	Stdin      string    `json:"stdin"`
	ExitCode   int       `json:"exit_code"`
	Stdout     string    `json:"stdout"`
	ErrorLines []string  `json:"error_lines"`
}

type fixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        oracleMeta        `json:"oracle"`
	Canonical     map[string]string `json:"canonical"`
	Scope         map[string]string `json:"scope"`
	Cases         []caseRecord      `json:"cases"`
}

type caseSpec struct {
	id, note string
	mcp      []setting
	stdin    string
}

// cases lists every mTLS listener setting combination that must fail closed.
// Values may use {certs} (fixture certificate directory) and {vault} (the
// throw-away vault, holding garbage.pem).
func cases() []caseSpec {
	cert := setting{"tls_cert_file", "{certs}/server.pem"}
	key := setting{"tls_key_file", "{certs}/server.key"}
	ca := setting{"tls_client_ca_file", "{certs}/client-ca.pem"}
	mtls := setting{"mtls_enabled", "true"}
	garbage := "{vault}/" + garbageRel
	return []caseSpec{
		{id: "missing_client_ca_setting", note: "mTLS enabled, no client CA configured",
			mcp: []setting{mtls, cert, key}},
		{id: "insecure_bind_with_mtls", note: "allow_insecure_bind and mtls_enabled together (the cleartext prompt is answered y)",
			mcp: []setting{mtls, {"allow_insecure_bind", "true"}, cert, key, ca}, stdin: "y\n"},
		{id: "client_ca_file_missing", note: "client CA path does not exist",
			mcp: []setting{mtls, cert, key, {"tls_client_ca_file", "/nonexistent/client-ca.pem"}}},
		{id: "client_ca_file_not_pem", note: "client CA file holds no PEM certificate",
			mcp: []setting{mtls, cert, key, {"tls_client_ca_file", garbage}}},
		{id: "server_key_file_missing", note: "server key path does not exist",
			mcp: []setting{mtls, cert, {"tls_key_file", "/nonexistent/server.key"}, ca}},
		{id: "server_key_file_not_pem", note: "server key file holds no PEM key",
			mcp: []setting{mtls, cert, {"tls_key_file", garbage}, ca}},
		{id: "server_certificate_file_missing", note: "server certificate path does not exist",
			mcp: []setting{mtls, {"tls_cert_file", "/nonexistent/server.pem"}, key, ca}},
		{id: "server_certificate_not_pem", note: "server certificate file holds no PEM certificate",
			mcp: []setting{mtls, {"tls_cert_file", garbage}, key, ca}},
		{id: "server_key_does_not_match_certificate", note: "key pair belongs to a different server identity",
			mcp: []setting{mtls, cert, {"tls_key_file", "{certs}/other-server.key"}, ca}},
		{id: "client_ca_is_checked_before_server_key", note: "both the client CA and the server key are unreadable: Go reports the client CA",
			mcp: []setting{mtls, cert, {"tls_key_file", "/nonexistent/server.key"}, {"tls_client_ca_file", "/nonexistent/client-ca.pem"}}},
	}
}

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
			log.Fatalf("approvaltlsgen: %s differs from regenerated oracle output\n%s", path, firstDifference(committed, data))
		}
		fmt.Printf("approvaltlsgen: %s reproduced byte-for-byte (%d bytes)\n", path, len(data))
		return
	}
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, data, 0o644)) // #nosec G306 -- public test fixture.
	fmt.Printf("approvaltlsgen: wrote %s (%d bytes)\n", path, len(data))
}

func must(err error) {
	if err != nil {
		log.Fatalf("approvaltlsgen: %v", err)
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

func generate(root string) ([]byte, error) {
	oracle, err := pinOracle(root)
	if err != nil {
		return nil, err
	}
	certs := filepath.Join(root, filepath.FromSlash(certsRel))
	tmp, err := os.MkdirTemp("", "approvaltlsgen-*")
	if err != nil {
		return nil, err
	}
	tmp, err = filepath.EvalSymlinks(tmp)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	binary := filepath.Join(tmp, "symvault-oracle")
	build := exec.Command("go", "build", "-trimpath", "-o", binary, ".") // #nosec G204 -- fixed arguments.
	build.Dir = root
	if out, buildErr := build.CombinedOutput(); buildErr != nil {
		return nil, fmt.Errorf("build Go CLI oracle: %w\n%s", buildErr, out)
	}

	var records []caseRecord
	for _, spec := range cases() {
		record, runErr := runCase(binary, tmp, certs, spec)
		if runErr != nil {
			return nil, fmt.Errorf("case %s: %w", spec.id, runErr)
		}
		records = append(records, record)
	}

	f := fixture{
		SchemaVersion: 1,
		Oracle:        oracle,
		Canonical: map[string]string{
			"paths":    "the fixture certificate directory is {certs}, the throw-away vault directory is {vault}",
			"garbage":  "{vault}/" + garbageRel + " contains the single line `not a pem`",
			"commands": "init --auth passphrase, an appended `mcp:` section in config.yaml, then `mcp --port 0`",
		},
		Scope: map[string]string{
			"compared":     "exit code, stdout (empty) and every line of stderr that starts with `Error: `",
			"not_compared": "stderr lines before the failing check: `MCP server listening on ...` and the legacy-token migration warning (random token id), the cleartext prompt",
			"ordering":     "Go binds the listener and migrates the token registry before it validates the client CA and key pair; the Rust server validates first and so prints none of those lines and leaves no token registry behind",
			"plain_tls":    "non-mTLS certificate/key failures surface Go crypto/tls library text (open ...: no such file or directory, tls: failed to find any PEM data) and are not frozen here",
			"windows":      "recorded texts are the Unix errno texts; the Rust replay is unix-only",
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

func runCase(binary, tmp, certs string, spec caseSpec) (caseRecord, error) {
	vault, err := os.MkdirTemp(tmp, "vault-*")
	if err != nil {
		return caseRecord{}, err
	}
	home, err := os.MkdirTemp(tmp, "home-*")
	if err != nil {
		return caseRecord{}, err
	}
	env := []string{
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"XDG_DATA_HOME=" + filepath.Join(home, "data"),
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
		"SYMVAULT_TEST_KEYRING=memory",
		"SYMVAULT_PASSPHRASE=" + passphrase,
		"SYMVAULT_ALLOW_ENV_PASSPHRASE=1",
		"SYMVAULT_NO_ENV_WARNING=1",
		"CI=1",
		"PATH=" + os.Getenv("PATH"),
		"TMPDIR=" + tmp,
	}
	run := func(timeout time.Duration, stdin string, args ...string) (int, string, string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, append([]string{"--vault", vault}, args...)...) // #nosec G204 -- generator-built oracle binary.
		cmd.Env = env
		cmd.Dir = tmp
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		runErr := cmd.Run()
		if ctx.Err() != nil {
			return 0, "", "", fmt.Errorf("`%s` did not exit within %s: the settings did not fail closed", strings.Join(args, " "), timeout)
		}
		code := 0
		if runErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) {
				return 0, "", "", runErr
			}
			code = exitErr.ExitCode()
		}
		return code, stdout.String(), stderr.String(), nil
	}

	if code, _, stderr, err := run(60*time.Second, "", "init", "--auth", "passphrase"); err != nil || code != 0 {
		return caseRecord{}, fmt.Errorf("init oracle vault: exit %d err %v\n%s", code, err, stderr)
	}
	if err := os.WriteFile(filepath.Join(vault, garbageRel), []byte("not a pem\n"), 0o600); err != nil {
		return caseRecord{}, err
	}
	subst := func(s string) string {
		s = strings.ReplaceAll(s, "{certs}", certs)
		return strings.ReplaceAll(s, "{vault}", vault)
	}
	var section strings.Builder
	section.WriteString("mcp:\n")
	for _, kv := range spec.mcp {
		section.WriteString("  " + kv.Key + ": " + subst(kv.Value) + "\n")
	}
	config, err := os.OpenFile(filepath.Join(vault, "config.yaml"), os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- generator vault.
	if err != nil {
		return caseRecord{}, err
	}
	if _, err := config.WriteString(section.String()); err != nil {
		_ = config.Close()
		return caseRecord{}, err
	}
	if err := config.Close(); err != nil {
		return caseRecord{}, err
	}

	code, stdout, stderr, err := run(30*time.Second, spec.stdin, "mcp", "--port", "0")
	if err != nil {
		return caseRecord{}, err
	}
	norm := func(s string) string {
		s = strings.ReplaceAll(s, vault, "{vault}")
		return strings.ReplaceAll(s, certs, "{certs}")
	}
	var errorLines []string
	for _, line := range strings.SplitAfter(norm(stderr), "\n") {
		if idx := strings.Index(line, "Error: "); idx >= 0 {
			errorLines = append(errorLines, line[idx:])
		}
	}
	if code == 0 || len(errorLines) == 0 {
		return caseRecord{}, fmt.Errorf("exit %d, no Error: line; settings did not fail closed\n%s", code, stderr)
	}
	return caseRecord{
		ID: spec.id, Note: spec.note, MCP: spec.mcp, Stdin: spec.stdin,
		ExitCode: code, Stdout: norm(stdout), ErrorLines: errorLines,
	}, nil
}
