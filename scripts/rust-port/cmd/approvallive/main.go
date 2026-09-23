// Command approvallive exercises the Rust approval CLI against the Go
// production local approval handler over an ephemeral loopback TLS server.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	"github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
)

const maxResponseBytes = 1 << 20

type listOutput struct {
	Requests []approval.Entry `json:"requests"`
}

type outcomeOutput struct {
	Outcome approval.Outcome `json:"outcome"`
}

func main() {
	binary := flag.String("rust-binary", "", "path to the already-built Rust symvault CLI")
	flag.Parse()
	if *binary == "" {
		fatal(errors.New("--rust-binary is required"))
	}
	if err := run(*binary); err != nil {
		fatal(err)
	}
	fmt.Println("PASS live Go/Rust approval list and decide differential")
}

//nolint:gocyclo // This is one linear live acceptance scenario.
func run(binary string) (runErr error) {
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return fmt.Errorf("resolve Rust binary: %w", err)
	}
	if info, statErr := os.Stat(absoluteBinary); statErr != nil || info.IsDir() {
		if statErr == nil {
			statErr = errors.New("path is a directory")
		}
		return fmt.Errorf("rust binary %q is unavailable: %w", absoluteBinary, statErr)
	}

	vault, err := os.MkdirTemp("", "symvault-approval-live-")
	if err != nil {
		return fmt.Errorf("create disposable vault: %w", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(vault); cleanupErr != nil && runErr == nil {
			runErr = fmt.Errorf("remove disposable vault: %w", cleanupErr)
		}
	}()
	if writeErr := os.WriteFile(filepath.Join(vault, "identity.age"), []byte("integration marker\n"), 0o600); writeErr != nil {
		return fmt.Errorf("write initialized vault marker: %w", writeErr)
	}
	if writeErr := os.WriteFile(filepath.Join(vault, "config.yaml"), []byte("{}\n"), 0o600); writeErr != nil {
		return fmt.Errorf("write initialized vault config: %w", writeErr)
	}

	queue := approval.NewQueue()
	secret, err := serverbootstrap.EnsureEnrollSecret(vault)
	if err != nil {
		return fmt.Errorf("create vault proof secret: %w", err)
	}
	handler := approval.NewLocalHTTPHandler(queue, secret, func(host string) bool {
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	})
	certPath, keyPath, err := serverbootstrap.EnsureTLSCert(vault)
	if err != nil {
		return fmt.Errorf("create loopback server certificate: %w", err)
	}
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load loopback server certificate: %w", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	port, err := serverPort(server)
	if err != nil {
		return err
	}
	if saveErr := cli.SaveRuntimePort(vault, "127.0.0.1", port); saveErr != nil {
		return fmt.Errorf("write runtime port record: %w", saveErr)
	}
	if saveErr := cli.SaveRuntimeTLSConfig(vault, certPath, "", "", "", false); saveErr != nil {
		return fmt.Errorf("write runtime TLS record: %w", saveErr)
	}

	goApproveID, err := enqueue(queue, "go-approve")
	if err != nil {
		return err
	}
	rustApproveID, err := enqueue(queue, "rust-approve")
	if err != nil {
		return err
	}
	goDenyID, err := enqueue(queue, "go-deny")
	if err != nil {
		return err
	}
	rustDenyID, err := enqueue(queue, "rust-deny")
	if err != nil {
		return err
	}

	goListBody, status, err := goRequest(server, secret, http.MethodGet, approval.PathLocalApprovals)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("go list returned HTTP %d: %s", status, strings.TrimSpace(string(goListBody)))
	}
	var goList listOutput
	if decodeErr := json.Unmarshal(goListBody, &goList); decodeErr != nil {
		return fmt.Errorf("decode go list result: %w", decodeErr)
	}
	rustList, err := runRust[listOutput](absoluteBinary, vault, "--output", "json", "approval", "list")
	if err != nil {
		return fmt.Errorf("rust approval list: %w", err)
	}
	if !sameList(goList, rustList) {
		return fmt.Errorf("approval list differs: Go=%s Rust=%+v", bytes.TrimSpace(goListBody), rustList)
	}

	goApprove, err := goDecision(server, secret, goApproveID, "approve")
	if err != nil {
		return fmt.Errorf("go approve: %w", err)
	}
	rustApprove, err := runRust[outcomeOutput](absoluteBinary, vault, "--output", "json", "approval", "decide", rustApproveID, "--approve")
	if err != nil {
		return fmt.Errorf("rust approve: %w", err)
	}
	if !sameOutcome(goApproveID, goApprove, rustApproveID, rustApprove.Outcome) {
		return fmt.Errorf("approve result differs: Go=%+v Rust=%+v", goApprove, rustApprove)
	}

	goDeny, err := goDecision(server, secret, goDenyID, "deny")
	if err != nil {
		return fmt.Errorf("go deny: %w", err)
	}
	rustDeny, err := runRust[outcomeOutput](absoluteBinary, vault, "--output", "json", "approval", "decide", rustDenyID, "--deny")
	if err != nil {
		return fmt.Errorf("rust deny: %w", err)
	}
	if !sameOutcome(goDenyID, goDeny, rustDenyID, rustDeny.Outcome) {
		return fmt.Errorf("deny result differs: Go=%+v Rust=%+v", goDeny, rustDeny)
	}

	goConflictBody, goConflictStatus, err := goRequest(server, secret, http.MethodPost, approval.PathLocalApprovalAction+rustApproveID+"/approve")
	if err != nil {
		return err
	}
	if goConflictStatus != http.StatusConflict {
		return fmt.Errorf("go repeat decision returned HTTP %d, want 409", goConflictStatus)
	}
	conflictOutput, err := runRustRaw(absoluteBinary, vault, "--output", "json", "approval", "decide", rustApproveID, "--approve")
	if err != nil {
		return fmt.Errorf("rust repeat decision process: %w", err)
	}
	var goConflict struct {
		Error string `json:"error"`
	}
	if decodeErr := json.Unmarshal(goConflictBody, &goConflict); decodeErr != nil {
		return fmt.Errorf("decode go conflict body: %w", decodeErr)
	}
	wantConflict := "Error: approval server: " + goConflict.Error
	if conflictOutput.ExitCode != 1 || !strings.Contains(string(conflictOutput.Stderr), wantConflict) {
		return fmt.Errorf("rust repeat decision mismatch: exit=%d stderr=%q, want go conflict %q", conflictOutput.ExitCode, conflictOutput.Stderr, wantConflict)
	}

	for id, want := range map[string]approval.Status{
		goApproveID:   approval.StatusApproved,
		rustApproveID: approval.StatusApproved,
		goDenyID:      approval.StatusDenied,
		rustDenyID:    approval.StatusDenied,
	} {
		entry, err := queue.Get(id)
		if err != nil {
			return fmt.Errorf("read queue state for %s: %w", id, err)
		}
		if entry.Status != want || entry.DecidedBy != "local-cli" {
			return fmt.Errorf("queue state for %s = %+v, want %s by local-cli", id, entry, want)
		}
	}
	return runMTLS(absoluteBinary, vault, queue, handler, certPath, serverCert)
}

func runMTLS(binary, vault string, queue *approval.Queue, handler http.Handler, certPath string, serverCert tls.Certificate) error {
	fixtureDir, err := filepath.Abs(filepath.Join("crates", "symvault-cli", "tests", "fixtures", "approval-mtls"))
	if err != nil {
		return fmt.Errorf("resolve synthetic mTLS fixtures: %w", err)
	}
	caPath := filepath.Join(fixtureDir, "client-ca.pem")
	clientCertPath := filepath.Join(fixtureDir, "approval-client.pem")
	clientKeyPath := filepath.Join(fixtureDir, "approval-client.key")
	caPEM, err := os.ReadFile(caPath) // #nosec G304 -- fixed repository test fixture path.
	if err != nil {
		return fmt.Errorf("read synthetic client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return errors.New("parse synthetic client CA")
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	port, err := serverPort(server)
	if err != nil {
		return err
	}
	if err := cli.SaveRuntimePort(vault, "127.0.0.1", port); err != nil {
		return fmt.Errorf("write mTLS runtime port: %w", err)
	}
	id, err := enqueue(queue, "rust-mtls-approve")
	if err != nil {
		return err
	}
	if err := cli.SaveRuntimeTLSConfig(vault, certPath, caPath, "", "", true); err != nil {
		return fmt.Errorf("write missing mTLS identity: %w", err)
	}
	missing, err := runRustRaw(binary, vault, "--output", "json", "approval", "list")
	if err != nil || missing.ExitCode != 1 || !bytes.Contains(missing.Stderr, []byte("dedicated local approval client certificate")) {
		return fmt.Errorf("missing approval identity was accepted: exit=%d err=%v stderr=%q", missing.ExitCode, err, missing.Stderr)
	}
	if err := cli.SaveRuntimeTLSConfig(vault, certPath, filepath.Join(fixtureDir, "rotated-client-ca.pem"), clientCertPath, clientKeyPath, true); err != nil {
		return fmt.Errorf("write rotated mTLS CA: %w", err)
	}
	rotated, err := runRustRaw(binary, vault, "--output", "json", "approval", "list")
	if err != nil || rotated.ExitCode != 1 || !bytes.Contains(rotated.Stderr, []byte("verify local approval client identity")) {
		return fmt.Errorf("rotated approval CA was accepted: exit=%d err=%v stderr=%q", rotated.ExitCode, err, rotated.Stderr)
	}
	if err := cli.SaveRuntimeTLSConfig(vault, certPath, caPath, clientCertPath, clientKeyPath, true); err != nil {
		return fmt.Errorf("write dedicated mTLS identity: %w", err)
	}
	list, err := runRust[listOutput](binary, vault, "--output", "json", "approval", "list")
	if err != nil {
		return fmt.Errorf("mTLS approval list: %w", err)
	}
	if len(list.Requests) != 1 || list.Requests[0].ID != id || list.Requests[0].Status != approval.StatusPending {
		return fmt.Errorf("mTLS approval list = %+v, want pending %s", list, id)
	}
	decision, err := runRust[outcomeOutput](binary, vault, "--output", "json", "approval", "decide", id, "--approve")
	if err != nil {
		return fmt.Errorf("mTLS approval decide: %w", err)
	}
	entry, err := queue.Get(id)
	if err != nil || entry.Status != approval.StatusApproved || entry.DecidedBy != "local-cli" || decision.Outcome.ID != id {
		return fmt.Errorf("mTLS approval queue = %+v, outcome = %+v, err = %v", entry, decision, err)
	}
	return nil
}

func enqueue(queue *approval.Queue, name string) (string, error) {
	id, err := queue.Enqueue(approval.Request{
		AgentName: name,
		Path:      "approvals/" + name,
		Write:     true,
		Reason:    "live Go/Rust differential",
	})
	if err != nil {
		return "", fmt.Errorf("enqueue %s request: %w", name, err)
	}
	return id, nil
}

func serverPort(server *httptest.Server) (int, error) {
	address, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected loopback listener address %T", server.Listener.Addr())
	}
	return address.Port, nil
}

func goRequest(server *httptest.Server, secret []byte, method, path string) ([]byte, int, error) {
	now := time.Now().UTC().Truncate(time.Second)
	request, err := http.NewRequest(method, server.URL+path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build Go local approval request: %w", err)
	}
	request.Header.Set(approval.HeaderEnrollTimestamp, now.Format(time.RFC3339))
	request.Header.Set(approval.HeaderEnrollProof, approval.EnrollProof(secret, now))
	client := *server.Client()
	client.Timeout = 10 * time.Second
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("send Go local approval request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, response.StatusCode, fmt.Errorf("read Go local approval response: %w", err)
	}
	return body, response.StatusCode, nil
}

func goDecision(server *httptest.Server, secret []byte, id, action string) (approval.Outcome, error) {
	body, status, err := goRequest(server, secret, http.MethodPost, approval.PathLocalApprovalAction+id+"/"+action)
	if err != nil {
		return approval.Outcome{}, err
	}
	if status != http.StatusOK {
		return approval.Outcome{}, fmt.Errorf("HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	var result outcomeOutput
	if err := json.Unmarshal(body, &result); err != nil {
		return approval.Outcome{}, fmt.Errorf("decode Go decision: %w", err)
	}
	return result.Outcome, nil
}

func runRust[T any](binary, vault string, args ...string) (T, error) {
	var result T
	output, err := runRustRaw(binary, vault, args...)
	if err != nil {
		return result, err
	}
	if output.ExitCode != 0 {
		return result, fmt.Errorf("exit %d: %s", output.ExitCode, strings.TrimSpace(string(output.Stderr)))
	}
	if err := json.Unmarshal(output.Stdout, &result); err != nil {
		return result, fmt.Errorf("decode stdout %q: %w", output.Stdout, err)
	}
	return result, nil
}

type processOutput struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

func runRustRaw(binary, vault string, args ...string) (processOutput, error) {
	commandArgs := make([]string, 0, 2+len(args))
	commandArgs = append(commandArgs, "--vault", vault)
	commandArgs = append(commandArgs, args...)
	// #nosec G204 -- The executable is the explicit --rust-binary test input, resolved and stat-checked in run.
	command := exec.Command(binary, commandArgs...)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	result := processOutput{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	return result, fmt.Errorf("launch Rust CLI: %w", err)
}

func sameList(goList, rustList listOutput) bool {
	if len(goList.Requests) != len(rustList.Requests) {
		return false
	}
	goByID := make(map[string]approval.Entry, len(goList.Requests))
	for _, entry := range goList.Requests {
		goByID[entry.ID] = entry
	}
	seen := make(map[string]bool, len(rustList.Requests))
	for _, entry := range rustList.Requests {
		if seen[entry.ID] {
			return false
		}
		seen[entry.ID] = true
		if expected, ok := goByID[entry.ID]; !ok || expected != entry {
			return false
		}
	}
	return true
}

func sameOutcome(goID string, goOutcome approval.Outcome, rustID string, rustOutcome approval.Outcome) bool {
	// The two operations use distinct queue entries and timestamps, so compare
	// each returned ID to its request and compare the shared outcome semantics.
	return goOutcome.ID == goID && rustOutcome.ID == rustID &&
		goOutcome.Status == rustOutcome.Status &&
		goOutcome.DecidedBy == rustOutcome.DecidedBy &&
		!goOutcome.DecidedAt.IsZero() && !rustOutcome.DecidedAt.IsZero()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "FAIL live approval differential:", err)
	os.Exit(1)
}
