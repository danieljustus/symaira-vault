// Command approvallive exercises the Rust approval CLI against the Go
// production local approval handler over an ephemeral loopback TLS server.
package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
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

func run(binary string) error {
	absoluteBinary, err := filepath.Abs(binary)
	if err != nil {
		return fmt.Errorf("resolve Rust binary: %w", err)
	}
	if info, err := os.Stat(absoluteBinary); err != nil || info.IsDir() {
		if err == nil {
			err = errors.New("path is a directory")
		}
		return fmt.Errorf("Rust binary %q is unavailable: %w", absoluteBinary, err)
	}

	vault, err := os.MkdirTemp("", "symvault-approval-live-")
	if err != nil {
		return fmt.Errorf("create disposable vault: %w", err)
	}
	defer os.RemoveAll(vault)
	if err := os.WriteFile(filepath.Join(vault, "identity.age"), []byte("integration marker\n"), 0o600); err != nil {
		return fmt.Errorf("write initialized vault marker: %w", err)
	}
	if err := os.WriteFile(filepath.Join(vault, "config.yaml"), []byte("{}\n"), 0o600); err != nil {
		return fmt.Errorf("write initialized vault config: %w", err)
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
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	certPath := filepath.Join(vault, "loopback-server.pem")
	if len(server.TLS.Certificates) != 1 || len(server.TLS.Certificates[0].Certificate) == 0 {
		return errors.New("Go TLS test server did not expose its certificate")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.TLS.Certificates[0].Certificate[0]})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("write loopback server certificate: %w", err)
	}
	port, err := serverPort(server)
	if err != nil {
		return err
	}
	if err := cli.SaveRuntimePort(vault, "127.0.0.1", port); err != nil {
		return fmt.Errorf("write runtime port record: %w", err)
	}
	if err := cli.SaveRuntimeTLSConfig(vault, certPath, "", "", "", false); err != nil {
		return fmt.Errorf("write runtime TLS record: %w", err)
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
		return fmt.Errorf("Go list returned HTTP %d: %s", status, strings.TrimSpace(string(goListBody)))
	}
	var goList listOutput
	if err := json.Unmarshal(goListBody, &goList); err != nil {
		return fmt.Errorf("decode Go list result: %w", err)
	}
	rustList, err := runRust[listOutput](absoluteBinary, vault, "--output", "json", "approval", "list")
	if err != nil {
		return fmt.Errorf("Rust approval list: %w", err)
	}
	if !sameList(goList, rustList) {
		return fmt.Errorf("approval list differs: Go=%s Rust=%+v", bytes.TrimSpace(goListBody), rustList)
	}

	goApprove, err := goDecision(server, secret, goApproveID, "approve")
	if err != nil {
		return fmt.Errorf("Go approve: %w", err)
	}
	rustApprove, err := runRust[outcomeOutput](absoluteBinary, vault, "--output", "json", "approval", "decide", rustApproveID, "--approve")
	if err != nil {
		return fmt.Errorf("Rust approve: %w", err)
	}
	if !sameOutcome(goApproveID, goApprove, rustApproveID, rustApprove.Outcome) {
		return fmt.Errorf("approve result differs: Go=%+v Rust=%+v", goApprove, rustApprove)
	}

	goDeny, err := goDecision(server, secret, goDenyID, "deny")
	if err != nil {
		return fmt.Errorf("Go deny: %w", err)
	}
	rustDeny, err := runRust[outcomeOutput](absoluteBinary, vault, "--output", "json", "approval", "decide", rustDenyID, "--deny")
	if err != nil {
		return fmt.Errorf("Rust deny: %w", err)
	}
	if !sameOutcome(goDenyID, goDeny, rustDenyID, rustDeny.Outcome) {
		return fmt.Errorf("deny result differs: Go=%+v Rust=%+v", goDeny, rustDeny)
	}

	goConflictBody, goConflictStatus, err := goRequest(server, secret, http.MethodPost, approval.PathLocalApprovalAction+rustApproveID+"/approve")
	if err != nil {
		return err
	}
	if goConflictStatus != http.StatusConflict {
		return fmt.Errorf("Go repeat decision returned HTTP %d, want 409", goConflictStatus)
	}
	conflictOutput, err := runRustRaw(absoluteBinary, vault, "--output", "json", "approval", "decide", rustApproveID, "--approve")
	if err != nil {
		return fmt.Errorf("Rust repeat decision process: %w", err)
	}
	var goConflict struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(goConflictBody, &goConflict); err != nil {
		return fmt.Errorf("decode Go conflict body: %w", err)
	}
	wantConflict := "Error: approval server: " + goConflict.Error
	if conflictOutput.ExitCode != 1 || !strings.Contains(string(conflictOutput.Stderr), wantConflict) {
		return fmt.Errorf("Rust repeat decision mismatch: exit=%d stderr=%q, want Go conflict %q", conflictOutput.ExitCode, conflictOutput.Stderr, wantConflict)
	}

	for id, want := range map[string]approval.Status{
		goApproveID:   approval.StatusApproved,
		rustApproveID: approval.StatusApproved,
		goDenyID:      approval.StatusDenied,
		rustDenyID:    approval.StatusDenied,
	} {
		entry, err := queue.Get(id)
		if err != nil || entry.Status != want || entry.DecidedBy != "local-cli" {
			return fmt.Errorf("queue state for %s = (%+v, %v), want %s by local-cli", id, entry, err, want)
		}
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
	defer response.Body.Close()
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
	commandArgs := []string{"--vault", vault}
	commandArgs = append(commandArgs, args...)
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
