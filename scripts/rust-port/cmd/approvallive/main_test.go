package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/approval"
)

func TestGoOracleAndComparisonGuards(t *testing.T) {
	queue := approval.NewQueue()
	secret := []byte("0123456789abcdef0123456789abcdef")
	handler := approval.NewLocalHTTPHandler(queue, secret, func(host string) bool {
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	if port, err := serverPort(server); err != nil || port <= 0 {
		t.Fatalf("loopback port = %d, %v", port, err)
	}
	id, err := enqueue(queue, "test")
	if err != nil {
		t.Fatal(err)
	}
	body, status, err := goRequest(server, secret, http.MethodGet, approval.PathLocalApprovals)
	if err != nil || status != http.StatusOK {
		t.Fatalf("Go list = HTTP %d, %v", status, err)
	}
	var listed listOutput
	if err := json.Unmarshal(body, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Requests) != 1 || listed.Requests[0].ID != id || !sameList(listed, listed) {
		t.Fatalf("Go list mismatch: %+v", listed)
	}
	if sameList(listed, listOutput{Requests: append(listed.Requests, listed.Requests[0])}) {
		t.Fatal("duplicate Rust queue entry accepted")
	}
	mutated := listed.Requests[0]
	mutated.Status = approval.StatusDenied
	if sameList(listed, listOutput{Requests: []approval.Entry{mutated}}) {
		t.Fatal("changed Rust queue status accepted")
	}
	decided, err := goDecision(server, secret, id, "approve")
	if err != nil || decided.Status != approval.StatusApproved {
		t.Fatalf("Go approval = %+v, %v", decided, err)
	}
	if !sameOutcome(id, decided, id, decided) || sameOutcome("wrong-id", decided, id, decided) {
		t.Fatal("approval outcome ID guard failed")
	}
	if _, err := goDecision(server, secret, id, "approve"); err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("repeat approval must be rejected with conflict: %v", err)
	}
}

func TestRustProcessResultGuards(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	fixture := func(name, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	valid := fixture("valid", "printf '{\"value\":1}'\n")
	got, err := runRust[map[string]int](valid, t.TempDir(), "approval", "list")
	if err != nil || got["value"] != 1 {
		t.Fatalf("valid Rust JSON response = %v, %v", got, err)
	}
	invalid := fixture("invalid", "printf 'not-json'\n")
	if _, err := runRust[map[string]int](invalid, t.TempDir()); err == nil || !strings.Contains(err.Error(), "decode stdout") {
		t.Fatalf("invalid Rust JSON accepted: %v", err)
	}
	failing := fixture("failing", "printf 'denied' >&2; exit 7\n")
	output, err := runRustRaw(failing, t.TempDir())
	if err != nil || output.ExitCode != 7 || string(output.Stderr) != "denied" {
		t.Fatalf("failed process = %+v, %v", output, err)
	}
	if _, err := runRust[map[string]int](failing, t.TempDir()); err == nil || !strings.Contains(err.Error(), "exit 7: denied") {
		t.Fatalf("nonzero Rust exit accepted: %v", err)
	}
	if _, err := runRustRaw(filepath.Join(t.TempDir(), "missing"), t.TempDir()); err == nil || !strings.Contains(err.Error(), "launch Rust CLI") {
		t.Fatalf("missing Rust binary accepted: %v", err)
	}
	if err := run(filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("live differential accepted missing Rust binary: %v", err)
	}
}
