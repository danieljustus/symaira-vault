package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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
}
