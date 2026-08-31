package update

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSecureClient_TLS13Only(t *testing.T) {
	client := newSecureClient()
	if client == nil {
		t.Fatal("newSecureClient() returned nil")
	}
	if client.Timeout == 0 {
		t.Fatal("expected non-zero timeout")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLSClientConfig")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want %x (TLS 1.3)", transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
}

func TestNewSecureClient_RejectsTLS12(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	server.TLS.MaxVersion = tls.VersionTLS12

	client := newSecureClient()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.InsecureSkipVerify = true

	resp, err := client.Get(server.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected TLS 1.2-only server to be rejected")
	}
	if !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("expected protocol version error, got: %v", err)
	}
}

func TestChecker_FetchWithTLSError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewChecker(nil)
	checker.LatestReleaseURL = server.URL
	checker.CacheTTL = 0

	_, err := checker.Check(context.Background(), "1.0.0")
	if err == nil {
		t.Fatal("expected TLS certificate error")
	}
	if !strings.Contains(err.Error(), "update check failed: TLS certificate verification error") {
		t.Fatalf("expected user-friendly TLS error message, got: %v", err)
	}
}
