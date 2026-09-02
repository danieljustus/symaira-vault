package cmd

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/approval"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
	"github.com/danieljustus/symaira-vault/internal/pairing"
)

func TestApprovalPairingPayload_JSONShape(t *testing.T) {
	payload := approvalPairingPayload{Host: "192.168.1.42", Port: 8443, Code: "ABCD1234", Fingerprint: "deadbeef"}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"host", "port", "code", "fingerprint"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("expected JSON key %q in pairing payload, got %v", key, decoded)
		}
	}
}

// TestMintApprovalEnrollCode_RoundTrip exercises the full HTTPS call
// mintApprovalEnrollCode makes to the local enroll-code endpoint, using the
// exact same cert-generation/pinning code paths serve_deps.go and
// device_approval.go use in production: a real TLS listener presenting the
// vault directory's cached certificate, trusted only because
// mintApprovalEnrollCode loads that same certificate file — not the system
// trust store.
func TestMintApprovalEnrollCode_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	certFile, keyFile, err := serverbootstrap.EnsureTLSCert(dir)
	if err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}

	secret, err := serverbootstrap.EnsureEnrollSecret(dir)
	if err != nil {
		t.Fatalf("EnsureEnrollSecret: %v", err)
	}
	codes := pairing.NewTokenStore()
	handler := approval.NewEnrollCodeHTTPHandler(codes, "fp-test", func(string) bool { return true }, secret)

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	code, expiresAt, fingerprint, err := mintApprovalEnrollCode(dir, port)
	if err != nil {
		t.Fatalf("mintApprovalEnrollCode: %v", err)
	}
	if code == "" {
		t.Error("expected a non-empty code")
	}
	if fingerprint != "fp-test" {
		t.Errorf("fingerprint = %q, want fp-test", fingerprint)
	}
	if expiresAt.IsZero() {
		t.Error("expected a non-zero expiry")
	}

	if _, ok := codes.Validate(code); !ok {
		t.Error("minted code did not validate against the same store")
	}
}

func TestMintApprovalEnrollCode_RejectsUntrustedServer(t *testing.T) {
	dir := t.TempDir()
	// Deliberately do NOT create a cert in dir before starting the test
	// server with its own self-generated (different) certificate, so the
	// pinned client should refuse to trust it.
	secret, err := serverbootstrap.EnsureEnrollSecret(dir)
	if err != nil {
		t.Fatalf("EnsureEnrollSecret: %v", err)
	}
	codes := pairing.NewTokenStore()
	handler := approval.NewEnrollCodeHTTPHandler(codes, "fp-test", func(string) bool { return true }, secret)

	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	if _, _, err := serverbootstrap.EnsureTLSCert(dir); err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}

	if _, _, _, err := mintApprovalEnrollCode(dir, port); err == nil {
		t.Fatal("expected an error connecting to a server presenting an untrusted certificate")
	}
}

// TestApprovalPair_RefusesLoopbackOnlyBind covers the issue's core
// acceptance criterion: running "approval-pair" against a server bound to
// 127.0.0.1 (the default) must produce a clear, actionable error instead of
// a QR code a phone can never reach. This is checked before any network
// call, so no server needs to actually be listening.
func TestApprovalPair_RefusesLoopbackOnlyBind(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	if err := cli.SaveRuntimePort(vaultDir, "127.0.0.1", 8443); err != nil {
		t.Fatalf("SaveRuntimePort: %v", err)
	}

	cmd := newDeviceApprovalPairCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected an error for a loopback-only bind, got nil")
	}
	if !strings.Contains(err.Error(), "loopback-only") || !strings.Contains(err.Error(), "--bind") {
		t.Fatalf("error = %q, want it to explain the loopback-only bind and suggest --bind", err.Error())
	}
}

// TestApprovalPair_AllowsNonLoopbackBind is the negative case: a server
// bound to a real interface must not be refused by the loopback check (the
// command still fails past that point in this test, since no server is
// actually listening on the recorded port — but that failure must not be
// the loopback-only error).
func TestApprovalPair_AllowsNonLoopbackBind(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	if err := cli.SaveRuntimePort(vaultDir, "0.0.0.0", 8443); err != nil {
		t.Fatalf("SaveRuntimePort: %v", err)
	}

	cmd := newDeviceApprovalPairCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("expected an error since no server is actually listening, got nil")
	}
	if strings.Contains(err.Error(), "loopback-only") {
		t.Fatalf("error = %q, should not be the loopback-only refusal for a non-loopback bind", err.Error())
	}
}
