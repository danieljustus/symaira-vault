package cmd

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/config"
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

func TestApprovalList_Empty(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()

	cmd := newDeviceApprovalListCmd()
	var runErr error
	output := captureStdout(func() {
		runErr = cmd.RunE(cmd, nil)
	})
	if runErr != nil {
		t.Fatalf("approval-list: %v", runErr)
	}
	if output != "No approval devices enrolled.\n" {
		t.Fatalf("approval-list output = %q, want empty-state message", output)
	}
}

func TestApprovalList_RendersSessionStates(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()

	now := time.Now().UTC()
	writeApprovalDeviceSessions(t, vaultDir, map[string]*pairing.DeviceSession{
		strings.Repeat("a", 64): {
			Prefix:    "ACT1",
			DeviceID:  "device-one",
			Name:      "Phone",
			CreatedAt: now.Add(-time.Hour),
			ExpiresAt: now.Add(time.Hour),
		},
		strings.Repeat("b", 64): {
			Prefix:    "REV1",
			DeviceID:  "device-two",
			CreatedAt: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(time.Hour),
			Revoked:   true,
		},
		strings.Repeat("c", 64): {
			Prefix:    "EXP1",
			DeviceID:  "device-three",
			Name:      "OldPhone",
			CreatedAt: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(-time.Hour),
		},
	})

	cmd := newDeviceApprovalListCmd()
	var runErr error
	output := captureStdout(func() {
		runErr = cmd.RunE(cmd, nil)
	})
	if runErr != nil {
		t.Fatalf("approval-list: %v", runErr)
	}
	if !strings.Contains(output, "DEVICE ID") || !strings.Contains(output, "TOKEN") || !strings.Contains(output, "STATUS") {
		t.Fatalf("approval-list output missing header: %q", output)
	}
	assertApprovalListLine(t, output, "device-one", "ACT1…", "Phone", "active")
	assertApprovalListLine(t, output, "device-two", "REV1…", "(unnamed)", "revoked")
	assertApprovalListLine(t, output, "device-three", "EXP1…", "OldPhone", "expired")
}

func TestApprovalCommands_ReportStoreLoadErrors(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{name: "list", run: func() error {
			cmd := newDeviceApprovalListCmd()
			return cmd.RunE(cmd, nil)
		}},
		{name: "revoke", run: func() error {
			cmd := newDeviceApprovalRevokeCmd()
			return cmd.RunE(cmd, []string{"dev-one"})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetVaultState(t)
			vaultDir := t.TempDir()
			defer setupVaultFlag(t, vaultDir)()
			writeApprovalDeviceStoreBytes(t, vaultDir, []byte("{not-json"))

			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), "load approval device store") {
				t.Fatalf("error = %v, want approval device store load error", err)
			}
		})
	}
}

func TestApprovalCommands_ReportVaultPathErrors(t *testing.T) {
	resetVaultState(t)
	for _, key := range []string{"HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"} {
		t.Setenv(key, "")
	}
	originalVault := cli.Vault
	originalChanged := cli.VaultFlag.Changed
	if err := cli.VaultFlag.Value.Set("~/approval-test"); err != nil {
		t.Fatalf("set vault flag: %v", err)
	}
	cli.VaultFlag.Changed = true
	t.Cleanup(func() {
		_ = cli.VaultFlag.Value.Set(originalVault)
		cli.VaultFlag.Changed = originalChanged
	})

	tests := []struct {
		name string
		run  func() error
	}{
		{name: "list", run: func() error {
			cmd := newDeviceApprovalListCmd()
			return cmd.RunE(cmd, nil)
		}},
		{name: "revoke", run: func() error {
			cmd := newDeviceApprovalRevokeCmd()
			return cmd.RunE(cmd, []string{"dev-one"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil || !strings.Contains(err.Error(), "expand vault path") {
				t.Fatalf("error = %v, want vault path expansion error", err)
			}
		})
	}
}

func TestApprovalRevoke_UnknownDevice(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()

	cmd := newDeviceApprovalRevokeCmd()
	err := cmd.RunE(cmd, []string{"missing-device"})
	if err == nil || !strings.Contains(err.Error(), `approval device "missing-device" not found`) {
		t.Fatalf("error = %v, want unknown-device error", err)
	}
}

func TestApprovalRevoke_CancelledPreservesSession(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()
	token := enrollApprovalDevice(t, vaultDir, "dev-cancel", "Phone")

	cmd := newDeviceApprovalRevokeCmd()
	var runErr error
	stderr := captureStderr(func() {
		runErr = withApprovalStdin(t, "n\n", func() error {
			return cmd.RunE(cmd, []string{"dev-cancel"})
		})
	})
	if runErr != nil {
		t.Fatalf("approval-revoke cancellation: %v", runErr)
	}
	if !strings.Contains(stderr, "Canceled") {
		t.Fatalf("stderr = %q, want cancellation message", stderr)
	}
	assertApprovalTokenValid(t, vaultDir, token, "dev-cancel", true)
}

func TestApprovalRevoke_PersistsRevocation(t *testing.T) {
	tests := []struct {
		name  string
		yes   bool
		input string
	}{
		{name: "yes flag", yes: true},
		{name: "confirmed prompt", input: "y\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetVaultState(t)
			vaultDir := t.TempDir()
			defer setupVaultFlag(t, vaultDir)()
			token := enrollApprovalDevice(t, vaultDir, "dev-revoke", "Phone")

			cmd := newDeviceApprovalRevokeCmd()
			if tt.yes {
				if err := cmd.Flags().Set("yes", "true"); err != nil {
					t.Fatalf("set --yes: %v", err)
				}
			}
			var runErr error
			output := captureStdout(func() {
				if tt.input == "" {
					runErr = cmd.RunE(cmd, []string{"dev-revoke"})
					return
				}
				runErr = withApprovalStdin(t, tt.input, func() error {
					return cmd.RunE(cmd, []string{"dev-revoke"})
				})
			})
			if runErr != nil {
				t.Fatalf("approval-revoke: %v", runErr)
			}
			if !strings.Contains(output, `Approval device "dev-revoke" revoked.`) {
				t.Fatalf("stdout = %q, want revocation confirmation", output)
			}
			assertApprovalTokenValid(t, vaultDir, token, "dev-revoke", false)
		})
	}
}

func TestApprovalRevoke_ReportsSaveError(t *testing.T) {
	resetVaultState(t)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()
	_ = enrollApprovalDevice(t, vaultDir, "dev-save-error", "Phone")

	tmpPath := filepath.Join(vaultDir, config.DefaultVaultSubdir, "device-sessions.json.tmp")
	if err := os.Mkdir(tmpPath, 0o700); err != nil {
		t.Fatalf("create blocking temp directory: %v", err)
	}

	cmd := newDeviceApprovalRevokeCmd()
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set --yes: %v", err)
	}
	err := cmd.RunE(cmd, []string{"dev-save-error"})
	if err == nil || !strings.Contains(err.Error(), "save approval device store") {
		t.Fatalf("error = %v, want save error", err)
	}
}

func writeApprovalDeviceSessions(t *testing.T, vaultDir string, sessions map[string]*pairing.DeviceSession) {
	t.Helper()
	data, err := json.Marshal(sessions)
	if err != nil {
		t.Fatalf("marshal approval sessions: %v", err)
	}
	writeApprovalDeviceStoreBytes(t, vaultDir, data)
}

func writeApprovalDeviceStoreBytes(t *testing.T, vaultDir string, data []byte) {
	t.Helper()
	dir := filepath.Join(vaultDir, config.DefaultVaultSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create approval store directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "device-sessions.json"), data, 0o600); err != nil {
		t.Fatalf("write approval store: %v", err)
	}
}

func assertApprovalListLine(t *testing.T, output, deviceID string, wants ...string) {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, deviceID) {
			continue
		}
		for _, want := range wants {
			if !strings.Contains(line, want) {
				t.Fatalf("line for %s = %q, want %q", deviceID, line, want)
			}
		}
		return
	}
	t.Fatalf("approval-list output has no line for %s: %q", deviceID, output)
}

func enrollApprovalDevice(t *testing.T, vaultDir, deviceID, name string) string {
	t.Helper()
	store, err := pairing.NewDeviceSessionStore(vaultDir)
	if err != nil {
		t.Fatalf("new approval device store: %v", err)
	}
	token, err := store.Enroll(deviceID, name, "age1-test-public-key")
	if err != nil {
		t.Fatalf("enroll approval device: %v", err)
	}
	return token
}

func assertApprovalTokenValid(t *testing.T, vaultDir, token, wantDeviceID string, wantValid bool) {
	t.Helper()
	store, err := pairing.NewDeviceSessionStore(vaultDir)
	if err != nil {
		t.Fatalf("reload approval device store: %v", err)
	}
	deviceID, valid := store.Validate(token)
	if valid != wantValid {
		t.Fatalf("Validate(%q) valid = %v, want %v", wantDeviceID, valid, wantValid)
	}
	if wantValid && deviceID != wantDeviceID {
		t.Fatalf("Validate device ID = %q, want %q", deviceID, wantDeviceID)
	}
	if !wantValid && deviceID != "" {
		t.Fatalf("revoked token returned device ID %q", deviceID)
	}
}

func withApprovalStdin(t *testing.T, input string, fn func() error) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write stdin fixture: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open stdin fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	originalStdin := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = originalStdin }()
	return fn()
}
