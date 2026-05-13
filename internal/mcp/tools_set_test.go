package mcp

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func assertTOTPSet(t *testing.T, vaultDir string, identity *age.X25519Identity, path string) {
	t.Helper()

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	totpJSON := `{"secret":"JBSWY3DPEHPK3PXP","issuer":"GitHub","account_name":"testuser"}`
	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  path,
			"field": "totp",
			"value": totpJSON,
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleSet() returned error: %s", result.Text)
	}

	entry, err := vault.ReadEntry(vaultDir, path, identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	totpData, ok := entry.Data["totp"].(map[string]any)
	if !ok {
		t.Fatal("totp field should be map[string]any")
	}
	if totpData["secret"] != "JBSWY3DPEHPK3PXP" {
		t.Errorf("totp.secret = %v, want JBSWY3DPEHPK3PXP", totpData["secret"])
	}
	if totpData["issuer"] != "GitHub" {
		t.Errorf("totp.issuer = %v, want GitHub", totpData["issuer"])
	}
	if totpData["account_name"] != "testuser" {
		t.Errorf("totp.account_name = %v, want testuser", totpData["account_name"])
	}
}

func TestHandleSet_WriteDenied(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false, // Cannot write
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "password",
			"value": "newpass",
		},
	}

	_, err := srv.handleSet(context.Background(), req)
	if err == nil {
		t.Fatal("handleSet() expected error for write-denied agent, got nil")
	}
	if !strings.Contains(err.Error(), "write operations not permitted") {
		t.Fatalf("handleSet() error = %v, want 'write operations not permitted'", err)
	}
}

func TestHandleSet_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "password",
			"value": "StrongP@ssw0rd123",
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleSet() returned error: %s", result.Text)
	}

	// Verify the entry was updated
	entry, err := vault.ReadEntry(vaultDir, "github", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if entry.Data["password"] != "StrongP@ssw0rd123" {
		t.Errorf("password = %v, want StrongP@ssw0rd123", entry.Data["password"])
	}
}

func TestHandleSet_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "password",
			"value": "newpass",
		},
	}

	_, err := srv.handleSet(context.Background(), req)
	if err == nil {
		t.Fatal("handleSet() expected error for out-of-scope path, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("handleSet() error = %v, want 'outside allowed scope'", err)
	}
}

func TestHandleSet_ApprovalRequired(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "deny", // Requires approval
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "password",
			"value": "newpass",
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("handleSet() expected IsError for approval-required path")
	}
}

func TestHandleSet_MissingParams(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path": "github",
			// missing field and value
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if !result.IsError {
		t.Error("handleSet() expected error result for missing params")
	}
}

func TestHandleSet_NewEntry(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "newentry",
			"field": "password",
			"value": "StrongP@ssw0rd123",
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleSet() returned error: %s", result.Text)
	}

	// Verify the entry was created
	_, err = vault.ReadEntry(vaultDir, "newentry", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
}

func TestHandleSet_TOTPField(t *testing.T) {
	vaultDir, identity := mockVault(t)
	assertTOTPSet(t, vaultDir, identity, "github")
}

func TestHandleSet_NewEntryTOTP(t *testing.T) {
	vaultDir, identity := mockVault(t)
	assertTOTPSet(t, vaultDir, identity, "newentry")
}

func TestHandleSet_InvalidTOTPJSON(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "totp",
			"value": "not-valid-json",
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if !result.IsError {
		t.Error("handleSet() expected error for invalid TOTP JSON")
	}
}

func TestHandleSet_TOTPInvalidAlgorithm(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	totpJSON := `{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"MD5","digits":6,"period":30}`
	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "totp",
			"value": totpJSON,
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if !result.IsError {
		t.Error("handleSet() expected error for invalid TOTP algorithm")
	}
	if !strings.Contains(result.Text, "invalid TOTP") {
		t.Errorf("handleSet() error text = %q, want to contain 'invalid TOTP'", result.Text)
	}
}

func TestHandleSet_TOTPInvalidDigits(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	totpJSON := `{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":7,"period":30}`
	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "totp",
			"value": totpJSON,
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if !result.IsError {
		t.Error("handleSet() expected error for invalid TOTP digits")
	}
	if !strings.Contains(result.Text, "invalid TOTP") {
		t.Errorf("handleSet() error text = %q, want to contain 'invalid TOTP'", result.Text)
	}
}

func TestHandleSet_TOTPInvalidPeriod(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	totpJSON := `{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":6,"period":5000}`
	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "totp",
			"value": totpJSON,
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if !result.IsError {
		t.Error("handleSet() expected error for invalid TOTP period")
	}
	if !strings.Contains(result.Text, "invalid TOTP") {
		t.Errorf("handleSet() error text = %q, want to contain 'invalid TOTP'", result.Text)
	}
}

func TestHandleSet_TOTPValidParams(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	totpJSON := `{"secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":6,"period":30}`
	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "newentry",
			"field": "totp",
			"value": totpJSON,
		},
	}

	result, err := srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleSet() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleSet() returned error: %s", result.Text)
	}

	entry, err := vault.ReadEntry(vaultDir, "newentry", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	totpData, ok := entry.Data["totp"].(map[string]any)
	if !ok {
		t.Fatal("totp field should be map[string]any")
	}
	if totpData["algorithm"] != "SHA1" {
		t.Errorf("totp.algorithm = %v, want SHA1", totpData["algorithm"])
	}
	if totpData["digits"] != float64(6) {
		t.Errorf("totp.digits = %v, want 6", totpData["digits"])
	}
	if totpData["period"] != float64(30) {
		t.Errorf("totp.period = %v, want 30", totpData["period"])
	}
}

func TestHandleSet_WriteEntryFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "new-entry-that-does-not-exist",
			"field": "password",
			"value": "StrongP@ssw0rd123",
		},
	}

	srv.vault.Dir = "/nonexistent/directory/that/cannot/be/created"

	_, err := srv.handleSet(context.Background(), req)
	if err == nil {
		t.Fatal("handleSet() expected error when WriteEntry fails, got nil")
	}
}

func TestHandleSet_PreservesMultiRecipientAccess(t *testing.T) {
	writerDir := t.TempDir()
	writerIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate writer identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     true,
				ApprovalMode: "none",
			},
		},
	}
	if initErr := vault.Init(writerDir, writerIdentity, cfg); initErr != nil {
		t.Fatalf("vault.Init() error = %v", initErr)
	}

	secondIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate second identity: %v", err)
	}

	rm := vault.NewRecipientsManager(writerDir)
	if addErr := rm.AddRecipient(secondIdentity.Recipient().String()); addErr != nil {
		t.Fatalf("AddRecipient() error = %v", addErr)
	}

	srv := &Server{
		vault: &vault.Vault{
			Dir:      writerDir,
			Identity: writerIdentity,
		},
		agent: &config.AgentProfile{
			Name:         "test",
			AllowedPaths: []string{"*"},
			CanWrite:     true,
			ApprovalMode: "none",
		},
	}

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "shared-entry",
			"field": "password",
			"value": "StrongP@ssw0rd123",
		},
	}
	_, err = srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}

	entry, err := vault.ReadEntry(writerDir, "shared-entry", secondIdentity)
	if err != nil {
		t.Fatalf("ReadEntry() with second identity error = %v", err)
	}
	if entry.Data["password"] != "StrongP@ssw0rd123" {
		t.Errorf("password = %v, want StrongP@ssw0rd123", entry.Data["password"])
	}
}

func TestHandleSet_MergePreservesMultiRecipientAccess(t *testing.T) {
	writerDir := t.TempDir()
	writerIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate writer identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     true,
				ApprovalMode: "none",
			},
		},
	}
	if initErr := vault.Init(writerDir, writerIdentity, cfg); initErr != nil {
		t.Fatalf("vault.Init() error = %v", initErr)
	}

	existingEntry := &vault.Entry{
		Data: map[string]any{
			"username": "testuser",
		},
	}
	if writeErr := vault.WriteEntry(writerDir, "existing-entry", existingEntry, writerIdentity); writeErr != nil {
		t.Fatalf("WriteEntry() error = %v", writeErr)
	}

	secondIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate second identity: %v", err)
	}

	rm := vault.NewRecipientsManager(writerDir)
	if addErr := rm.AddRecipient(secondIdentity.Recipient().String()); addErr != nil {
		t.Fatalf("AddRecipient() error = %v", addErr)
	}

	srv := &Server{
		vault: &vault.Vault{
			Dir:      writerDir,
			Identity: writerIdentity,
		},
		agent: &config.AgentProfile{
			Name:         "test",
			AllowedPaths: []string{"*"},
			CanWrite:     true,
			ApprovalMode: "none",
		},
	}

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":  "existing-entry",
			"field": "password",
			"value": "StrongP@ssw0rd123",
		},
	}
	_, err = srv.handleSet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}

	entry, err := vault.ReadEntry(writerDir, "existing-entry", secondIdentity)
	if err != nil {
		t.Fatalf("ReadEntry() with second identity error = %v", err)
	}
	if entry.Data["password"] != "StrongP@ssw0rd123" {
		t.Errorf("password = %v, want StrongP@ssw0rd123", entry.Data["password"])
	}
	if entry.Data["username"] != "testuser" {
		t.Errorf("username = %v, want testuser", entry.Data["username"])
	}
}
