package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/autotype"
	"github.com/danieljustus/OpenPass/internal/clipboard"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"

	"filippo.io/age"
)

func writeTOTPEntry(t *testing.T, vaultDir string, identity *age.X25519Identity) {
	t.Helper()
	entry := &vault.Entry{
		Data: map[string]any{
			"password": "testpass123",
			"username": "testuser",
			"totp": map[string]any{
				"secret":       "JBSWY3DPEHPK3PXP",
				"issuer":       "GitHub",
				"account_name": "testuser",
			},
		},
	}
	if err := vault.WriteEntry(vaultDir, "github", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}
}

// Return destination with explicit return_code=true
func TestHandleGenerateTOTP_ReturnSuccess(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      false,
		CanReadValues: true,
		ApprovalMode:  "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":        "github",
			"destination": "return",
			"return_code": true,
		},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handleGenerateTOTP() returned error: %v", result)
	}

	var totpResult map[string]any
	if err := json.Unmarshal([]byte(result.Text), &totpResult); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if totpResult["code"] == nil || totpResult["code"] == "" {
		t.Error("expected TOTP code in return result")
	}
	if totpResult["expires_at"] == nil {
		t.Error("expected expires_at in return result")
	}
	if totpResult["period"] == nil {
		t.Error("expected period in return result")
	}
}

func TestHandleGenerateTOTP_ReturnWithoutReturnCode(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":        "github",
			"destination": "return",
		},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected error for return without return_code")
	}
	if !strings.Contains(result.Text, "return_code must be true") {
		t.Fatalf("error = %q, want 'return_code must be true'", result.Text)
	}
}

func TestHandleGenerateTOTP_ClipboardDefault(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "test",
		AllowedPaths:    []string{"*"},
		CanWrite:        false,
		CanUseClipboard: true,
		ApprovalMode:    "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	mockClip := &mockClipboard{}
	clipboard.SetClipboard(mockClip)
	defer clipboard.SetClipboard(nil)

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handleGenerateTOTP() returned error: %v", result)
	}

	// Verify clipboard received the code
	text, _ := mockClip.Read()
	if text == "" {
		t.Error("expected TOTP code in clipboard")
	}
	if len(text) != 6 {
		t.Errorf("expected 6-digit TOTP code, got %q", text)
	}

	// Verify response has clipboard format (no code)
	var clipResult map[string]any
	if err := json.Unmarshal([]byte(result.Text), &clipResult); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if clipResult["success"] != true {
		t.Error("expected success=true in clipboard result")
	}
	if clipResult["destination"] != "clipboard" {
		t.Error(`expected destination="clipboard" in clipboard result`)
	}
	if clipResult["code"] != nil {
		t.Error("code should not be present in clipboard response")
	}
	if clipResult["clipboard_clears_in"] == nil {
		t.Error("expected clipboard_clears_in in clipboard result")
	}
	if clipResult["expires_in"] != nil {
		t.Error("expires_in should not be present in clipboard response (use clipboard_clears_in)")
	}
}

func TestHandleGenerateTOTP_DefaultsToReturnForCanReadValues(t *testing.T) {
	// Agents with only CanReadValues (no clipboard, no autotype) should default
	// destination to "return" rather than "clipboard" to avoid a confusing denial.
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      false,
		CanReadValues: true,
		ApprovalMode:  "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	// No destination specified — should default to "return" for this agent.
	// Without return_code=true, totpReturn will return a tool-level error.
	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected error result: return_code must be true (destination defaulted to return)")
	}
	if !strings.Contains(result.Text, "return_code must be true") {
		t.Fatalf("error = %q, want 'return_code must be true'", result.Text)
	}
}

func TestHandleGenerateTOTP_ClipboardExplicit(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "test",
		AllowedPaths:    []string{"*"},
		CanWrite:        false,
		CanUseClipboard: true,
		ApprovalMode:    "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	mockClip := &mockClipboard{}
	clipboard.SetClipboard(mockClip)
	defer clipboard.SetClipboard(nil)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":        "github",
			"destination": "clipboard",
		},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handleGenerateTOTP() returned error: %v", result)
	}

	text, _ := mockClip.Read()
	if text == "" {
		t.Error("expected TOTP code in clipboard")
	}
}

func TestHandleGenerateTOTP_ClipboardDenied(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "test",
		AllowedPaths:    []string{"*"},
		CanWrite:        false,
		CanUseClipboard: false,
		ApprovalMode:    "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":        "github",
			"destination": "clipboard",
		},
	}

	_, err := srv.handleGenerateTOTP(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for clipboard denied")
	}
	if !strings.Contains(err.Error(), "clipboard operations not permitted") {
		t.Fatalf("error = %q, want 'clipboard operations not permitted'", err.Error())
	}
}

func TestHandleGenerateTOTP_AutotypeSuccess(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanWrite:       false,
		CanUseAutotype: true,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	mockAT := &mockAutotype{}
	autotype.SetAutotype(mockAT)
	defer autotype.SetAutotype(nil)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":        "github",
			"destination": "autotype",
		},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("handleGenerateTOTP() returned error: %v", result)
	}

	// Verify autotype received the code
	mockAT.mu.Lock()
	text := mockAT.text
	mockAT.mu.Unlock()
	if text == "" {
		t.Error("expected TOTP code sent to autotype")
	}
	if len(text) != 6 {
		t.Errorf("expected 6-digit TOTP code, got %q", text)
	}

	// Verify response
	if !strings.Contains(result.Text, `"success": true`) {
		t.Errorf("expected success response, got %q", result.Text)
	}
}

func TestHandleGenerateTOTP_AutotypeDenied(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanWrite:       false,
		CanUseAutotype: false,
		ApprovalMode:   "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":        "github",
			"destination": "autotype",
		},
	}

	_, err := srv.handleGenerateTOTP(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for autotype denied")
	}
	if !strings.Contains(err.Error(), "autotype operations not permitted") {
		t.Fatalf("error = %q, want 'autotype operations not permitted'", err.Error())
	}
}

func TestHandleGenerateTOTP_InvalidDestination(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":        "github",
			"destination": "email",
		},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected error for invalid destination")
	}
	if !strings.Contains(result.Text, `invalid destination "email"`) {
		t.Fatalf("error = %q, want 'invalid destination'", result.Text)
	}
}

func TestHandleGenerateTOTP_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	entry := &vault.Entry{
		Data: map[string]any{
			"password": "testpass123",
			"totp": map[string]any{
				"secret": "JBSWY3DPEHPK3PXP",
			},
		},
	}
	if err := vault.WriteEntry(vaultDir, "github", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	_, err := srv.handleGenerateTOTP(context.Background(), req)
	if err == nil {
		t.Fatal("handleGenerateTOTP() expected error for out-of-scope path, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("handleGenerateTOTP() error = %v, want 'outside allowed scope'", err)
	}
}

func TestHandleGenerateTOTP_MissingPath(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGenerateTOTP() returned nil result")
	}
	if !result.IsError {
		t.Error("handleGenerateTOTP() expected error result for missing path")
	}
}

func TestHandleGenerateTOTP_EntryNotFound(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "nonexistent"},
	}

	result, err := srv.handleGenerateTOTP(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("handleGenerateTOTP() expected error result for nonexistent entry")
	}
}

func TestHandleGenerateTOTP_NoTOTPConfig(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	entry := &vault.Entry{
		Data: map[string]any{
			"password": "testpass123",
		},
	}
	if err := vault.WriteEntry(vaultDir, "github", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	_, err := srv.handleGenerateTOTP(context.Background(), req)
	if err == nil {
		t.Fatal("handleGenerateTOTP() expected error for entry without TOTP, got nil")
	}
	if !strings.Contains(err.Error(), "does not have TOTP configuration") {
		t.Fatalf("handleGenerateTOTP() error = %v, want 'does not have TOTP configuration'", err)
	}
}

func TestHandleGenerateTOTP_EmptySecret(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	entry := &vault.Entry{
		Data: map[string]any{
			"password": "testpass123",
			"totp": map[string]any{
				"secret": "",
			},
		},
	}
	if err := vault.WriteEntry(vaultDir, "github", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	_, err := srv.handleGenerateTOTP(context.Background(), req)
	if err == nil {
		t.Fatal("handleGenerateTOTP() expected error for empty TOTP secret, got nil")
	}
}

func TestExecuteTool_GenerateTOTP_Return(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      false,
		CanReadValues: true,
		ApprovalMode:  "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	args := json.RawMessage(`{"path": "github", "destination": "return", "return_code": true}`)
	result, err := srv.executeTool(context.Background(), "generate_totp", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
	if result["isError"] == true {
		t.Errorf("expected no error, got isError=true: %s", content[0]["text"])
	}

	var totpResult map[string]any
	if err := json.Unmarshal([]byte(content[0]["text"].(string)), &totpResult); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if totpResult["code"] == nil {
		t.Error("expected code in return result via executeTool")
	}
}

func TestExecuteTool_GenerateTOTP_Clipboard(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "test",
		AllowedPaths:    []string{"*"},
		CanWrite:        false,
		CanUseClipboard: true,
		ApprovalMode:    "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	writeTOTPEntry(t, vaultDir, identity)

	mockClip := &mockClipboard{}
	clipboard.SetClipboard(mockClip)
	defer clipboard.SetClipboard(nil)

	args := json.RawMessage(`{"path": "github"}`)
	result, err := srv.executeTool(context.Background(), "generate_totp", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("result content has unexpected type")
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}
	if result["isError"] == true {
		t.Errorf("expected no error, got isError=true: %s", content[0]["text"])
	}

	// Verify clipboard received the code
	text, _ := mockClip.Read()
	if text == "" {
		t.Error("expected TOTP code in clipboard via executeTool")
	}
}

func TestGenerateTOTPAvailable_ClipboardOnly(t *testing.T) {
	srv := &Server{agent: &config.AgentProfile{CanUseClipboard: true, CanUseAutotype: false, CanReadValues: false}}
	if !generateTOTPAvailable(srv) {
		t.Error("expected TOTP available when clipboard is allowed")
	}
}

func TestGenerateTOTPAvailable_AutotypeOnly(t *testing.T) {
	srv := &Server{agent: &config.AgentProfile{CanUseClipboard: false, CanUseAutotype: true, CanReadValues: false}}
	if !generateTOTPAvailable(srv) {
		t.Error("expected TOTP available when autotype is allowed")
	}
}

func TestGenerateTOTPAvailable_CanReadValuesOnly(t *testing.T) {
	srv := &Server{agent: &config.AgentProfile{CanUseClipboard: false, CanUseAutotype: false, CanReadValues: true}}
	if !generateTOTPAvailable(srv) {
		t.Error("expected TOTP available when canReadValues")
	}
}

func TestGenerateTOTPAvailable_AllDenied(t *testing.T) {
	srv := &Server{agent: &config.AgentProfile{CanUseClipboard: false, CanUseAutotype: false, CanReadValues: false}}
	if generateTOTPAvailable(srv) {
		t.Error("expected TOTP not available when all denied")
	}
}

func TestGenerateTOTPAvailable_NilServer(t *testing.T) {
	if !generateTOTPAvailable(nil) {
		t.Error("expected TOTP available for nil server (no profile context)")
	}
}

func TestGenerateTOTPAvailable_NilAgent(t *testing.T) {
	srv := &Server{agent: nil}
	if !generateTOTPAvailable(srv) {
		t.Error("expected TOTP available for nil agent (no profile context)")
	}
}

func TestToolsList_GenerateTOTP_Filtered(t *testing.T) {
	// Profile with no usable capabilities → generate_totp should be filtered out
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "test",
		AllowedPaths:    []string{"*"},
		CanUseClipboard: false,
		CanUseAutotype:  false,
		CanReadValues:   false,
		CanWrite:        false,
	}, "stdio", "")

	tools := toolsListPayload(srv)
	for _, tool := range tools {
		if tool["name"] == "generate_totp" {
			t.Fatal("generate_totp should not be in tools/list when no TOTP destination available")
		}
	}
}

func TestToolsList_GenerateTOTP_Visible(t *testing.T) {
	// Profile with clipboard capability → generate_totp should be visible
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "test",
		AllowedPaths:    []string{"*"},
		CanUseClipboard: true,
		CanWrite:        false,
	}, "stdio", "")

	tools := toolsListPayload(srv)
	found := false
	for _, tool := range tools {
		if tool["name"] == "generate_totp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("generate_totp should be visible when clipboard is allowed")
	}
}
