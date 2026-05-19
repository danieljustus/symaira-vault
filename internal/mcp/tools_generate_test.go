package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestHandleGenerate_DefaultLength(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	req := CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleGenerate(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerate() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGenerate() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleGenerate() returned error: %s", result.Text)
	}

	password := result.Text
	if len(password) != 16 {
		t.Errorf("password length = %d, want 16 (default)", len(password))
	}
}

func TestHandleGenerate_CustomLength(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	req := CallToolRequest{
		Arguments: map[string]any{"length": 32.0},
	}

	result, err := srv.handleGenerate(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerate() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGenerate() returned nil result")
	}

	password := result.Text
	if len(password) != 32 {
		t.Errorf("password length = %d, want 32", len(password))
	}
}

func TestHandleGenerate_WithSymbols(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	req := CallToolRequest{
		Arguments: map[string]any{"length": 50.0, "symbols": "true"},
	}

	result, err := srv.handleGenerate(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerate() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGenerate() returned nil result")
	}

	password := result.Text
	hasSymbol := false
	for _, c := range password {
		if strings.Contains("!@#$%^&*()_+-=[]{}|;:,.<>?", string(c)) {
			hasSymbol = true
			break
		}
	}
	if !hasSymbol {
		t.Error("expected password to contain symbols")
	}
}

func TestHandleGenerate_WithoutSymbols(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	req := CallToolRequest{
		Arguments: map[string]any{"length": 50.0, "symbols": "false"},
	}

	result, err := srv.handleGenerate(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerate() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGenerate() returned nil result")
	}

	password := result.Text
	for _, c := range password {
		if strings.Contains("!@#$%^&*()_+-=[]{}|;:,.<>?", string(c)) {
			t.Error("expected password to NOT contain symbols")
			break
		}
	}
}

func TestHandleGenerate_NonNumericLength(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	req := CallToolRequest{
		Arguments: map[string]any{"length": "not-a-number"},
	}

	result, err := srv.handleGenerate(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerate() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGenerate() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleGenerate() returned error: %s", result.Text)
	}

	password := result.Text
	if len(password) != 16 {
		t.Errorf("password length = %d, want 16 (default fallback)", len(password))
	}
}

func TestGeneratePassword(t *testing.T) {
	password, err := generatePassword(16, true)
	if err != nil {
		t.Fatalf("generatePassword() error = %v", err)
	}
	if len(password) != 16 {
		t.Errorf("password length = %d, want 16", len(password))
	}

	// Generate again to ensure randomness
	password2, err := generatePassword(16, true)
	if err != nil {
		t.Fatalf("generatePassword() second call error = %v", err)
	}
	if password == password2 {
		t.Error("expected different passwords on consecutive calls")
	}
}

func TestGeneratePassword_ZeroLength(t *testing.T) {
	password, err := generatePassword(0, true)
	if err != nil {
		t.Fatalf("generatePassword() error = %v", err)
	}
	// Should default to 16
	if len(password) != 16 {
		t.Errorf("password length = %d, want 16 (default)", len(password))
	}
}

func TestGeneratePassword_NoSymbols(t *testing.T) {
	password, err := generatePassword(50, false)
	if err != nil {
		t.Fatalf("generatePassword() error = %v", err)
	}

	for _, c := range password {
		if strings.Contains("!@#$%^&*()_+-=[]{}|;:,.<>?", string(c)) {
			t.Error("expected password without symbols")
			break
		}
	}
}

func TestExecuteTool_GeneratePassword(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	args := json.RawMessage(`{}`)
	result, err := srv.executeTool(context.Background(), "generate_password", args)
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
}
