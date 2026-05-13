package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

//nolint:dupl // similar test structure for get success cases
func TestHandleGet_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleGet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGet() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleGet() returned error: %s", result.Text)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(result.Text), &response); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if response["path"] != "github" {
		t.Errorf("path = %v, want github", response["path"])
	}
	if response["has_value"] != true {
		t.Errorf("has_value = %v, want true", response["has_value"])
	}

	meta, ok := response["meta"].(map[string]any)
	if !ok {
		t.Fatal("expected 'meta' field in response")
	}
	if meta["version"] != float64(1) {
		t.Errorf("version = %v, want 1", meta["version"])
	}
}

func TestHandleGet_WithValue(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":          "github",
			"include_value": "true",
		},
	}

	result, err := srv.handleGet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGet() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleGet() returned error: %s", result.Text)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(result.Text), &response); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	// include_value is deprecated — handleGet now always returns metadata only.
	// The password value should NOT appear in the response.
	if response["password"] != nil {
		t.Error("password value should not appear in metadata response")
	}
	if response["has_value"] != true {
		t.Error("has_value should be true")
	}
	fields, _ := response["fields"].([]any)
	if !hasField(fields, "password") {
		t.Error(`fields should contain field "password"`)
	}
	if len(fields) > 0 {
		f := fields[0].(map[string]any)
		if f["name"] == nil {
			t.Error("field should have 'name'")
		}
		if f["handle"] == nil {
			t.Error("field should have 'handle'")
		}
		if f["kind"] == nil {
			t.Error("field should have 'kind'")
		}
	}
}

// TestHandleGet_WithoutMetadata tests without the include_value flag.
// This is the default behavior — always returns metadata.

func TestHandleGet_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	_, err := srv.handleGet(context.Background(), req)
	if err == nil {
		t.Fatal("handleGet() expected error for out-of-scope path, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("handleGet() error = %v, want 'outside allowed scope'", err)
	}
}

func TestHandleGet_MissingPath(t *testing.T) {
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

	result, err := srv.handleGet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGet() returned nil result")
	}
	if !result.IsError {
		t.Error("handleGet() expected error result for missing path")
	}
}

func TestHandleGet_NotFound(t *testing.T) {
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

	result, err := srv.handleGet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGet() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("handleGet() expected error result for nonexistent entry")
	}
}

func TestHandleGet_WithMetadata(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path":          "github",
			"include_value": "true",
		},
	}

	result, err := srv.handleGet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGet() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleGet() returned error: %s", result.Text)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(result.Text), &response); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	// handleGet always returns metadata only.
	// include_value is ignored.
	if response["password"] != nil {
		t.Error("password value should not appear in metadata response")
	}
	if response["has_value"] != true {
		t.Error("has_value should be true")
	}
	fields, _ := response["fields"].([]any)
	if !hasField(fields, "password") {
		t.Error(`fields should contain field "password"`)
	}
	if len(fields) > 0 {
		f := fields[0].(map[string]any)
		if f["name"] == nil {
			t.Error("field should have 'name'")
		}
		if f["handle"] == nil {
			t.Error("field should have 'handle'")
		}
		if f["kind"] == nil {
			t.Error("field should have 'kind'")
		}
	}
	meta, _ := response["meta"].(map[string]any)
	if meta == nil {
		t.Fatal("meta should be present")
	}
	if v, _ := meta["version"].(float64); v != 1 {
		t.Errorf("version = %v, want 1", v)
	}
}

//nolint:dupl // similar test structure for get success cases
func TestHandleGet_WithoutMetadata(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{
			"path": "github",
		},
	}

	result, err := srv.handleGet(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGet() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGet() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleGet() returned error: %s", result.Text)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(result.Text), &response); err != nil {
		t.Fatalf("parse result: %v", err)
	}

	if response["path"] != "github" {
		t.Errorf("path = %v, want github", response["path"])
	}
	if response["has_value"] != true {
		t.Errorf("has_value = %v, want true", response["has_value"])
	}

	meta, ok := response["meta"].(map[string]any)
	if !ok {
		t.Fatal("expected 'meta' field in response")
	}
	if meta["version"] != float64(1) {
		t.Errorf("version = %v, want 1", meta["version"])
	}
}

func TestHandleGet_RedactedTOTPStillGeneratesCode(t *testing.T) {
	vaultDir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"restricted": {
				Name:         "restricted",
				AllowedPaths: []string{"*"},
				CanWrite:     false,
				ApprovalMode: "none",
				RedactFields: []string{"totp.secret"},
			},
		},
	}
	if initErr := vault.Init(vaultDir, identity, cfg); initErr != nil {
		t.Fatalf("vault.Init() error = %v", initErr)
	}

	entry := &vault.Entry{
		Data: map[string]any{
			"password": "testpass",
			"totp": map[string]any{
				"secret":    "JBSWY3DPEHPK3PXP",
				"algorithm": "SHA1",
				"digits":    float64(6),
				"period":    float64(30),
			},
		},
	}
	if writeErr := vault.WriteEntry(vaultDir, "github", entry, identity); writeErr != nil {
		t.Fatalf("WriteEntry() error = %v", writeErr)
	}

	srv := &Server{
		vault: &vault.Vault{
			Dir:      vaultDir,
			Identity: identity,
		},
		agent: &config.AgentProfile{
			Name:         "restricted",
			AllowedPaths: []string{"*"},
			CanWrite:     false,
			ApprovalMode: "none",
			RedactFields: []string{"totp.secret"},
		},
	}

	getReq := CallToolRequest{
		Arguments: map[string]any{
			"path": "github",
		},
	}
	getResult, err := srv.handleGet(context.Background(), getReq)
	if err != nil {
		t.Fatalf("handleGet() error = %v", err)
	}

	var response map[string]any
	if parseErr := json.Unmarshal([]byte(getResult.Text), &response); parseErr != nil {
		t.Fatalf("parse get result: %v", parseErr)
	}

	if response["path"] != "github" {
		t.Errorf("path = %v, want github", response["path"])
	}

	totpReq := CallToolRequest{
		Arguments: map[string]any{
			"path": "github",
		},
	}
	totpResult, err := srv.handleGenerateTOTP(context.Background(), totpReq)
	if err != nil {
		t.Fatalf("handleGenerateTOTP() error = %v", err)
	}

	var codeResult map[string]any
	if err := json.Unmarshal([]byte(totpResult.Text), &codeResult); err != nil {
		t.Fatalf("parse totp result: %v", err)
	}
	if codeResult["code"] == nil || codeResult["code"] == "" {
		t.Error("generate_totp returned empty code")
	}
}

func TestHandleGetValue_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGetValue() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleGetValue() returned error: %s", result.Text)
	}

	var entry vault.Entry
	if err := json.Unmarshal([]byte(result.Text), &entry); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if entry.Data["password"] != "testpass123" {
		t.Errorf("password = %v, want testpass123", entry.Data["password"])
	}
}

func TestExecuteTool_GetEntry(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	args := json.RawMessage(`{"path": "github"}`)
	result, err := srv.executeTool(context.Background(), "get_entry", args)
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

func TestHandleGetMetadata_Success(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleGetMetadata(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetMetadata() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGetMetadata() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleGetMetadata() returned error: %s", result.Text)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(result.Text), &response); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if response["path"] != "github" {
		t.Errorf("path = %v, want github", response["path"])
	}

	meta, ok := response["meta"].(map[string]any)
	if !ok {
		t.Fatal("expected 'meta' field in response")
	}
	if meta["version"] != float64(1) {
		t.Errorf("version = %v, want 1", meta["version"])
	}
	if meta["created"] == nil || meta["created"] == "" {
		t.Error("created timestamp should be set")
	}
	if meta["updated"] == nil || meta["updated"] == "" {
		t.Error("updated timestamp should be set")
	}
}

func TestHandleGetMetadata_OutsideScope(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"work/"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	_, err := srv.handleGetMetadata(context.Background(), req)
	if err == nil {
		t.Fatal("handleGetMetadata() expected error for out-of-scope path, got nil")
	}
	if !strings.Contains(err.Error(), "outside allowed scope") {
		t.Fatalf("handleGetMetadata() error = %v, want 'outside allowed scope'", err)
	}
}

func TestHandleGetMetadata_MissingPath(t *testing.T) {
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

	result, err := srv.handleGetMetadata(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetMetadata() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGetMetadata() returned nil result")
	}
	if !result.IsError {
		t.Error("handleGetMetadata() expected error result for missing path")
	}
}

func TestHandleGetMetadata_NotFound(t *testing.T) {
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

	result, err := srv.handleGetMetadata(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetMetadata() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("handleGetMetadata() expected error result for nonexistent entry")
	}
}

func TestHandleGetMetadata_VersionIncrementedAfterUpdate(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}
	result, err := srv.handleGetMetadata(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetMetadata() initial error = %v", err)
	}

	var initialResponse map[string]any
	if unmarshalErr := json.Unmarshal([]byte(result.Text), &initialResponse); unmarshalErr != nil {
		t.Fatalf("parse initial result: %v", unmarshalErr)
	}
	initialMeta, _ := initialResponse["meta"].(map[string]any)
	initialVersion, _ := initialMeta["version"].(float64)

	setReq := CallToolRequest{
		Arguments: map[string]any{
			"path":  "github",
			"field": "password",
			"value": "StrongP@ssw0rd123",
		},
	}
	_, err = srv.handleSet(context.Background(), setReq)
	if err != nil {
		t.Fatalf("handleSet() error = %v", err)
	}

	result, err = srv.handleGetMetadata(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetMetadata() after update error = %v", err)
	}

	var updatedResponse map[string]any
	if err := json.Unmarshal([]byte(result.Text), &updatedResponse); err != nil {
		t.Fatalf("parse updated result: %v", err)
	}
	updatedMeta, _ := updatedResponse["meta"].(map[string]any)
	updatedVersion, _ := updatedMeta["version"].(float64)

	if updatedVersion <= initialVersion {
		t.Errorf("version should increment after update: initial=%v, updated=%v", initialVersion, updatedVersion)
	}
}

func hasField(slice []any, targetName string) bool {
	for _, s := range slice {
		if m, ok := s.(map[string]any); ok {
			if name, _ := m["name"].(string); name == targetName {
				return true
			}
		}
	}
	return false
}
