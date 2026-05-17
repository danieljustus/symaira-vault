package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
	"github.com/danieljustus/OpenPass/internal/vault/taint"
)

func TestHandleGetValue_ReturnsValuesForPublicEntry(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   false,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleGetValue() returned error: %s", result.Text)
	}

	var entry vault.Entry
	if err := json.Unmarshal([]byte(result.Text), &entry); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	passwordVal, _ := entry.Data["password"].(string)
	if !strings.Contains(passwordVal, "testpass123") {
		t.Errorf("password = %v, want to contain testpass123", entry.Data["password"])
	}
	usernameVal, _ := entry.Data["username"].(string)
	if !strings.Contains(usernameVal, "testuser") {
		t.Errorf("username = %v, want to contain testuser", entry.Data["username"])
	}
}

func TestHandleGetValue_SealsRestrictedClassification(t *testing.T) {
	vaultDir, identity := mockVault(t)
	restrictedEntry := &vault.Entry{
		Data:           map[string]any{"key": "supersecret"},
		Classification: taint.Restricted,
	}
	if err := vault.WriteEntry(vaultDir, "restricted-entry", restrictedEntry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   false,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "restricted-entry"},
	}

	result, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(result.Text), &resp); err != nil {
		t.Fatalf("parse result: %v", err)
	}

	class, _ := resp["classification"].(string)
	if class != "restricted" {
		t.Errorf("classification = %q, want 'restricted'", class)
	}
	if _, ok := resp["handle"]; !ok {
		t.Error("expected 'handle' in response")
	}
}

func testHandleGetValueUnsealed(t *testing.T, autoUnseal bool, classification taint.Classification, data map[string]any, entryName, wantKey, wantValue string) {
	t.Helper()
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data:           data,
		Classification: classification,
	}
	if err := vault.WriteEntry(vaultDir, entryName, entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   autoUnseal,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": entryName},
	}

	result, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}

	var got vault.Entry
	if err := json.Unmarshal([]byte(result.Text), &got); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	gotVal, _ := got.Data[wantKey].(string)
	if !strings.Contains(gotVal, wantValue) {
		t.Errorf("%s = %v, want to contain %q", wantKey, got.Data[wantKey], wantValue)
	}
}

func TestHandleGetValue_DoesNotSealWhenAutoUnsealTrue(t *testing.T) {
	testHandleGetValueUnsealed(t, true, taint.Secret, map[string]any{"password": "visible"}, "secret-entry", "password", "visible")
}

func TestHandleGetValue_DoesNotSealInternalClassification(t *testing.T) {
	testHandleGetValueUnsealed(t, false, taint.Internal, map[string]any{"key": "internal-value"}, "internal-entry", "key", "internal-value")
}

func TestSecretUnseal_ResolvesHandle(t *testing.T) {
	vaultDir, identity := mockVault(t)
	secretEntry := &vault.Entry{
		Data:           map[string]any{"password": "sealed-value"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", secretEntry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   false,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	handle := (taint.SecretHandle{Path: "secret-entry", Field: "password"}).String()

	req := CallToolRequest{
		Arguments: map[string]any{"handle": handle},
	}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleSecretUnseal() returned error: %s", result.Text)
	}
	if result.Text != "sealed-value" {
		t.Errorf("unsealed value = %q, want 'sealed-value'", result.Text)
	}
}

func TestSecretUnseal_InvalidHandle(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	req := CallToolRequest{
		Arguments: map[string]any{"handle": "invalid-handle"},
	}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if !result.IsError {
		t.Error("expected error for invalid handle")
	}
	if !strings.Contains(result.Text, "invalid handle format") {
		t.Errorf("error = %q, want 'invalid handle format'", result.Text)
	}
}

func TestSecretUnseal_MissingHandle(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	req := CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if !result.IsError {
		t.Error("expected error for missing handle")
	}
}

func TestSecretUnseal_UnknownEntry(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	handle := (taint.SecretHandle{Path: "nonexistent", Field: "password"}).String()
	req := CallToolRequest{
		Arguments: map[string]any{"handle": handle},
	}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if !result.IsError {
		t.Error("expected error for nonexistent entry")
	}
}

func TestSecretUnseal_MissingField(t *testing.T) {
	vaultDir, identity := mockVault(t)
	secretEntry := &vault.Entry{
		Data:           map[string]any{"password": "val"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", secretEntry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	handle := (taint.SecretHandle{Path: "secret-entry", Field: "nonexistent"}).String()
	req := CallToolRequest{
		Arguments: map[string]any{"handle": handle},
	}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if !result.IsError {
		t.Error("expected error for nonexistent field")
	}
}

func TestSecretUnseal_SpecificField(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data: map[string]any{
			"user": "alice",
			"key":  "abc123",
		},
	}
	if err := vault.WriteEntry(vaultDir, "multi-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	handle := (taint.SecretHandle{Path: "multi-entry", Field: "key"}).String()
	req := CallToolRequest{
		Arguments: map[string]any{"handle": handle},
	}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleSecretUnseal() returned error: %s", result.Text)
	}
	if result.Text != "abc123" {
		t.Errorf("value = %q, want 'abc123'", result.Text)
	}
}

func TestSecretUnseal_ApprovalCacheKeyFormat(t *testing.T) {
	key := approvalCacheKey("agent1", "secret_unseal", "op://path/field")
	expected := "agent1:secret_unseal:op://path/field"
	if key != expected {
		t.Errorf("cacheKey = %q, want %q", key, expected)
	}
}

func TestSecretUnseal_CachesApprovalInMemory(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data:           map[string]any{"password": "cached-test"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   false,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.approvalCache = newApprovalCache()

	handle := (taint.SecretHandle{Path: "secret-entry", Field: "password"}).String()
	cacheKey := approvalCacheKey(srv.agent.Name, "secret_unseal", handle)

	if srv.approvalCache.isRemembered(cacheKey) {
		t.Fatal("cache should be empty before first call")
	}

	srv.approvalCache.setRemembered(cacheKey)

	if !srv.approvalCache.isRemembered(cacheKey) {
		t.Error("cache should remember after setRemembered")
	}

	req := CallToolRequest{
		Arguments: map[string]any{"handle": handle},
	}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleSecretUnseal() returned error: %s", result.Text)
	}
	if result.Text != "cached-test" {
		t.Errorf("unsealed value = %q, want 'cached-test'", result.Text)
	}
}

func TestSecretsAccessed_IncrementedOnUnseal(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data:           map[string]any{"password": "val"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   false,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	before := srv.secretsAccessed.Load()

	handle := (taint.SecretHandle{Path: "secret-entry", Field: "password"}).String()
	req := CallToolRequest{
		Arguments: map[string]any{"handle": handle},
	}

	_, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}

	after := srv.secretsAccessed.Load()
	if after != before+1 {
		t.Errorf("secretsAccessed = %d, want %d", after, before+1)
	}
}

func TestSecretsAccessed_IncrementedOnGetValueUnsealed(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	secretEntry := &vault.Entry{
		Data:           map[string]any{"a": "1", "b": "2"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", secretEntry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	before := srv.secretsAccessed.Load()

	req := CallToolRequest{
		Arguments: map[string]any{"path": "secret-entry"},
	}

	_, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}

	after := srv.secretsAccessed.Load()
	expected := before + 2
	if after != expected {
		t.Errorf("secretsAccessed = %d, want %d", after, expected)
	}
}

func TestMaxSecretsInSession_BlocksUnseal(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data:           map[string]any{"password": "val"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:                "test",
		AllowedPaths:        []string{"*"},
		CanWrite:            false,
		ApprovalMode:        "none",
		AutoUnseal:          true,
		MaxSecretsInSession: 1,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	srv.secretsAccessed.Store(1)

	handle := (taint.SecretHandle{Path: "secret-entry", Field: "password"}).String()
	req := CallToolRequest{
		Arguments: map[string]any{"handle": handle},
	}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if !result.IsError {
		t.Error("expected error when max secrets exceeded")
	}
	if !strings.Contains(result.Text, "max secrets per session exceeded") {
		t.Errorf("error = %q, want 'max secrets per session exceeded'", result.Text)
	}
}

func TestMaxSecretsInSession_ZeroMeansNoLimit(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:                "test",
		AllowedPaths:        []string{"*"},
		CanWrite:            false,
		ApprovalMode:        "none",
		AutoUnseal:          true,
		MaxSecretsInSession: 0,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	srv.secretsAccessed.Store(999)

	entry := &vault.Entry{
		Data:           map[string]any{"a": "1"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	req := CallToolRequest{
		Arguments: map[string]any{"path": "secret-entry"},
	}

	result, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}
	if result.IsError {
		t.Errorf("expected success when MaxSecretsInSession=0, got error: %s", result.Text)
	}
}

func TestSecretUnseal_ToolInToolRegistry(t *testing.T) {
	defs := toolDefinitions()
	found := false
	for _, d := range defs {
		if d.Name == "secret_unseal" {
			found = true
			if d.Handler == nil {
				t.Error("secret_unseal handler is nil")
			}
		}
	}
	if !found {
		t.Error("secret_unseal not found in tool definitions")
	}
}

func TestSecretUnseal_NotBlockedByExposeValueTools(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:             "test",
		AllowedPaths:     []string{"*"},
		ExposeValueTools: false,
	}, "stdio", "")

	if isToolBlockedByAgent(srv.agent, "secret_unseal") {
		t.Error("secret_unseal should not be blocked when ExposeValueTools=false")
	}
}

func TestHandleGetValue_SealedScalesWithApprovalModeNone(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data:           map[string]any{"key": "secret-val"},
		Classification: taint.Confidential,
	}
	if err := vault.WriteEntry(vaultDir, "conf-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "conf-entry"},
	}

	result, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}

	var entry2 vault.Entry
	if err := json.Unmarshal([]byte(result.Text), &entry2); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	keyVal, _ := entry2.Data["key"].(string)
	if !strings.Contains(keyVal, "secret-val") {
		t.Errorf("key = %v, want to contain secret-val", entry2.Data["key"])
	}
}

func TestClassificationConstants(t *testing.T) {
	if taint.Public != 0 {
		t.Errorf("Public = %d, want 0", taint.Public)
	}
	if taint.Secret != 3 {
		t.Errorf("Secret = %d, want 3", taint.Secret)
	}
	if taint.Restricted != 4 {
		t.Errorf("Restricted = %d, want 4", taint.Restricted)
	}
	if taint.Confidential != 2 {
		t.Errorf("Confidential = %d, want 2", taint.Confidential)
	}
}

func TestClassificationString(t *testing.T) {
	tests := []struct {
		c    taint.Classification
		want string
	}{
		{taint.Public, "public"},
		{taint.Internal, "internal"},
		{taint.Confidential, "confidential"},
		{taint.Secret, "secret"},
		{taint.Restricted, "restricted"},
		{taint.Classification(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.c.String(); got != tt.want {
			t.Errorf("Classification(%d).String() = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestSealResponse_ContainsExpectedFields(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data:           map[string]any{"token": "abc"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   false,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "secret-entry"},
	}

	result, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal([]byte(result.Text), &resp); err != nil {
		t.Fatalf("parse result: %v", err)
	}

	handle, _ := resp["handle"].(string)
	expectedHandle := "op://secret-entry/token"
	if handle != expectedHandle {
		t.Errorf("handle = %q, want %q", handle, expectedHandle)
	}

	class, _ := resp["classification"].(string)
	if class != "secret" {
		t.Errorf("classification = %q, want 'secret'", class)
	}

	note, _ := resp["note"].(string)
	if !strings.Contains(note, "secret_unseal") {
		t.Errorf("note = %q, want to mention secret_unseal", note)
	}

	if _, ok := resp["data"]; ok {
		t.Error("sealed response should not contain 'data' field")
	}
	if _, ok := resp["meta"]; ok {
		t.Error("sealed response should not contain 'meta' field")
	}
}

func TestHandleGetValue_SealedEntryDoesNotCountSecrets(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data:           map[string]any{"a": "1", "b": "2", "c": "3"},
		Classification: taint.Secret,
	}
	if err := vault.WriteEntry(vaultDir, "secret-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:                "test",
		AllowedPaths:        []string{"*"},
		CanWrite:            false,
		ApprovalMode:        "none",
		AutoUnseal:          false,
		MaxSecretsInSession: 1,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	before := srv.secretsAccessed.Load()

	req := CallToolRequest{
		Arguments: map[string]any{"path": "secret-entry"},
	}

	result, err := srv.handleGetValue(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetValue() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("handleGetValue() returned error: %s", result.Text)
	}

	after := srv.secretsAccessed.Load()
	if after != before {
		t.Errorf("secretsAccessed changed from %d to %d (should not increment when sealed)", before, after)
	}
}

// F-5: secret_unseal previously used fmt.Sprintf("%v", val) which leaks
// Go's map/slice representation when a field is unexpectedly nested.
// For non-scalar fields the handler should return a clean error instead
// of dumping a Go-formatted map literal to the LLM.
func TestSecretUnseal_RejectsNonScalarField(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data: map[string]any{
			"nested": map[string]any{
				"secret": "JBSWY3DPEHPK3PXP",
				"issuer": "GitHub",
			},
		},
	}
	if err := vault.WriteEntry(vaultDir, "totp-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	handle := (taint.SecretHandle{Path: "totp-entry", Field: "nested"}).String()
	req := CallToolRequest{Arguments: map[string]any{"handle": handle}}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected error for non-scalar field, got value: %q", result.Text)
	}
	if strings.Contains(result.Text, "map[") {
		t.Errorf("response leaked Go map repr: %q", result.Text)
	}
	if !strings.Contains(result.Text, "scalar") && !strings.Contains(result.Text, "string") {
		t.Errorf("error should mention scalar/string type, got: %q", result.Text)
	}
}

// F-5: scalar string fields must continue to unseal unchanged.
func TestSecretUnseal_ScalarStringUnchanged(t *testing.T) {
	vaultDir, identity := mockVault(t)
	entry := &vault.Entry{
		Data: map[string]any{"password": "plain-secret-123"},
	}
	if err := vault.WriteEntry(vaultDir, "scalar-entry", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AutoUnseal:   true,
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	handle := (taint.SecretHandle{Path: "scalar-entry", Field: "password"}).String()
	req := CallToolRequest{Arguments: map[string]any{"handle": handle}}

	result, err := srv.handleSecretUnseal(context.Background(), req)
	if err != nil {
		t.Fatalf("handleSecretUnseal() error = %v", err)
	}
	if result.IsError {
		t.Fatalf("scalar unseal returned error: %s", result.Text)
	}
	if result.Text != "plain-secret-123" {
		t.Errorf("scalar unseal corrupted: %q", result.Text)
	}
}
