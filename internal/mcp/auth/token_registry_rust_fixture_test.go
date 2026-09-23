package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
)

type rustEncryptedRegistryFixture struct {
	Identity      string   `json:"identity"`
	RawToken      string   `json:"raw_token"`
	TokenID       string   `json:"token_id"`
	AgentName     string   `json:"agent_name"`
	AllowedTools  []string `json:"allowed_tools"`
	RegistryAge64 string   `json:"registry_age_base64"`
}

// TestWriteGoEncryptedRegistryRustFixture is invoked by the focused Rust
// interop test. Its output contains only a disposable generated identity and
// bearer token; callers must write it to a private temporary file.
func TestWriteGoEncryptedRegistryRustFixture(t *testing.T) {
	output := os.Getenv("SYMAIRA_GO_ENCRYPTED_REGISTRY_FIXTURE")
	if output == "" {
		t.Skip("fixture is generated only for the Rust encrypted-registry interop test")
	}
	if runtime.Version() != "go1.26.6" {
		t.Fatalf("fixture requires pinned Go 1.26.6, got %s", runtime.Version())
	}

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate fixture identity: %v", err)
	}
	allowedTools := []string{"health", "list_entries"}
	root := t.TempDir()
	registry := NewTokenRegistry(TokenRegistryFilePath(root))
	registry.SetIdentity(identity)
	token, rawToken, err := registry.Create("rust interop fixture", allowedTools, "rust-fixture-agent", 0)
	if err != nil {
		t.Fatalf("create encrypted fixture token: %v", err)
	}
	if _, err := os.Stat(TokenRegistryFilePath(root)); !os.IsNotExist(err) {
		t.Fatalf("encrypted registry unexpectedly wrote plaintext mcp-tokens.json: %v", err)
	}
	ciphertext, err := os.ReadFile(TokenRegistryEncryptedFilePath(root))
	if err != nil {
		t.Fatalf("read encrypted registry: %v", err)
	}
	if bytes.Contains(ciphertext, []byte(rawToken)) || bytes.Contains(ciphertext, []byte(identity.String())) {
		t.Fatal("encrypted registry contains plaintext token material")
	}

	fixture := rustEncryptedRegistryFixture{
		Identity:      identity.String(),
		RawToken:      rawToken,
		TokenID:       token.ID,
		AgentName:     token.AgentName,
		AllowedTools:  allowedTools,
		RegistryAge64: base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal interop fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		t.Fatalf("write private interop fixture: %v", err)
	}
}
