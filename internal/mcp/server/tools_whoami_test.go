package server

import (
	"encoding/json"
	"testing"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

func TestHandleWhoami_VaultDir(t *testing.T) {
	srv := setupTestServer(t)

	result, err := srv.handleWhoami(t.Context(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handleWhoami() error = %v", err)
	}

	var info whoamiInfo
	if unmarshalErr := json.Unmarshal([]byte(result.Text), &info); unmarshalErr != nil {
		t.Fatalf("unmarshal whoami result: %v", unmarshalErr)
	}

	if info.Vault.Dir != srv.vault.Dir {
		t.Errorf("Vault.Dir = %q, want %q", info.Vault.Dir, srv.vault.Dir)
	}
	if info.Vault.Dir == "" {
		t.Error("Vault.Dir should not be empty")
	}
}
