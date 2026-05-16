package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/danieljustus/OpenPass/internal/mcp"
)

func TestBuildHTTPServerConfig_DryRun(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPENPASS_VAULT", tmp)
	regPath := filepath.Join(tmp, "mcp-tokens.json")

	// Seed an existing token so the registry file exists.
	reg := mcp.NewTokenRegistry(regPath)
	if err := reg.Load(); err != nil {
		t.Fatalf("load error: %v", err)
	}
	_, _, err := reg.Create("existing", []string{"*"}, "test", 0)
	if err != nil {
		t.Fatalf("create error: %v", err)
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save error: %v", err)
	}

	initialCount := len(reg.List())

	// Build HTTP config in dry-run mode.
	config, tokenID, err := buildHTTPServerConfig(tmp, "opencode", true)
	if err != nil {
		t.Fatalf("buildHTTPServerConfig dry-run error: %v", err)
	}

	// Verify placeholder token ID.
	if tokenID != "<not-generated-dry-run>" {
		t.Fatalf("expected placeholder token ID, got %q", tokenID)
	}

	// Verify config contains placeholder token.
	headers, ok := config["headers"].(map[string]string)
	if !ok {
		t.Fatal("expected headers map in config")
	}
	if headers["Authorization"] != "Bearer <dry-run-preview-token>" {
		t.Fatalf("expected placeholder bearer token, got %q", headers["Authorization"])
	}

	// Verify no new token was created.
	regAfter := mcp.NewTokenRegistry(regPath)
	if err := regAfter.Load(); err != nil {
		t.Fatalf("load after error: %v", err)
	}
	if len(regAfter.List()) != initialCount {
		t.Fatalf("dry-run created a token: expected %d tokens, got %d", initialCount, len(regAfter.List()))
	}
}

func TestBuildHTTPServerConfig_CreatesToken(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("OPENPASS_VAULT", tmp)

	config, tokenID, err := buildHTTPServerConfig(tmp, "opencode", false)
	if err != nil {
		t.Fatalf("buildHTTPServerConfig error: %v", err)
	}

	if tokenID == "" || tokenID == "<not-generated-dry-run>" {
		t.Fatalf("expected real token ID, got %q", tokenID)
	}

	// Verify real bearer token was generated.
	headers, ok := config["headers"].(map[string]string)
	if !ok {
		t.Fatal("expected headers map in config")
	}
	auth := headers["Authorization"]
	if auth == "" || auth == "Bearer <dry-run-preview-token>" {
		t.Fatalf("expected real bearer token, got %q", auth)
	}

	// Verify token was persisted.
	regPath := filepath.Join(tmp, "mcp-tokens.json")
	if _, err := os.Stat(regPath); os.IsNotExist(err) {
		t.Fatal("expected token registry file to be created")
	}
}
