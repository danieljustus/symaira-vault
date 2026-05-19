package mcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestDebugHandleGetMetadata(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{"path": "github"},
	}

	result, err := srv.handleGetMetadata(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGetMetadata() error = %v", err)
	}
	fmt.Printf("Result Text: %s\n", result.Text)
}
