package mcp

import (
	"context"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestHandleHealth(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	req := CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleHealth(context.Background(), req)
	if err != nil {
		t.Fatalf("handleHealth() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleHealth() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleHealth() returned error: %s", result.Text)
	}
}
