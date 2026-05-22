package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
	mcp "github.com/danieljustus/OpenPass/internal/mcp"
)

func TestValidateOutputPath_ValidInVault(t *testing.T) {
	vaultDir := t.TempDir()
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)

	validPath := filepath.Join(vaultDir, "test.txt")
	if err := srv.validateOutputPath(validPath); err != nil {
		t.Errorf("validateOutputPath(%q) error = %v, want nil", validPath, err)
	}
}

func TestValidateOutputPath_EscapesViaDotDot(t *testing.T) {
	vaultDir := t.TempDir()
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)

	escapedPath := filepath.Join(vaultDir, "..", "outside.txt")
	if err := srv.validateOutputPath(escapedPath); err == nil {
		t.Errorf("validateOutputPath(%q) = nil, want error", escapedPath)
	}
}

func TestValidateOutputPath_AbsoluteOutsideVault(t *testing.T) {
	vaultDir := t.TempDir()
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)

	outsidePath := "/tmp/outside.txt"
	if err := srv.validateOutputPath(outsidePath); err == nil {
		t.Errorf("validateOutputPath(%q) = nil, want error", outsidePath)
	}
}

func TestValidateOutputPath_DotDotInMiddle(t *testing.T) {
	vaultDir := t.TempDir()
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)

	escapedPath := filepath.Join(vaultDir, "subdir", "..", "..", "outside.txt")
	if err := srv.validateOutputPath(escapedPath); err == nil {
		t.Errorf("validateOutputPath(%q) = nil, want error", escapedPath)
	}
}

func TestValidateOutputPath_NoVault(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "")

	if err := srv.validateOutputPath("/tmp/test.txt"); err == nil {
		t.Error("validateOutputPath with no vault dir = nil, want error")
	}
}

func TestHandleGenerateTemplate_RespectsPathValidation(t *testing.T) {
	vaultDir := t.TempDir()
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(true),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)

	req := mcp.CallToolRequest{
		Arguments: map[string]any{
			"template_type": "app",
			"output_path":   filepath.Join(vaultDir, "..", "outside.txt"),
		},
	}

	result, err := srv.handleGenerateTemplate(context.Background(), req)
	if err != nil {
		t.Fatalf("handleGenerateTemplate() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleGenerateTemplate() returned nil result")
	}
	if !result.IsError {
		t.Fatal("handleGenerateTemplate() should have returned error for escaped path")
	}
}
