package server

import (
	"context"

	"github.com/danieljustus/symaira-vault/internal/crypto"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

func (s *Server) handleGenerate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	length := 16
	if v, err := req.RequireFloat("length"); err == nil {
		length = int(v)
	}
	symbols := req.GetBool("symbols", true)

	_ = s.checkScope("")

	password, cleanup, err := generatePassword(length, symbols)
	if err != nil {
		s.logAudit(ctx, "generate", "password", false)
		return nil, err
	}

	// Copy password to GC heap before clearing SecureString backing so the
	// returned result stays valid after cleanup.
	result := mcp.NewToolResultText(string(append([]byte(nil), password...)))
	cleanup()

	s.logAudit(ctx, "generate", "password", true)
	return result, nil
}

func generatePassword(length int, symbols bool) (string, func(), error) {
	return crypto.GeneratePassword(length, symbols)
}
