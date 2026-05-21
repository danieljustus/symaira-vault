package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/crypto"
	mcp "github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/session"
)

func (s *Server) handleGetAuthStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, _ = ctx, req
	if s == nil || s.vault == nil || s.vault.Config == nil {
		return nil, fmt.Errorf("vault config unavailable")
	}
	status := map[string]any{
		"method":           s.vault.Config.EffectiveAuthMethod(),
		"touchIDAvailable": session.BiometricAvailable(),
		"cache":            session.GetCacheStatus(),
	}
	payload, err := json.Marshal(status)
	if err != nil {
		return nil, err
	}
	return mcp.NewToolResultText(string(payload)), nil
}

func (s *Server) handleSetAuthMethod(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if !s.canManageConfig() {
		s.logAudit(ctx, "auth_config_denied", "<config>", false)
		agentName := ""
		if s != nil && s.agent != nil {
			agentName = s.agent.Name
		}
		return nil, fmt.Errorf("agent %q cannot manage OpenPass configuration", agentName)
	}
	if s == nil || s.vault == nil || s.vault.Config == nil {
		return nil, fmt.Errorf("vault config unavailable")
	}
	methodArg, err := req.RequireString("method")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	method, err := config.NormalizeAuthMethod(methodArg)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if method == config.AuthMethodTouchID {
		if !session.BiometricAvailable() {
			return mcp.NewToolResultError("Touch ID is not available in this OpenPass build or on this Mac"), nil
		}
		passphrase, err := session.LoadPassphrase(s.vault.Dir)
		if err != nil || len(passphrase) == 0 {
			return mcp.NewToolResultError("Touch ID setup requires an active OpenPass session; run openpass unlock first"), nil
		}
		defer crypto.Wipe(passphrase)
		if err := session.SaveBiometricPassphrase(ctx, s.vault.Dir, passphrase); err != nil {
			return nil, fmt.Errorf("save Touch ID unlock item: %w", err)
		}
	} else if err := session.ClearBiometricPassphrase(s.vault.Dir); err != nil {
		return nil, fmt.Errorf("clear Touch ID unlock item: %w", err)
	}

	if err := s.vault.Config.SetAuthMethod(method); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := s.vault.Config.SaveTo(filepath.Join(s.vault.Dir, "config.yaml")); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}
	s.logAudit(ctx, "auth_config", "<config>", true)
	return mcp.NewToolResultText(fmt.Sprintf("Auth method set to %s", method)), nil
}
