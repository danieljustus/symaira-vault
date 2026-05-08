// Package mcp implements the Model Context Protocol (MCP) server for OpenPass.
// It provides AI agent integration via stdio and HTTP transports with
// configurable access control, audit logging, and vault operations.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/policy"
	"github.com/danieljustus/OpenPass/internal/vault"
)

const (
	defaultServerName    = "OpenPass MCP"
	defaultServerVersion = "1.0.0"
)

// Server provides the MCP server functionality for OpenPass.
// It handles agent authentication, vault access, and tool execution.
type Server struct {
	vault        *vault.Vault
	agent        *config.AgentProfile
	auditLog     *audit.Logger
	transport    string
	policyEngine *policy.Engine
	shareStore   *ShareStore
}

// New creates a new MCP server instance with the specified vault and agent configuration.
func New(v *vault.Vault, agentName string, transport string) (*Server, error) {
	if v == nil {
		return nil, errors.New("nil vault")
	}

	cfg := v.Config
	if cfg == nil {
		if v.Dir == "" {
			return nil, errors.New("vault config unavailable")
		}
		loaded, err := config.Load(filepath.Join(v.Dir, "config.yaml"))
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
		cfg = loaded
	}

	if agentName == "" {
		agentName = cfg.DefaultAgent
	}

	agent, ok := cfg.Agents[agentName]
	if !ok {
		return nil, fmt.Errorf("agent %q not found", agentName)
	}
	agent.Name = agentName

	if cfg.Audit != nil {
		audit.SetConfig(&audit.Config{
			MaxFileSize: cfg.Audit.MaxFileSize,
			MaxBackups:  cfg.Audit.MaxBackups,
			MaxAgeDays:  cfg.Audit.MaxAgeDays,
		})
	}

	auditLog, err := audit.New(agentName, v.Dir)
	if err != nil {
		return nil, err
	}

	// Load policy engine
	policyDir := policy.DefaultPolicyDir()
	var policyEngine *policy.Engine
	if policyDir != "" {
		policies, loadErr := policy.LoadPoliciesFromDir(policyDir)
		if loadErr == nil && len(policies) > 0 {
			policyEngine = policy.NewEngine(policies)
		}
	}

	return &Server{
		vault:        v,
		agent:        &agent,
		auditLog:     auditLog,
		transport:    transport,
		policyEngine: policyEngine,
	}, nil
}

// ServeStdio runs the MCP server using stdio transport.
func (s *Server) ServeStdio(ctx context.Context) error {
	transport := NewStdioTransport()
	handler := NewProtocolHandler("OpenPass", "1.0.0", s)
	return transport.Start(ctx, handler.HandleMessage)
}

// Close shuts down the server and closes the audit log.
func (s *Server) Close() error {
	if s == nil || s.auditLog == nil {
		return nil
	}
	return s.auditLog.Close()
}
