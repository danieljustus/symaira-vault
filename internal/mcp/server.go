// Package mcp implements the Model Context Protocol (MCP) server for OpenPass.
// It provides AI agent integration via stdio and HTTP transports with
// configurable access control, audit logging, and vault operations.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/policy"
	"github.com/danieljustus/OpenPass/internal/vault"
)

// approvalCache provides a session-level cache for remembered approvals.
type approvalCache struct {
	mu    sync.Mutex
	cache map[string]bool
}

func newApprovalCache() *approvalCache {
	return &approvalCache{cache: make(map[string]bool)}
}

func (c *approvalCache) isRemembered(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache[key]
}

func (c *approvalCache) setRemembered(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = true
}

// cacheKey builds a unique key for the approval cache.
func approvalCacheKey(agentID, toolName, entryPath string) string {
	return agentID + ":" + toolName + ":" + entryPath
}

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

	approvalCache      *approvalCache
	approvalKeyCounter atomic.Int64
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
		vault:         v,
		agent:         &agent,
		auditLog:      auditLog,
		transport:     transport,
		policyEngine:  policyEngine,
		approvalCache: newApprovalCache(),
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
