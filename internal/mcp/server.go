// Package mcp implements the Model Context Protocol (MCP) server for OpenPass.
// It provides AI agent integration via stdio and HTTP transports with
// configurable access control, audit logging, and vault operations.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/danieljustus/OpenPass/internal/anomaly"
	"github.com/danieljustus/OpenPass/internal/audit"
	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/notify"
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

// cacheKey builds a unique key for the approval cache. Vault paths are
// normalized so that equivalent representations (trailing slash, dot
// segments, surrounding whitespace) collapse to the same key. Without
// this, an adversarial agent could vary the path form to bypass a
// remembered approval and force repeated prompts.
//
// Secret handles (e.g. "op://path/field") are kept verbatim — they use
// a URI-like scheme that filepath.Clean would corrupt by collapsing the
// double slash.
func approvalCacheKey(agentID, toolName, entryPath string) string {
	key := entryPath
	if !strings.Contains(entryPath, "://") {
		key = normalizeScopePath(entryPath)
	}
	return agentID + ":" + toolName + ":" + key
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
	secretsAccessed    atomic.Int64

	hookRegistry    *HookRegistry
	sessionID       string
	anomalyDetector *anomaly.AnomalyDetector
}

// SessionID returns the server's unique session identifier.
func (s *Server) SessionID() string {
	if s == nil {
		return ""
	}
	return s.sessionID
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

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}

	detector := anomaly.New(
		anomaly.WithAlertHook(func(alert anomaly.AnomalyAlert) {
			slog.Default().Warn("anomaly detected",
				"type", alert.Type,
				"severity", alert.Severity.String(),
				"agent", alert.Agent,
				"description", alert.Description,
			)
			notify.AlertNotify("Anomaly Detected: "+string(alert.Type), alert.Description)
		}),
	)

	srv := &Server{
		vault:           v,
		agent:           &agent,
		auditLog:        auditLog,
		transport:       transport,
		policyEngine:    policyEngine,
		approvalCache:   newApprovalCache(),
		hookRegistry:    NewHookRegistry(),
		sessionID:       sessionID,
		anomalyDetector: detector,
	}

	// Register hooks specified in the agent's config profile
	srv.registerConfigHooks(cfg)

	return srv, nil
}

// RegisterPreCallHook registers a pre-call hook on the server's hook registry.
func (s *Server) RegisterPreCallHook(hook PreCallHook) {
	if s == nil || s.hookRegistry == nil {
		return
	}
	s.hookRegistry.RegisterPreCallHook(hook)
}

// RegisterPostCallHook registers a post-call hook on the server's hook registry.
func (s *Server) RegisterPostCallHook(hook PostCallHook) {
	if s == nil || s.hookRegistry == nil {
		return
	}
	s.hookRegistry.RegisterPostCallHook(hook)
}

// registerConfigHooks reads the agent's PreCallHooks and PostCallHooks config
// and registers the corresponding built-in hook implementations.
func (s *Server) registerConfigHooks(cfg *config.Config) {
	if s == nil || s.agent == nil {
		return
	}

	rateLimit := 60
	if cfg != nil && cfg.MCP != nil && cfg.MCP.RateLimit > 0 {
		rateLimit = cfg.MCP.RateLimit
	}

	for _, name := range s.agent.PreCallHooks {
		switch name {
		case "audit":
			s.RegisterPreCallHook(NewAuditPreHook())
		case "rate_limit":
			s.RegisterPreCallHook(NewRateLimitPreHook(rateLimit))
		case "scope_check":
			s.RegisterPreCallHook(NewScopeCheckPreHook())
		case "metrics":
			s.RegisterPreCallHook(NewMetricsPreHook())
		}
	}

	for _, name := range s.agent.PostCallHooks {
		switch name {
		case "audit":
			s.RegisterPostCallHook(NewAuditPostHook())
		case "notification":
			s.RegisterPostCallHook(NewNotificationPostHook())
		case "metrics":
			s.RegisterPostCallHook(NewMetricsPostHook())
		}
	}
}

// ServeStdio runs the MCP server using stdio transport.
func (s *Server) ServeStdio(ctx context.Context) error {
	transport := NewStdioTransport()
	handler := NewProtocolHandler("OpenPass", "1.0.0", s)
	return transport.Start(ctx, handler.HandleMessage)
}

// generateSessionID creates a unique session identifier using crypto/rand.
func generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateRequestID creates a unique request identifier.
func generateRequestID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// invalidateApprovalCache clears all remembered approvals for the current session.
// This is called when an anomaly is detected to force re-approval on subsequent operations.
func (s *Server) invalidateApprovalCache() {
	if s == nil || s.approvalCache == nil {
		return
	}
	s.approvalCache.mu.Lock()
	s.approvalCache.cache = make(map[string]bool)
	s.approvalCache.mu.Unlock()
}

// Close shuts down the server and closes the audit log.
func (s *Server) Close() error {
	if s == nil || s.auditLog == nil {
		return nil
	}
	return s.auditLog.Close()
}
