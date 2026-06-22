package serverbootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/danieljustus/symaira-vault/internal/audit"
	auth "github.com/danieljustus/symaira-vault/internal/mcp/auth"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// tokenSystem bundles the token registry, the legacy fallback token and the
// audit loggers the MCP HTTP server's auth path depends on. It is produced by
// setupTokenSystem so RunHTTPServerOnListener does not have to inline token
// loading, cleanup wiring and audit-logger construction.
//
// Close releases the audit loggers; the caller owns its lifetime and must
// defer Close after a successful setup.
type tokenSystem struct {
	registry        *auth.TokenRegistry
	legacyToken     string
	cleanupAuditLog *audit.Logger
	authAuditLog    *audit.Logger
}

// Close releases the audit loggers owned by the token system. It is safe to
// call on a nil receiver and tolerates partially-initialized loggers.
func (ts *tokenSystem) Close() {
	if ts == nil {
		return
	}
	if ts.cleanupAuditLog != nil {
		_ = ts.cleanupAuditLog.Close()
	}
	if ts.authAuditLog != nil {
		_ = ts.authAuditLog.Close()
	}
}

// setupTokenSystem loads the scoped-token registry (with legacy bearer-token
// fallback), wires the registry's revoked-token retention and cleanup audit
// logging, starts the background registry cleanup + file watcher bound to ctx,
// and performs an initial cleanup pass. On any error it closes whatever it has
// already opened so the caller never has to.
func setupTokenSystem(ctx context.Context, v *vaultpkg.Vault, vaultDir string) (*tokenSystem, error) {
	tokenPath := ""
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		tf := v.Config.MCP.HTTPTokenFile
		if tf != "" && tf != "auto" {
			tokenPath = tf
		}
	}

	registry, legacyToken, err := auth.LoadTokenSystem(vaultDir, tokenPath)
	if err != nil {
		return nil, fmt.Errorf("load token system: %w", err)
	}

	// Create the cleanup audit logger before starting the cleanup goroutine so
	// the goroutine can reference it.
	cleanupAuditLog, err := audit.New("token-cleanup", vaultDir, v.Identity)
	if err != nil {
		return nil, fmt.Errorf("create token cleanup audit logger: %w", err)
	}

	if registry != nil {
		registry.SetRevokedRetention(30 * 24 * time.Hour) // 30-day retention for revoked tokens
		registry.SetCleanupLogger(func(_, tokenID, _, reason string) {
			if logErr := cleanupAuditLog.LogEntry(audit.LogEntry{
				Action:  "token_cleanup",
				Agent:   "token-cleanup",
				Reason:  reason,
				TokenID: tokenID,
				OK:      true,
			}); logErr != nil {
				cliout.Errorf("token cleanup audit log write failed: %v", logErr)
			}
		})
		_ = registry.StartCleanup(ctx, 5*time.Minute)
		// Reload the registry when the CLI creates new tokens out-of-band.
		_ = registry.StartFileWatcher(ctx, 2*time.Second)
	}

	authAuditLog, err := audit.New("auth-failures", vaultDir, v.Identity)
	if err != nil {
		_ = cleanupAuditLog.Close()
		return nil, fmt.Errorf("create auth audit logger: %w", err)
	}

	if registry != nil {
		result := registry.Cleanup()
		totalRemoved := result.ExpiredRemoved + result.RevokedRemoved
		if totalRemoved > 0 {
			_ = authAuditLog.LogEntry(audit.LogEntry{
				Agent:  "system",
				Action: "token_cleanup",
				Reason: fmt.Sprintf("removed %d expired, %d revoked (%d total)", result.ExpiredRemoved, result.RevokedRemoved, totalRemoved),
				OK:     true,
			})
		}
	}

	return &tokenSystem{
		registry:        registry,
		legacyToken:     legacyToken,
		cleanupAuditLog: cleanupAuditLog,
		authAuditLog:    authAuditLog,
	}, nil
}

// setupRateLimiter resolves the configured per-minute request limit (default
// 60; <= 0 disables rate limiting) and, when enabled, constructs the limiter
// and starts its background cleanup bound to ctx. The returned stop function is
// nil when rate limiting is disabled.
func setupRateLimiter(ctx context.Context, v *vaultpkg.Vault) (*auth.RateLimiter, func()) {
	rateLimit := 60
	var trustedProxyIPs []string
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		if v.Config.MCP.RateLimit >= 0 {
			rateLimit = v.Config.MCP.RateLimit
		}
		trustedProxyIPs = v.Config.MCP.TrustedProxyIPs
	}
	if rateLimit <= 0 {
		return nil, nil
	}
	rateLimiter := auth.NewRateLimiter(rateLimit, time.Minute, trustedProxyIPs...)
	stop := rateLimiter.StartCleanup(ctx, 5*time.Minute)
	return rateLimiter, stop
}

// httpServerTimeouts holds the resolved HTTP server timeout configuration.
type httpServerTimeouts struct {
	readHeader time.Duration
	read       time.Duration
	write      time.Duration
	shutdown   time.Duration
}

// resolveServerTimeouts returns the HTTP server timeouts, applying any positive
// overrides from the vault's MCP config over the built-in defaults.
func resolveServerTimeouts(v *vaultpkg.Vault) httpServerTimeouts {
	t := httpServerTimeouts{
		readHeader: 5 * time.Second,
		read:       10 * time.Second,
		write:      10 * time.Second,
		shutdown:   5 * time.Second,
	}
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		mcpCfg := v.Config.MCP
		if mcpCfg.ReadHeaderTimeout > 0 {
			t.readHeader = mcpCfg.ReadHeaderTimeout
		}
		if mcpCfg.ReadTimeout > 0 {
			t.read = mcpCfg.ReadTimeout
		}
		if mcpCfg.WriteTimeout > 0 {
			t.write = mcpCfg.WriteTimeout
		}
		if mcpCfg.ShutdownTimeout > 0 {
			t.shutdown = mcpCfg.ShutdownTimeout
		}
	}
	return t
}
