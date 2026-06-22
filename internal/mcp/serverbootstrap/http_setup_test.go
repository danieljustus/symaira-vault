package serverbootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestResolveServerTimeouts_Defaults(t *testing.T) {
	// nil vault and empty MCP config both fall back to the built-in defaults.
	for name, v := range map[string]*vaultpkg.Vault{
		"nil vault":      nil,
		"empty mcp cfg":  {Config: &config.Config{MCP: &config.MCPConfig{}}},
		"nil mcp config": {Config: &config.Config{}},
	} {
		t.Run(name, func(t *testing.T) {
			got := resolveServerTimeouts(v)
			want := httpServerTimeouts{
				readHeader: 5 * time.Second,
				read:       10 * time.Second,
				write:      10 * time.Second,
				shutdown:   5 * time.Second,
			}
			if got != want {
				t.Fatalf("resolveServerTimeouts() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestResolveServerTimeouts_Overrides(t *testing.T) {
	v := &vaultpkg.Vault{Config: &config.Config{MCP: &config.MCPConfig{
		ReadHeaderTimeout: 1 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      3 * time.Second,
		ShutdownTimeout:   4 * time.Second,
	}}}
	got := resolveServerTimeouts(v)
	want := httpServerTimeouts{
		readHeader: 1 * time.Second,
		read:       2 * time.Second,
		write:      3 * time.Second,
		shutdown:   4 * time.Second,
	}
	if got != want {
		t.Fatalf("resolveServerTimeouts() = %+v, want %+v", got, want)
	}
}

func TestResolveServerTimeouts_PartialOverrideKeepsDefaults(t *testing.T) {
	// A single positive override must not reset the other fields to zero.
	v := &vaultpkg.Vault{Config: &config.Config{MCP: &config.MCPConfig{ReadTimeout: 30 * time.Second}}}
	got := resolveServerTimeouts(v)
	if got.read != 30*time.Second {
		t.Fatalf("read timeout = %v, want 30s", got.read)
	}
	if got.readHeader != 5*time.Second || got.write != 10*time.Second || got.shutdown != 5*time.Second {
		t.Fatalf("non-overridden timeouts changed: %+v", got)
	}
}

func TestSetupRateLimiter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	t.Run("default enabled", func(t *testing.T) {
		rl, stop := setupRateLimiter(ctx, nil)
		if rl == nil {
			t.Fatal("expected a rate limiter for the default config, got nil")
		}
		if stop == nil {
			t.Fatal("expected a non-nil stop function when rate limiting is enabled")
		}
		stop()
		_ = rl.Close()
	})

	t.Run("disabled when limit is zero", func(t *testing.T) {
		v := &vaultpkg.Vault{Config: &config.Config{MCP: &config.MCPConfig{RateLimit: 0}}}
		rl, stop := setupRateLimiter(ctx, v)
		if rl != nil || stop != nil {
			t.Fatalf("expected (nil, nil) when rate limit is 0, got rl!=nil=%t stop!=nil=%t", rl != nil, stop != nil)
		}
	})

	t.Run("custom positive limit enabled", func(t *testing.T) {
		v := &vaultpkg.Vault{Config: &config.Config{MCP: &config.MCPConfig{RateLimit: 120}}}
		rl, stop := setupRateLimiter(ctx, v)
		if rl == nil || stop == nil {
			t.Fatalf("expected an enabled limiter for RateLimit=120, got rl!=nil=%t stop!=nil=%t", rl != nil, stop != nil)
		}
		stop()
		_ = rl.Close()
	})
}

func TestSetupTokenSystem(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	v := newTestVault(t)
	ts, err := setupTokenSystem(ctx, v, v.Dir)
	if err != nil {
		t.Fatalf("setupTokenSystem() error = %v", err)
	}
	if ts == nil {
		t.Fatal("setupTokenSystem() returned nil token system without error")
	}
	t.Cleanup(ts.Close)

	if ts.registry == nil {
		t.Error("expected a non-nil token registry")
	}
	if ts.authAuditLog == nil {
		t.Error("expected a non-nil auth audit logger")
	}
	if ts.cleanupAuditLog == nil {
		t.Error("expected a non-nil cleanup audit logger")
	}
	// The pre-seeded legacy mcp-token is migrated into the registry and also
	// returned as the legacy fallback.
	if ts.legacyToken == "" {
		t.Error("expected the migrated legacy token to be returned")
	}
}

func TestTokenSystemCloseNilSafe(t *testing.T) {
	var ts *tokenSystem
	ts.Close() // must not panic on a nil receiver

	// A partially-initialized token system (no auth logger) must also be safe.
	(&tokenSystem{}).Close()
}
