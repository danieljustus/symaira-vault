package config

import (
	"testing"
	"time"
)

func TestDefaultOAuthConfig(t *testing.T) {
	cfg := defaultMCPConfig()
	if cfg.OAuth == nil {
		t.Fatal("OAuth config is nil in defaults")
	}
	if cfg.OAuth.AccessTokenTTL != 24*time.Hour {
		t.Errorf("default AccessTokenTTL = %v, want 24h", cfg.OAuth.AccessTokenTTL)
	}
	if cfg.OAuth.RefreshTokenTTL != 720*time.Hour {
		t.Errorf("default RefreshTokenTTL = %v, want 720h (30d)", cfg.OAuth.RefreshTokenTTL)
	}
}

func TestMergeFromMCP_OAuthConfig(t *testing.T) {
	fileCfg := MCPConfig{
		OAuth: &OAuthConfig{
			AccessTokenTTL:  10 * time.Second,
			RefreshTokenTTL: 30 * time.Second,
		},
	}

	result := defaultMCPConfig()
	MergeFromMCP(&result, fileCfg)

	if result.OAuth == nil {
		t.Fatal("OAuth config is nil after merge")
	}
	if result.OAuth.AccessTokenTTL != 10*time.Second {
		t.Errorf("AccessTokenTTL = %v, want 10s", result.OAuth.AccessTokenTTL)
	}
	if result.OAuth.RefreshTokenTTL != 30*time.Second {
		t.Errorf("RefreshTokenTTL = %v, want 30s", result.OAuth.RefreshTokenTTL)
	}
}

func TestMergeFromMCP_OAuthPartialOverride(t *testing.T) {
	fileCfg := MCPConfig{
		OAuth: &OAuthConfig{
			RefreshTokenTTL: 100 * time.Hour,
		},
	}

	result := defaultMCPConfig()
	MergeFromMCP(&result, fileCfg)

	if result.OAuth.AccessTokenTTL != 24*time.Hour {
		t.Errorf("AccessTokenTTL = %v, want default 24h", result.OAuth.AccessTokenTTL)
	}
	if result.OAuth.RefreshTokenTTL != 100*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 100h", result.OAuth.RefreshTokenTTL)
	}
}

func TestMergeFromMCP_NilOAuth(t *testing.T) {
	fileCfg := MCPConfig{}
	result := defaultMCPConfig()
	MergeFromMCP(&result, fileCfg)

	if result.OAuth == nil {
		t.Fatal("OAuth config should not be nil after merge with nil file cfg")
	}
	if result.OAuth.AccessTokenTTL != 24*time.Hour {
		t.Errorf("AccessTokenTTL = %v, want default 24h", result.OAuth.AccessTokenTTL)
	}
}
