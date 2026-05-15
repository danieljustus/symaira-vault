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

func TestMergeFileOAuthConfig(t *testing.T) {
	accessTTL := 10 * time.Second
	refreshTTL := 30 * time.Second

	fileCfg := &fileMCPConfig{
		OAuth: &fileOAuthConfig{
			AccessTokenTTL:  &accessTTL,
			RefreshTokenTTL: &refreshTTL,
		},
	}

	result := MergeFileMCPConfig(fileCfg, defaultMCPConfig())

	if result.OAuth == nil {
		t.Fatal("OAuth config is nil after merge")
	}
	if result.OAuth.AccessTokenTTL != accessTTL {
		t.Errorf("AccessTokenTTL = %v, want %v", result.OAuth.AccessTokenTTL, accessTTL)
	}
	if result.OAuth.RefreshTokenTTL != refreshTTL {
		t.Errorf("RefreshTokenTTL = %v, want %v", result.OAuth.RefreshTokenTTL, refreshTTL)
	}
}

func TestMergeFileOAuthConfig_PartialOverride(t *testing.T) {
	refreshTTL := 100 * time.Hour

	fileCfg := &fileMCPConfig{
		OAuth: &fileOAuthConfig{
			RefreshTokenTTL: &refreshTTL,
		},
	}

	result := MergeFileMCPConfig(fileCfg, defaultMCPConfig())

	if result.OAuth.AccessTokenTTL != 24*time.Hour {
		t.Errorf("AccessTokenTTL = %v, want default 24h", result.OAuth.AccessTokenTTL)
	}
	if result.OAuth.RefreshTokenTTL != 100*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 100h", result.OAuth.RefreshTokenTTL)
	}
}

func TestMergeFileOAuthConfig_NilOAuth(t *testing.T) {
	fileCfg := &fileMCPConfig{}
	result := MergeFileMCPConfig(fileCfg, defaultMCPConfig())

	if result.OAuth == nil {
		t.Fatal("OAuth config should not be nil after merge with nil file cfg")
	}
	if result.OAuth.AccessTokenTTL != 24*time.Hour {
		t.Errorf("AccessTokenTTL = %v, want default 24h", result.OAuth.AccessTokenTTL)
	}
}
