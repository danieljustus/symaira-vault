package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault_SessionMaxLifetimeHasDefault(t *testing.T) {
	cfg := Default()
	if cfg.SessionMaxLifetime != defaultSessionMaxLifetime {
		t.Errorf("SessionMaxLifetime = %v, want %v", cfg.SessionMaxLifetime, defaultSessionMaxLifetime)
	}
}

func TestLoad_SessionMaxLifetimeRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("vaultDir: /tmp/test-vault\nsessionMaxLifetime: 2h\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.SessionMaxLifetime != 2*time.Hour {
		t.Errorf("SessionMaxLifetime = %v, want 2h", cfg.SessionMaxLifetime)
	}
}

func TestConfigValidate_RejectsNonPositiveSessionMaxLifetime(t *testing.T) {
	cfg := Default()
	cfg.SessionMaxLifetime = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want sessionMaxLifetime validation error")
	}
}
