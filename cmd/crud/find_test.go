package crud

import (
	"testing"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestSearchWorkersUsesVaultDefault(t *testing.T) {
	got := searchWorkers(nil)
	want := vaultpkg.SearchWorkerCount(0)
	if got != want {
		t.Fatalf("searchWorkers(nil) = %d, want %d", got, want)
	}
}

func TestSearchWorkersUsesConfiguredValue(t *testing.T) {
	cfg := &configpkg.Config{
		Vault: &configpkg.VaultConfig{SearchWorkers: 12},
	}

	got := searchWorkers(cfg)
	if got != 12 {
		t.Fatalf("searchWorkers(configured) = %d, want 12", got)
	}
}
