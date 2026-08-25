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

func TestNewFindCmd_HasURLFlag(t *testing.T) {
	cmd := newFindCmd()
	flag := cmd.Flags().Lookup("url")
	if flag == nil {
		t.Fatal("newFindCmd() missing --url flag")
	}
	if flag.Value.Type() != "string" {
		t.Errorf("url flag type = %s, want string", flag.Value.Type())
	}
}

func TestNewFindCmd_ArgsValidation(t *testing.T) {
	cmd := newFindCmd()

	// No args and no --url flag -> error
	if err := cmd.Args(cmd, []string{}); err == nil {
		t.Error("cmd.Args with 0 args and no url flag expected error, got nil")
	}

	// 1 arg and no --url flag -> ok
	if err := cmd.Args(cmd, []string{"search_query"}); err != nil {
		t.Errorf("cmd.Args with 1 arg unexpected error: %v", err)
	}

	// 0 args but --url flag set -> ok
	_ = cmd.Flags().Set("url", "github.com")
	if err := cmd.Args(cmd, []string{}); err != nil {
		t.Errorf("cmd.Args with 0 args and --url flag unexpected error: %v", err)
	}

	// 1 arg with --url flag set -> ok
	if err := cmd.Args(cmd, []string{"query"}); err != nil {
		t.Errorf("cmd.Args with 1 arg and --url flag unexpected error: %v", err)
	}

	// > 1 args -> error
	if err := cmd.Args(cmd, []string{"arg1", "arg2"}); err == nil {
		t.Error("cmd.Args with >1 args expected error, got nil")
	}
}
