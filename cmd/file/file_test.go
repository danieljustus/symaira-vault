package file

import (
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// setupTestVault initializes a temp vault, points the global --vault flag at
// it, and unlocks it non-interactively for the duration of the test — the
// same fixture shape cmd/crud's package uses, reimplemented here because
// cmd's helpers are unexported to that package.
func setupTestVault(t *testing.T) {
	t.Helper()

	vaultDir := t.TempDir()
	passphrase := []byte("test-passphrase")
	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, configpkg.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	t.Cleanup(vaultpkg.FlushManifestUpdates)

	origVault := cli.Vault
	var origChanged bool
	if cli.VaultFlag != nil {
		origChanged = cli.VaultFlag.Changed
	}
	cli.Vault = vaultDir
	if cli.VaultFlag != nil {
		_ = cli.VaultFlag.Value.Set(vaultDir)
		cli.VaultFlag.Changed = true
	}
	t.Cleanup(func() {
		cli.Vault = origVault
		if cli.VaultFlag != nil {
			_ = cli.VaultFlag.Value.Set(origVault)
			cli.VaultFlag.Changed = origChanged
		}
	})

	t.Setenv("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
	t.Setenv("SYMVAULT_PASSPHRASE", string(passphrase))
}

// getTestEntry re-reads an entry from the vault via a fresh WithVaultRaw call,
// so assertions observe exactly what runFileAdd persisted rather than
// in-memory state.
func getTestEntry(t *testing.T, path string) *vaultpkg.Entry {
	t.Helper()
	var got *vaultpkg.Entry
	err := cli.WithVaultRaw(func(_ *vaultpkg.Vault, vs *cli.VaultService) error {
		entry, err := vs.GetEntry(path)
		if err != nil {
			return err
		}
		got = entry
		return nil
	})
	if err != nil {
		t.Fatalf("read back entry %q: %v", path, err)
	}
	return got
}
