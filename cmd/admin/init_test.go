package admin

import (
	"os"
	"path/filepath"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
)

// TestInit_NewVaultUsesArgon2id reproduces the real `symvault init` CLI path
// end-to-end and asserts the resulting identity.age is argon2id, as documented
// by `migrate kdf` ("New vaults already use argon2id.") and the doctor hint
// in internal/health/doctor_crypto.go.
func TestInit_NewVaultUsesArgon2id(t *testing.T) {
	vaultDir := filepath.Join(t.TempDir(), "vault")
	passphrase := "test-passphrase-1234"

	cli.SetCachedEnvPassphrase([]byte(passphrase))
	t.Cleanup(cli.ClearCachedEnvPassphrase)

	cmd := cli.RootCmd
	cmd.SetArgs([]string{"init", vaultDir, "--auth", "passphrase"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(vaultDir, "identity.age"))
	if err != nil {
		t.Fatalf("read identity.age: %v", err)
	}
	if format := cryptopkg.DetectEncryptedIdentityFormat(raw); format != "argon2id" {
		t.Errorf("new vault identity.age format = %q, want argon2id", format)
	}
}
