package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// makeScryptVaultForMigrateTest builds a vault whose identity.age uses the
// legacy scrypt KDF. formatVersion lets a test reproduce the #684 desync
// state (identity.age still scrypt, config.yaml already claims
// format_version: 2), and autoMigrate mirrors vault.auto_migrate_kdf.
func makeScryptVaultForMigrateTest(t *testing.T, passphrase []byte, formatVersion int, autoMigrate bool) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	identity := testutil.TempIdentity(t)
	if err := cryptopkg.SaveIdentity(identity, filepath.Join(dir, "identity.age"), append([]byte(nil), passphrase...), 0); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	cfg := config.Default()
	cfg.VaultDir = dir
	cfg.Vault = &config.VaultConfig{FormatVersion: formatVersion, ScryptWorkFactor: 18, AutoMigrateKDF: autoMigrate}
	if err := cfg.SaveTo(filepath.Join(dir, "config.yaml")); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return dir
}

// makeArgon2idVaultForMigrateTest builds a vault whose identity.age is
// already argon2id, independent of config.Default()/InitWithPassphrase
// (which currently take the legacy scrypt path — see the separately filed
// follow-up). This is the fixture for "already migrated, nothing to do".
func makeArgon2idVaultForMigrateTest(t *testing.T, passphrase []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	identity := testutil.TempIdentity(t)
	params := cryptopkg.DefaultArgon2idParams()
	if err := cryptopkg.SaveIdentityWithArgon2id(identity, filepath.Join(dir, "identity.age"), append([]byte(nil), passphrase...), params); err != nil {
		t.Fatalf("SaveIdentityWithArgon2id: %v", err)
	}
	cfg := config.Default()
	cfg.VaultDir = dir
	cfg.Vault = &config.VaultConfig{FormatVersion: 2}
	if err := cfg.SaveTo(filepath.Join(dir, "config.yaml")); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return dir
}

// writeStdinPipe redirects os.Stdin to a pipe that feeds the given lines
// (each newline-terminated) and restores the original os.Stdin on cleanup.
func writeStdinPipe(t *testing.T, lines ...string) {
	t.Helper()
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })
	go func() {
		defer w.Close()
		for _, line := range lines {
			_, _ = w.Write([]byte(line))
			_, _ = w.Write([]byte("\n"))
		}
	}()
}

func runMigrateKDF(t *testing.T, vaultDir string) (stdout string, execErr error) {
	t.Helper()
	stdout = captureStdout(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "migrate", "kdf"})
		execErr = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	return stdout, execErr
}

func TestMigrateKDF_AlreadyArgon2id(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	passphrase := []byte("correct horse battery staple")
	vaultDir := makeArgon2idVaultForMigrateTest(t, passphrase)
	defer setupVaultFlag(t, vaultDir)()

	stdout, execErr := runMigrateKDF(t, vaultDir)
	if execErr != nil {
		t.Fatalf("migrate kdf failed: %v", execErr)
	}
	if !strings.Contains(stdout, "already protected with argon2id") {
		t.Errorf("stdout = %q, want argon2id-already-protected message", stdout)
	}

	raw, err := os.ReadFile(filepath.Join(vaultDir, "identity.age"))
	if err != nil {
		t.Fatalf("read identity.age: %v", err)
	}
	if got := cryptopkg.DetectEncryptedIdentityFormat(raw); got != "argon2id" {
		t.Errorf("identity.age format = %q, want unchanged argon2id", got)
	}
}

// TestMigrateKDF_ScryptAutoMigrateDisabled_ConfirmedMigration is the core
// #684 regression: with vault.auto_migrate_kdf disabled (the default),
// `symvault migrate kdf` must actually perform the migration instead of
// only reporting status.
func TestMigrateKDF_ScryptAutoMigrateDisabled_ConfirmedMigration(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	passphrase := []byte("correct horse battery staple")
	vaultDir := makeScryptVaultForMigrateTest(t, passphrase, 1, false)
	defer setupVaultFlag(t, vaultDir)()

	writeStdinPipe(t, string(passphrase), "y")

	stdout, execErr := runMigrateKDF(t, vaultDir)
	if execErr != nil {
		t.Fatalf("migrate kdf failed: %v", execErr)
	}
	if !strings.Contains(stdout, "Migrated vault identity to argon2id") {
		t.Errorf("stdout = %q, want migration success message", stdout)
	}

	raw, err := os.ReadFile(filepath.Join(vaultDir, "identity.age"))
	if err != nil {
		t.Fatalf("read identity.age: %v", err)
	}
	if got := cryptopkg.DetectEncryptedIdentityFormat(raw); got != "argon2id" {
		t.Errorf("identity.age format = %q, want argon2id after migration", got)
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "identity.age.bak")); err != nil {
		t.Errorf("expected identity.age.bak backup, stat error: %v", err)
	}

	cfg, err := config.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Vault.FormatVersion != 2 {
		t.Errorf("FormatVersion = %d, want 2", cfg.Vault.FormatVersion)
	}
	// scrypt_work_factor is now inert for an argon2id vault (the #683 fix
	// skips that check entirely once identity.age is argon2id), but
	// MigrateKDF should still clear it from the on-disk YAML rather than
	// leaving a stale 18 sitting next to an argon2id identity. omitempty
	// means a reload can't distinguish "explicitly 0" from "never set", so
	// assert against the raw bytes instead of a reloaded Config.
	rawCfg, err := os.ReadFile(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	if strings.Contains(string(rawCfg), "scrypt_work_factor") {
		t.Errorf("config.yaml still contains scrypt_work_factor after migration: %s", rawCfg)
	}

	// The identity must still decrypt with the original passphrase.
	v, err := vaultpkg.OpenWithPassphrase(vaultDir, append([]byte(nil), passphrase...))
	if err != nil {
		t.Fatalf("migrated identity does not open with original passphrase: %v", err)
	}
	if v.NeedsMigration {
		t.Error("NeedsMigration should be false after a completed migration")
	}
}

func TestMigrateKDF_ScryptDeclinedConfirmation_LeavesIdentityUnchanged(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	passphrase := []byte("correct horse battery staple")
	vaultDir := makeScryptVaultForMigrateTest(t, passphrase, 1, false)
	defer setupVaultFlag(t, vaultDir)()

	writeStdinPipe(t, string(passphrase), "n")

	_, execErr := runMigrateKDF(t, vaultDir)
	if execErr != nil {
		t.Fatalf("migrate kdf failed: %v", execErr)
	}

	raw, err := os.ReadFile(filepath.Join(vaultDir, "identity.age"))
	if err != nil {
		t.Fatalf("read identity.age: %v", err)
	}
	if got := cryptopkg.DetectEncryptedIdentityFormat(raw); got != "scrypt" {
		t.Errorf("identity.age format = %q, want unchanged scrypt after declining", got)
	}
	if _, statErr := os.Stat(filepath.Join(vaultDir, "identity.age.bak")); !os.IsNotExist(statErr) {
		t.Errorf("expected no identity.age.bak backup after declining, stat error: %v", statErr)
	}
}

// TestMigrateKDF_ScryptAutoMigrateEnabled_MigratesOnUnlock covers the other
// half of #684's "tests decken deaktivierte und aktivierte Auto-Migration
// ab": with auto_migrate_kdf enabled, unlocking inside the command already
// performs the migration, and the command must report that accurately
// instead of asking for a confirmation the unlock already acted on.
func TestMigrateKDF_ScryptAutoMigrateEnabled_MigratesOnUnlock(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	passphrase := []byte("correct horse battery staple")
	vaultDir := makeScryptVaultForMigrateTest(t, passphrase, 1, true)
	defer setupVaultFlag(t, vaultDir)()

	writeStdinPipe(t, string(passphrase))

	stdout, execErr := runMigrateKDF(t, vaultDir)
	if execErr != nil {
		t.Fatalf("migrate kdf failed: %v", execErr)
	}
	if !strings.Contains(stdout, "Migrated automatically on unlock") {
		t.Errorf("stdout = %q, want auto-migrate-on-unlock message", stdout)
	}

	raw, err := os.ReadFile(filepath.Join(vaultDir, "identity.age"))
	if err != nil {
		t.Fatalf("read identity.age: %v", err)
	}
	if got := cryptopkg.DetectEncryptedIdentityFormat(raw); got != "argon2id" {
		t.Errorf("identity.age format = %q, want argon2id", got)
	}
}

// TestMigrateKDF_DesyncScryptFileWithStaleFormatVersion2 covers #684's
// "restaurierte scrypt-Datei mit Format v2" case: config.yaml already
// claims format_version: 2 while identity.age is still scrypt (e.g. after
// restoring an old identity file). The command must trust the on-disk file,
// not the stale config value, and reconcile them.
func TestMigrateKDF_DesyncScryptFileWithStaleFormatVersion2(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	passphrase := []byte("correct horse battery staple")
	vaultDir := makeScryptVaultForMigrateTest(t, passphrase, 2, false)
	defer setupVaultFlag(t, vaultDir)()

	writeStdinPipe(t, string(passphrase), "y")

	stdout, execErr := runMigrateKDF(t, vaultDir)
	if execErr != nil {
		t.Fatalf("migrate kdf failed: %v", execErr)
	}
	if !strings.Contains(stdout, "currently protected with scrypt") {
		t.Errorf("stdout = %q, want the command to detect scrypt from the file despite format_version: 2", stdout)
	}

	raw, err := os.ReadFile(filepath.Join(vaultDir, "identity.age"))
	if err != nil {
		t.Fatalf("read identity.age: %v", err)
	}
	if got := cryptopkg.DetectEncryptedIdentityFormat(raw); got != "argon2id" {
		t.Errorf("identity.age format = %q, want argon2id after reconciling the desync", got)
	}
}
