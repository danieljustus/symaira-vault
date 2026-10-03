package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

func legacyResourceFixture(t *testing.T) (string, []byte, []byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/port/crypto/kdf-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Passphrase string `json:"passphrase"`
		Cases      []struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	original, err := base64.StdEncoding.DecodeString(fixture.Cases[0].Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	config := []byte("vault:\n  format_version: 2\n  argon2id_time: 5\n  argon2id_memory: 65536\n  argon2id_threads: 4\n  auto_heal_zero_key: true\n  custom: retained\nroot_unknown: [true, 7]\n")
	for name, data := range map[string][]byte{"identity.age": original, "config.yaml": config} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, []byte(fixture.Passphrase), original, config
}

func TestKDFPolicyMigrationVerifiesIdentityAndRetainsBothBackups(t *testing.T) {
	root, passphrase, original, config := legacyResourceFixture(t)
	if _, err := OpenWithPassphrase(root, cloneBytes(passphrase)); !errors.Is(err, vaultcrypto.ErrArgon2Policy) {
		t.Fatalf("automatic open entered recovery: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "identity.age.bak")); !os.IsNotExist(err) {
		t.Fatal("automatic resource rejection mutated identity")
	}
	if err := MigrateKDFResourcePolicy(root, passphrase); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{"identity.age.bak": original, "config.yaml.bak": config} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s backup changed: %v", name, err)
		}
	}
	migrated, err := os.ReadFile(filepath.Join(root, "identity.age"))
	if err != nil {
		t.Fatal(err)
	}
	if needs, err := vaultcrypto.InspectArgon2idPolicy(migrated); err != nil || needs {
		t.Fatalf("replacement remains outside policy: %v", err)
	}
	if _, err := vaultcrypto.LoadIdentityWithArgon2id(filepath.Join(root, "identity.age"), cloneBytes(passphrase)); err != nil {
		t.Fatal(err)
	}
	rendered, err := os.ReadFile(filepath.Join(root, "config.yaml"))
	if err != nil || !bytes.Contains(rendered, []byte("custom: retained")) || !bytes.Contains(rendered, []byte("root_unknown:")) || !bytes.Contains(rendered, []byte("argon2id_time: 3")) {
		t.Fatalf("migration lost unknown config or retained expensive writes: %v", err)
	}
}

func TestKDFPolicyMigrationWrongPassphraseAndExistingBackupLeaveFilesIntact(t *testing.T) {
	root, passphrase, original, config := legacyResourceFixture(t)
	if err := MigrateKDFResourcePolicy(root, []byte("wrong public fixture")); !errors.Is(err, vaultcrypto.ErrDecryptionFailed) {
		t.Fatalf("wrong passphrase accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "identity.age.bak")); !os.IsNotExist(err) {
		t.Fatal("wrong passphrase created backup")
	}
	backup := []byte("earlier retained backup")
	if err := os.WriteFile(filepath.Join(root, "identity.age.bak"), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateKDFResourcePolicy(root, passphrase); err == nil {
		t.Fatal("existing different backup was overwritten")
	}
	for name, want := range map[string][]byte{"identity.age": original, "config.yaml": config, "identity.age.bak": backup} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s changed after rejection: %v", name, err)
		}
	}
}

func TestKDFPolicyMigrationRollsBackAfterConfigReplacementFailure(t *testing.T) {
	root, passphrase, original, config := legacyResourceFixture(t)
	configPath := filepath.Join(root, "config.yaml")
	failed := false
	injected := errors.New("injected post-replacement config failure")
	replace := func(path string, data []byte, mode os.FileMode) error {
		if err := fsutil.AtomicWriteFile(path, data, mode); err != nil {
			return err
		}
		if path == configPath && !failed {
			failed = true
			return injected
		}
		return nil
	}
	if err := migrateKDFResourcePolicy(root, passphrase, replace); !errors.Is(err, injected) {
		t.Fatalf("injected replacement failure was hidden: %v", err)
	}
	for name, want := range map[string][]byte{"identity.age": original, "config.yaml": config, "identity.age.bak": original, "config.yaml.bak": config} {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s rollback failed: %v", name, err)
		}
	}
}

func TestKDFPolicyMigrationAcceptsNullVaultConfig(t *testing.T) {
	root, passphrase, _, _ := legacyResourceFixture(t)
	config := []byte("vault: null\ncustom: retained\n")
	if err := os.WriteFile(filepath.Join(root, "config.yaml"), config, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateKDFResourcePolicy(root, passphrase); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(filepath.Join(root, "config.yaml.bak"))
	if err != nil || !bytes.Equal(backup, config) {
		t.Fatalf("backup changed: %v", err)
	}
	rendered, err := os.ReadFile(filepath.Join(root, "config.yaml"))
	if err != nil || !bytes.Contains(rendered, []byte("custom: retained")) || !bytes.Contains(rendered, []byte("argon2id_time: 3")) {
		t.Fatalf("null config migration failed: %v", err)
	}
}
