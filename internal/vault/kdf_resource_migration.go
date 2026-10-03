package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
)

// Argon2ConfigNeedsResourceMigration retains historical config readability
// while classifying values which cannot be used for automatic encryption.
func Argon2ConfigNeedsResourceMigration(cfg *vaultconfig.Config) bool {
	return cfg != nil && cfg.Vault != nil &&
		(cfg.Vault.Argon2idTime > vaultcrypto.AutomaticArgon2MaxTime ||
			cfg.Vault.Argon2idMemory > vaultcrypto.AutomaticArgon2MaxMemory ||
			cfg.Vault.Argon2idThreads > vaultcrypto.AutomaticArgon2MaxThreads)
}

// MigrateKDFResourcePolicy is the explicit local historical-budget boundary.
// It does not open a vault, warm indexes, heal zero-key files or enable services.
// Each replacement is atomic; verified encrypted/config backups survive success
// and rollback. An existing different backup is never overwritten.
func MigrateKDFResourcePolicy(vaultDir string, passphrase []byte) error {
	return migrateKDFResourcePolicy(vaultDir, passphrase, fsutil.AtomicWriteFile)
}

func migrateKDFResourcePolicy(vaultDir string, passphrase []byte, replace func(string, []byte, os.FileMode) error) error {
	if err := validateVaultDir(vaultDir); err != nil {
		return err
	}
	lock, err := AcquireWriteLock(vaultDir, DefaultLockTimeout)
	if err != nil {
		return err
	}
	defer func() { _ = ReleaseLock(lock) }()
	identityPath := filepath.Join(vaultDir, "identity.age")
	original, err := SafeReadFile(identityPath)
	if err != nil {
		return fmt.Errorf("read original identity: %w", err)
	}
	identity, err := vaultcrypto.DecryptIdentityForLegacyKDFMigration(original, passphrase)
	if err != nil {
		return fmt.Errorf("unlock historical identity: %w", err)
	}
	configPath := filepath.Join(vaultDir, "config.yaml")
	configOriginal, configReplacement, err := prepareResourceMigrationConfig(configPath)
	if err != nil {
		return err
	}
	replacement, err := vaultcrypto.EncryptWithPassphraseArgon2id([]byte(identity.String()), cloneBytes(passphrase), vaultcrypto.DefaultArgon2idParams())
	if err != nil {
		return fmt.Errorf("encrypt replacement identity: %w", err)
	}
	verified, err := vaultcrypto.DecryptWithPassphraseArgon2id(replacement, cloneBytes(passphrase))
	defer vaultcrypto.Wipe(verified)
	if err != nil || string(verified) != identity.String() {
		return errors.New("verify replacement identity failed")
	}
	if backupErr := retainResourceMigrationBackup(identityPath+".bak", original); backupErr != nil {
		return backupErr
	}
	if configOriginal != nil {
		if backupErr := retainResourceMigrationBackup(configPath+".bak", configOriginal); backupErr != nil {
			return backupErr
		}
	}
	current, err := SafeReadFile(identityPath)
	if err != nil || !bytes.Equal(current, original) {
		return errors.New("identity changed during KDF migration")
	}
	if configOriginal != nil {
		currentConfig, readErr := SafeReadFile(configPath)
		if readErr != nil || !bytes.Equal(currentConfig, configOriginal) {
			return errors.New("config changed during KDF migration")
		}
	}
	if err := replace(identityPath, replacement, 0o600); err != nil {
		return fmt.Errorf("write replacement identity: %w", err)
	}
	if configReplacement != nil {
		if err := replace(configPath, configReplacement, 0o600); err != nil {
			restoreErr := replace(identityPath, original, 0o600)
			configRestoreErr := replace(configPath, configOriginal, 0o600)
			return errors.Join(fmt.Errorf("write migrated config: %w", err), restoreErr, configRestoreErr)
		}
	}
	return nil
}

func prepareResourceMigrationConfig(path string) ([]byte, []byte, error) {
	original, err := SafeReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read migration config: %w", err)
	}
	cfg, err := vaultconfig.LoadFromBytes(original)
	if err != nil {
		return nil, nil, fmt.Errorf("load migration config: %w", err)
	}
	if validationErr := cfg.Validate(); validationErr != nil {
		return nil, nil, fmt.Errorf("validate migration config: %w", validationErr)
	}
	var document map[string]any
	if parseErr := yaml.Unmarshal(original, &document); parseErr != nil {
		return nil, nil, parseErr
	}
	if document == nil {
		document = make(map[string]any)
	}
	section, exists := document["vault"]
	vault, ok := section.(map[string]any)
	if exists && section != nil && !ok {
		return nil, nil, errors.New("migration config vault must be a mapping")
	}
	if !exists || section == nil {
		vault = make(map[string]any)
		document["vault"] = vault
	}
	vault["format_version"] = 2
	vault["argon2id_time"] = vaultcrypto.DefaultArgon2idTime
	vault["argon2id_memory"] = vaultcrypto.DefaultArgon2idMemory
	vault["argon2id_threads"] = vaultcrypto.DefaultArgon2idThreads
	delete(vault, "scrypt_work_factor")
	rendered, err := yaml.Marshal(document)
	if err != nil {
		return nil, nil, err
	}
	updated, err := vaultconfig.LoadFromBytes(rendered)
	if err != nil {
		return nil, nil, err
	}
	if err := updated.Validate(); err != nil {
		return nil, nil, err
	}
	return original, rendered, nil
}

func retainResourceMigrationBackup(path string, original []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed migration backup under validated vault root
	if errors.Is(err, os.ErrExist) {
		existing, readErr := SafeReadFile(path)
		if readErr != nil || !bytes.Equal(existing, original) {
			return errors.New("existing KDF migration backup differs; preserve it before retrying")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("create migration backup: %w", err)
	}
	_, writeErr := file.Write(original)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write migration backup: %w", err)
	}
	return nil
}
