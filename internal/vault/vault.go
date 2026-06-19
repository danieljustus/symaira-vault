package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
	"github.com/danieljustus/symaira-vault/internal/git"
)

const vaultFormatVersion2 = 2

var (
	ErrVaultDirEmpty       = errors.New("vault directory is empty")
	ErrNilConfig           = errors.New("config is nil")
	ErrIdentityMismatch    = errors.New("identity mismatch")
	ErrVaultNotInitialized = errors.New("vault not initialized")
	ErrVaultDirEscapes     = errors.New("vault directory path escapes intended directory")
)

func validateVaultDir(vaultDir string) error {
	if fsutil.HasTraversal(vaultDir) {
		return ErrVaultDirEscapes
	}
	return nil
}

type Vault struct {
	Identity       *age.X25519Identity
	Config         *vaultconfig.Config
	Dir            string
	NeedsMigration bool
	// HealedFromZeroKey is true when OpenWithPassphrase detected that the
	// identity.age file was wrapped under the pre-#476 zero-key bug, recovered
	// the identity via RecoverZeroKeyIdentity, verified it against
	// recipients.txt, and atomically re-wrapped the file under the user's real
	// passphrase. Callers (e.g. the CLI) can use this flag to surface a
	// "your identity was wrapped under an insecure key and has been healed"
	// warning.
	HealedFromZeroKey bool

	Cache *VaultCache

	searchIdentity atomic.Pointer[age.X25519Identity]
}

// WarmSearchIndex triggers a background build of the encrypted search index.
// This eliminates cold-start latency on the first FindWithOptions call.
func (v *Vault) WarmSearchIndex() {
	if v == nil || v.Identity == nil {
		return
	}
	go func() {
		_ = globalIndex.BuildMemoryOnly(v.Dir, v.Identity)
	}()
}

func Init(vaultDir string, identity *age.X25519Identity, cfg *vaultconfig.Config) error {
	if vaultDir == "" {
		return ErrVaultDirEmpty
	}
	if identity == nil {
		return vaultcrypto.ErrNilIdentity
	}
	if cfg == nil {
		return ErrNilConfig
	}
	if err := os.MkdirAll(entriesDir(vaultDir), 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	storedCfg := *cfg
	storedCfg.VaultDir = vaultDir
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	configData, err := yaml.Marshal(&storedCfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if writeErr := fsutil.AtomicWriteFile(cfgPath, configData, 0o600); writeErr != nil {
		return fmt.Errorf("write config: %w", writeErr)
	}
	identityData := []byte(identity.String())
	ciphertext, err := vaultcrypto.Encrypt(identityData, identity.Recipient())
	if err != nil {
		return fmt.Errorf("encrypt identity: %w", err)
	}
	if err := fsutil.AtomicWriteFile(filepath.Join(vaultDir, "identity.age"), ciphertext, 0o600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}
	return nil
}

func Open(vaultDir string, identity *age.X25519Identity) (*Vault, error) {
	if vaultDir == "" {
		return nil, ErrVaultDirEmpty
	}
	if identity == nil {
		return nil, vaultcrypto.ErrNilIdentity
	}
	if err := validateVaultDir(vaultDir); err != nil {
		return nil, err
	}
	cfg, err := vaultconfig.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	normalizeConfig(cfg)
	if err := detectLegacyMode(cfg, vaultDir); err != nil {
		return nil, fmt.Errorf("detect legacy mode: %w", err)
	}
	if !isLegacyMigrationDone(vaultDir) {
		if err := migrateLegacyEntries(vaultDir); err != nil {
			return nil, fmt.Errorf("migrate legacy entries: %w", err)
		}
		markLegacyMigrationDone(vaultDir)
	}
	// Flush any pending manifest updates before checking consistency.
	FlushManifestUpdates()

	// Check manifest consistency: rebuild if missing, or if the manifest is stale
	// (config generation counter > manifest generation counter, indicating unflushed
	// writes from a prior crash).
	if _, err := os.Stat(filepath.Join(vaultDir, manifestFileName)); os.IsNotExist(err) {
		_ = RebuildManifest(vaultDir, identity) // best-effort
	} else if cfg.Vault != nil && cfg.Vault.ManifestGeneration > 0 {
		m, loadErr := LoadManifest(vaultDir, identity)
		if loadErr == nil && m.Generation < cfg.Vault.ManifestGeneration {
			_ = RebuildManifest(vaultDir, identity) // best-effort
		}
	}
	if _, err := os.Stat(filepath.Join(vaultDir, ".git")); err == nil {
		if err := git.CreateGitignore(vaultDir); err != nil {
			return nil, fmt.Errorf("update gitignore: %w", err)
		}
	}
	cache := NewVaultCache(VaultCacheConfig{})
	if cfg != nil && cfg.Vault != nil {
		if cfg.Vault.ConfigCacheEntries > 0 {
			cache.SetConfigCacheSize(cfg.Vault.ConfigCacheEntries)
		}
		if cfg.Vault.ListingCacheTTL > 0 {
			cache.SetListCacheTTL(cfg.Vault.ListingCacheTTL)
		}
	}
	v := &Vault{Dir: vaultDir, Identity: identity, Config: cfg, Cache: cache}
	v.searchIdentity.Store(identity)
	registerVaultCache(vaultDir, cache)
	v.WarmSearchIndex()
	return v, nil
}

const legacyMigrationMarker = ".symvault-migrated"

func isLegacyMigrationDone(vaultDir string) bool {
	_, err := os.Stat(filepath.Join(vaultDir, legacyMigrationMarker))
	return err == nil
}

func markLegacyMigrationDone(vaultDir string) {
	_ = os.WriteFile(filepath.Join(vaultDir, legacyMigrationMarker), nil, 0o600)
}

func OpenWithPassphrase(vaultDir string, passphrase []byte) (*Vault, error) {
	if vaultDir == "" {
		return nil, ErrVaultDirEmpty
	}
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}
	if err := validateVaultDir(vaultDir); err != nil {
		return nil, err
	}
	identityPath := filepath.Join(vaultDir, "identity.age")
	raw, err := os.ReadFile(identityPath) // #nosec G304 — identityPath constructed from validated vaultDir with a fixed filename
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	migrationPassphrase := cloneBytes(passphrase)
	format := vaultcrypto.DetectEncryptedIdentityFormat(raw)
	var identity *age.X25519Identity
	healedFromZeroKey := false
	switch format {
	case vaultcrypto.Argon2idStanzaType:
		identity, err = vaultcrypto.LoadIdentityWithArgon2id(identityPath, cloneBytes(passphrase))
		if err != nil {
			// The argon2id unwrap failed. The file may have been written under
			// the pre-#476 zero-key bug, in which case the wrap key depends
			// only on the passphrase byte length. Attempt a length-n recovery
			// and, if it yields a key present in recipients.txt, atomically
			// re-wrap the file under the real passphrase.
			identity, healedFromZeroKey, err = tryHealZeroKeyIdentity(vaultDir, identityPath, raw, passphrase)
		}
	default:
		identity, err = vaultcrypto.LoadIdentity(identityPath, cloneBytes(passphrase))
	}
	if err != nil {
		vaultcrypto.Wipe(migrationPassphrase)
		return nil, fmt.Errorf("load identity: %w", err)
	}
	v, err := Open(vaultDir, identity)
	if err != nil {
		vaultcrypto.Wipe(migrationPassphrase)
		return nil, err
	}
	v.HealedFromZeroKey = healedFromZeroKey
	// Only auto-migrate the identity KDF when the user has explicitly opted in.
	// Rewriting the master identity file in place is not something to do silently
	// on every open; vaults that don't opt in are flagged as migratable instead.
	// The trigger is the on-disk file's actual KDF, not config.FormatVersion —
	// after an identity restore the file may be scrypt while FormatVersion is
	// still 2, and we must not silently treat that as "already migrated".
	if format != vaultcrypto.Argon2idStanzaType {
		if v.Config != nil && v.Config.Vault != nil && v.Config.Vault.AutoMigrateKDF {
			_ = MigrateKDF(vaultDir, identity, migrationPassphrase, v)
		} else {
			v.NeedsMigration = true
		}
	}
	vaultcrypto.Wipe(migrationPassphrase)
	return v, nil
}

// tryHealZeroKeyIdentity attempts to recover an identity.age that was wrapped
// under the pre-#476 zero-key bug. It derives the wrap key from
// Argon2id(zeros[len(passphrase)], salt, params), verifies the recovered
// identity's public key is listed in vaultDir/recipients.txt, and on a verified
// match atomically re-wraps the file under the real passphrase. The returned
// bool is true when the on-disk file was rewritten.
//
// If the config disables auto-heal, if recipients.txt is missing, or if the
// recovered public key is not in recipients.txt, the function returns the
// recovery error so the caller sees the original load failure and the file
// stays untouched.
func tryHealZeroKeyIdentity(vaultDir, identityPath string, raw, passphrase []byte) (*age.X25519Identity, bool, error) {
	recovered, recErr := vaultcrypto.RecoverZeroKeyIdentity(raw, len(passphrase))
	if recErr != nil {
		return nil, false, recErr
	}
	verified, verifyErr := verifyRecoveryAgainstRecipients(vaultDir, recovered)
	if verifyErr != nil {
		return nil, false, fmt.Errorf("verify recovery: %w", verifyErr)
	}
	if !verified {
		return nil, false, errors.New("recovered identity not present in recipients.txt; refusing to silently re-key the vault")
	}
	if err := rewriteIdentityAtomic(identityPath, recovered, cloneBytes(passphrase)); err != nil {
		return nil, false, fmt.Errorf("atomic rewrite of healed identity: %w", err)
	}
	return recovered, true, nil
}

// MigrateKDF re-encrypts the vault identity from scrypt to argon2id. The
// caller is responsible for deciding when to call it (typically: the on-disk
// identity is scrypt, the user opted in to AutoMigrateKDF, and the file is
// ready to be rewritten). The trigger is the on-disk file's actual KDF —
// not config.FormatVersion — so a restored scrypt identity with a stale
// "format 2" config is still migrated, instead of silently treated as
// already-modern.
//
// The rewrite is safe: the existing identity.age is backed up to
// identity.age.bak, the new argon2id identity is written and then verified to
// decrypt with the same passphrase before the migration is considered
// successful. On any failure the original file is restored and NeedsMigration
// is set, so an interrupted or faulty migration never leaves the vault with an
// unreadable master key.
func MigrateKDF(vaultDir string, identity *age.X25519Identity, passphrase []byte, v *Vault) error {
	if v == nil || v.Config == nil || v.Config.Vault == nil {
		return nil
	}
	identityPath := filepath.Join(vaultDir, "identity.age")
	if err := rewriteIdentityAtomic(identityPath, identity, passphrase); err != nil {
		v.NeedsMigration = true
		return nil
	}
	v.Config.Vault.FormatVersion = vaultFormatVersion2
	v.Config.Vault.ScryptWorkFactor = 0
	if cfgPath := filepath.Join(vaultDir, "config.yaml"); cfgPath != "" {
		_ = v.Config.SaveTo(cfgPath)
	}
	// Keep the backup until the next successful unlock confirms the new file.
	return nil
}

// rewriteIdentityAtomic replaces identity.age with one freshly encrypted under
// the given passphrase. The existing file is backed up to identity.age.bak
// first, the new content is written and then verified to decrypt with the
// passphrase; on any failure the original is restored and an error is
// returned. This is the shared safety primitive used by both the scrypt→argon2id
// KDF migration and the pre-#476 zero-key identity heal.
func rewriteIdentityAtomic(identityPath string, identity *age.X25519Identity, passphrase []byte) error {
	backupPath := identityPath + ".bak"
	original, readErr := os.ReadFile(identityPath) // #nosec G304 — fixed filename under validated vaultDir
	if readErr != nil {
		return fmt.Errorf("read original identity: %w", readErr)
	}
	if err := fsutil.AtomicWriteFile(backupPath, original, 0o600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	params := vaultcrypto.DefaultArgon2idParams()
	if err := vaultcrypto.SaveIdentityWithArgon2id(identity, identityPath, cloneBytes(passphrase), params); err != nil {
		_ = restoreIdentityBackup(identityPath, backupPath, original)
		return fmt.Errorf("save new identity: %w", err)
	}
	if _, err := vaultcrypto.LoadIdentityWithArgon2id(identityPath, cloneBytes(passphrase)); err != nil {
		_ = restoreIdentityBackup(identityPath, backupPath, original)
		return fmt.Errorf("verify new identity: %w", err)
	}
	return nil
}

// verifyRecoveryAgainstRecipients returns true when the public key derived
// from the recovered identity appears in vaultDir/recipients.txt. It returns
// (false, nil) when recipients.txt is absent — recovery is rejected in that
// case because there is no independent source of truth to compare against,
// which would otherwise allow a wrong-length passphrase to silently re-key
// the vault to a typo's length-equivalent identity.
func verifyRecoveryAgainstRecipients(vaultDir string, identity *age.X25519Identity) (bool, error) {
	rm := NewRecipientsManager(vaultDir)
	if !rm.RecipientsFileExists() {
		return false, nil
	}
	recipients, err := rm.LoadRecipients()
	if err != nil {
		return false, fmt.Errorf("load recipients: %w", err)
	}
	pubKey := identity.Recipient().String()
	for _, r := range recipients {
		if r.String() == pubKey {
			return true, nil
		}
	}
	return false, nil
}

// restoreIdentityBackup puts the original identity bytes back in place after a
// failed migration attempt.
func restoreIdentityBackup(identityPath, backupPath string, original []byte) error {
	if err := fsutil.AtomicWriteFile(identityPath, original, 0o600); err != nil {
		return err
	}
	_ = os.Remove(backupPath)
	return nil
}

func OpenWithCachedIdentity(vaultDir string, identity *age.X25519Identity) (*Vault, error) {
	if vaultDir == "" {
		return nil, ErrVaultDirEmpty
	}
	if identity == nil {
		return nil, vaultcrypto.ErrNilIdentity
	}
	return Open(vaultDir, identity)
}

func InitWithPassphrase(vaultDir string, passphrase []byte, cfg *vaultconfig.Config) (*age.X25519Identity, error) {
	if vaultDir == "" {
		return nil, ErrVaultDirEmpty
	}
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}
	if cfg == nil {
		return nil, ErrNilConfig
	}
	identity, err := vaultcrypto.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}
	if mkdirErr := os.MkdirAll(entriesDir(vaultDir), 0o700); mkdirErr != nil {
		return nil, fmt.Errorf("create vault dir: %w", mkdirErr)
	}
	storedCfg := *cfg
	storedCfg.VaultDir = vaultDir
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	configData, err := yaml.Marshal(&storedCfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	if err := fsutil.AtomicWriteFile(cfgPath, configData, 0o600); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	identityPath := filepath.Join(vaultDir, "identity.age")
	if cfg.Vault != nil {
		cfg.Vault.FormatVersion = vaultFormatVersion2
		params := vaultcrypto.DefaultArgon2idParams()
		if err := vaultcrypto.SaveIdentityWithArgon2id(identity, identityPath, cloneBytes(passphrase), params); err != nil {
			return nil, fmt.Errorf("save identity with argon2id: %w", err)
		}
	} else {
		wf := 0
		if cfg.Vault != nil {
			wf = cfg.Vault.ScryptWorkFactor
		}
		if err := vaultcrypto.SaveIdentity(identity, identityPath, cloneBytes(passphrase), wf); err != nil {
			return nil, fmt.Errorf("save identity: %w", err)
		}
	}
	return identity, nil
}

func EntryPath(v *Vault, path string) string {
	if v == nil {
		return filepath.Join(entriesDirName, filepath.FromSlash(path)+".age")
	}
	return entryStoragePath(v.Dir, path, v.Identity, v.Config)
}

func EnsureDir(v *Vault, path string) error {
	if v == nil {
		return errors.New("vault is nil")
	}
	return os.MkdirAll(filepath.Dir(EntryPath(v, path)), 0o700)
}

func IsInitialized(vaultDir string) bool {
	configPath := filepath.Join(vaultDir, "config.yaml")
	identityPath := filepath.Join(vaultDir, "identity.age")
	_, configErr := os.Stat(configPath)
	_, identityErr := os.Stat(identityPath)
	return configErr == nil && identityErr == nil
}

func (v *Vault) GetRecipient() (*age.X25519Recipient, error) {
	if v == nil {
		return nil, errors.New("vault is nil")
	}
	if v.Identity == nil {
		return nil, vaultcrypto.ErrNilIdentity
	}
	return v.Identity.Recipient(), nil
}

func (v *Vault) ValidateIdentity(identity *age.X25519Identity) error {
	if v == nil {
		return errors.New("vault is nil")
	}
	if identity == nil {
		return vaultcrypto.ErrNilIdentity
	}
	if v.Identity.String() != identity.String() {
		return ErrIdentityMismatch
	}
	return nil
}

func (v *Vault) AutoCommit(message string) error {
	return v.AutoCommitPaths(message)
}

func (v *Vault) AutoCommitEntry(message, path string) error {
	if v == nil {
		return errors.New("vault is nil")
	}
	entryPath := EntryPath(v, path)
	relPath, err := filepath.Rel(v.Dir, entryPath)
	if err != nil {
		return err
	}
	return v.AutoCommitPaths(message, filepath.ToSlash(relPath))
}

func (v *Vault) AutoCommitPaths(message string, affectedPaths ...string) error {
	if v == nil {
		return errors.New("vault is nil")
	}
	commitMessage := message
	autoPush := false
	if v.Config != nil && v.Config.Git != nil {
		autoPush = v.Config.Git.AutoPush
		if commitMessage == "" && v.Config.Git.CommitTemplate != "" {
			commitMessage = v.Config.Git.CommitTemplate
		}
	}
	if commitMessage == "" {
		commitMessage = "Update from Symaira Vault"
	}
	return git.AutoCommitAndPushWithOptions(v.Dir, git.CommitOptions{
		Message:       commitMessage,
		AffectedPaths: affectedPaths,
	}, autoPush)
}

func normalizeConfig(cfg *vaultconfig.Config) {
	if cfg == nil {
		return
	}
	if cfg.Agents == nil {
		cfg.Agents = map[string]vaultconfig.AgentProfile{}
	}
	for name, profile := range cfg.Agents {
		profile.Name = name
		if profile.AllowedPaths == nil {
			profile.AllowedPaths = []string{}
		}
		cfg.Agents[name] = profile
	}
}

func detectLegacyMode(cfg *vaultconfig.Config, vaultDir string) error {
	if cfg == nil {
		return nil
	}
	if cfg.Vault != nil && cfg.Vault.LegacyMode != nil {
		return nil
	}
	hasLegacy, err := hasLegacyTopLevelAgeFiles(vaultDir)
	if err != nil {
		return err
	}
	mode := hasLegacy
	if cfg.Vault == nil {
		cfg.Vault = &vaultconfig.VaultConfig{
			LegacyMode: &mode,
		}
	} else {
		cfg.Vault.LegacyMode = &mode
	}
	return cfg.SaveTo(filepath.Join(vaultDir, "config.yaml"))
}

func hasLegacyTopLevelAgeFiles(vaultDir string) (bool, error) {
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return false, err
	}
	entriesDirAbs := filepath.Join(vaultDir, entriesDirName)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".age" { //nolint:goconst // file extension literal
			continue
		}
		if entry.Name() == "identity.age" { //nolint:goconst // filename literal
			continue
		}
		absPath := filepath.Join(vaultDir, entry.Name())
		if absPath == entriesDirAbs {
			continue
		}
		return true, nil
	}
	return false, nil
}

func cloneBytes(b []byte) []byte {
	clone := make([]byte, len(b))
	copy(clone, b)
	return clone
}

// List returns all entry paths in this vault, optionally filtered by prefix.
// Uses the vault's identity for pseudonymized listings instead of global state.
func (v *Vault) List(prefix string) ([]string, error) {
	if v == nil {
		return nil, errors.New("vault is nil")
	}
	return List(v.Dir, prefix, v.Identity)
}

// FindWithOptions searches this vault's entries using the vault's identity
// instead of global state.
func (v *Vault) FindWithOptions(query string, opts FindOptions) ([]Match, error) {
	if v == nil {
		return nil, errors.New("vault is nil")
	}
	return findWithOptionsIdentity(v.Dir, query, opts, v.Identity)
}

// ReadEntry reads a single entry from this vault using the vault's identity.
func (v *Vault) ReadEntry(path string) (*Entry, error) {
	if v == nil {
		return nil, errors.New("vault is nil")
	}
	return ReadEntry(v.Dir, path, v.Identity)
}
