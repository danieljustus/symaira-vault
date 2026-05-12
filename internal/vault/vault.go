package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	vaultconfig "github.com/danieljustus/OpenPass/internal/config"
	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/fileutil"
	"github.com/danieljustus/OpenPass/internal/git"
	"github.com/danieljustus/OpenPass/internal/pathutil"
)

// Common vault errors
var (
	ErrVaultDirEmpty       = errors.New("vault directory is empty")
	ErrNilIdentity         = errors.New("identity is nil")
	ErrNilConfig           = errors.New("config is nil")
	ErrIdentityMismatch    = errors.New("identity mismatch")
	ErrVaultNotInitialized = errors.New("vault not initialized")
	ErrVaultDirEscapes     = errors.New("vault directory path escapes intended directory")
)

// validateVaultDir ensures the vault directory path stays within expected bounds.
func validateVaultDir(vaultDir string) error {
	if pathutil.HasTraversal(vaultDir) {
		return ErrVaultDirEscapes
	}
	return nil
}

// Vault represents an encrypted password vault
type Vault struct {
	Identity *age.X25519Identity
	Config   *vaultconfig.Config
	Dir      string
}

// Init initializes a new vault at the given directory with the provided identity and config.
// It creates the vault directory, config file, and encrypted identity file.
func Init(vaultDir string, identity *age.X25519Identity, cfg *vaultconfig.Config) error {
	if vaultDir == "" {
		return ErrVaultDirEmpty
	}
	if identity == nil {
		return ErrNilIdentity
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
	if writeErr := fileutil.AtomicWriteFile(cfgPath, configData, 0o600); writeErr != nil {
		return fmt.Errorf("write config: %w", writeErr)
	}

	identityData := []byte(identity.String())
	ciphertext, err := vaultcrypto.Encrypt(identityData, identity.Recipient())
	if err != nil {
		return fmt.Errorf("encrypt identity: %w", err)
	}
	if err := fileutil.AtomicWriteFile(filepath.Join(vaultDir, "identity.age"), ciphertext, 0o600); err != nil {
		return fmt.Errorf("write identity: %w", err)
	}

	return nil
}

// Open opens an existing vault at the given directory with the provided identity.
// It verifies the identity matches the stored encrypted identity.
func Open(vaultDir string, identity *age.X25519Identity) (*Vault, error) {
	if vaultDir == "" {
		return nil, ErrVaultDirEmpty
	}
	if identity == nil {
		return nil, ErrNilIdentity
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
	rememberSearchIdentity(identity)
	if err := migrateLegacyEntries(vaultDir); err != nil {
		return nil, fmt.Errorf("migrate legacy entries: %w", err)
	}
	if _, err := os.Stat(filepath.Join(vaultDir, ".git")); err == nil {
		if err := git.CreateGitignore(vaultDir); err != nil {
			return nil, fmt.Errorf("update gitignore: %w", err)
		}
	}

	return &Vault{Dir: vaultDir, Identity: identity, Config: cfg}, nil
}

// OpenWithPassphrase opens a vault using a passphrase-protected identity file.
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
	identity, err := vaultcrypto.LoadIdentity(identityPath, cloneBytes(passphrase))
	if err != nil {
		return nil, fmt.Errorf("load identity: %w", err)
	}

	return Open(vaultDir, identity)
}

// OpenWithCachedIdentity opens a vault directly from an X25519 identity, skipping
// the scrypt KDF. This is the fast path when identity is cached in the OS keyring.
func OpenWithCachedIdentity(vaultDir string, identity *age.X25519Identity) (*Vault, error) {
	if vaultDir == "" {
		return nil, ErrVaultDirEmpty
	}
	if identity == nil {
		return nil, ErrNilIdentity
	}
	return Open(vaultDir, identity)
}

// InitWithPassphrase initializes a new vault with a passphrase-protected identity.
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
	if err := fileutil.AtomicWriteFile(cfgPath, configData, 0o600); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	identityPath := filepath.Join(vaultDir, "identity.age")
	wf := 0
	if cfg.Vault != nil {
		wf = cfg.Vault.ScryptWorkFactor
	}
	if err := vaultcrypto.SaveIdentity(identity, identityPath, cloneBytes(passphrase), wf); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}

	return identity, nil
}

// EntryPath returns the full file path for a vault entry
func EntryPath(v *Vault, path string) string {
	if v == nil {
		return filepath.Join(entriesDirName, filepath.FromSlash(path)+".age")
	}
	return entryStoragePath(v.Dir, path, v.Identity, v.Config)
}

// EnsureDir ensures the directory for an entry exists
func EnsureDir(v *Vault, path string) error {
	if v == nil {
		return errors.New("vault is nil")
	}
	return os.MkdirAll(filepath.Dir(EntryPath(v, path)), 0o700)
}

// IsInitialized checks if a vault is initialized at the given directory
func IsInitialized(vaultDir string) bool {
	configPath := filepath.Join(vaultDir, "config.yaml")
	identityPath := filepath.Join(vaultDir, "identity.age")

	_, configErr := os.Stat(configPath)
	_, identityErr := os.Stat(identityPath)

	return configErr == nil && identityErr == nil
}

// GetRecipient returns the vault's recipient (public key)
func (v *Vault) GetRecipient() (*age.X25519Recipient, error) {
	if v == nil {
		return nil, errors.New("vault is nil")
	}
	if v.Identity == nil {
		return nil, ErrNilIdentity
	}
	return v.Identity.Recipient(), nil
}

// ValidateIdentity validates that the provided identity matches the vault
func (v *Vault) ValidateIdentity(identity *age.X25519Identity) error {
	if v == nil {
		return errors.New("vault is nil")
	}
	if identity == nil {
		return ErrNilIdentity
	}
	if v.Identity.String() != identity.String() {
		return ErrIdentityMismatch
	}
	return nil
}

// AutoCommit performs a git auto-commit with vault configuration
func (v *Vault) AutoCommit(message string) error {
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
		commitMessage = "Update from OpenPass"
	}

	return git.AutoCommitAndPush(v.Dir, commitMessage, autoPush)
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

// detectLegacyMode checks if the vault directory contains legacy top-level .age files
// (outside entries/) and persists the result in the vault config. This one-time
// detection allows List to skip the legacy directory walk for legacy-free vaults.
func detectLegacyMode(cfg *vaultconfig.Config, vaultDir string) error {
	if cfg == nil {
		return nil
	}

	// Already detected — nothing to do
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

// hasLegacyTopLevelAgeFiles scans the top-level of vaultDir for .age files
// that are NOT in the entries/ subdirectory and NOT identity.age.
// Returns true if any legacy entries are found.
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
		// Skip identity.age — it's always present and not a legacy entry
		if entry.Name() == "identity.age" { //nolint:goconst // filename literal
			continue
		}
		// Ensure this is not inside entries/ (unlikely for top-level scan,
		// but guard against symlinks or unusual mounts)
		absPath := filepath.Join(vaultDir, entry.Name())
		if absPath == entriesDirAbs {
			continue
		}
		return true, nil
	}
	return false, nil
}

// cloneBytes returns a copy of b so that the caller's buffer is not
// affected by downstream zeroization.
func cloneBytes(b []byte) []byte {
	clone := make([]byte, len(b))
	copy(clone, b)
	return clone
}
