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

const vaultFormatVersion2 = 2

var (
	ErrVaultDirEmpty       = errors.New("vault directory is empty")
	ErrNilIdentity         = errors.New("identity is nil")
	ErrNilConfig           = errors.New("config is nil")
	ErrIdentityMismatch    = errors.New("identity mismatch")
	ErrVaultNotInitialized = errors.New("vault not initialized")
	ErrVaultDirEscapes     = errors.New("vault directory path escapes intended directory")
)

func validateVaultDir(vaultDir string) error {
	if pathutil.HasTraversal(vaultDir) {
		return ErrVaultDirEscapes
	}
	return nil
}

type Vault struct {
	Identity       *age.X25519Identity
	Config         *vaultconfig.Config
	Dir            string
	NeedsMigration bool
}

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
	raw, err := os.ReadFile(identityPath)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	migrationPassphrase := cloneBytes(passphrase)
	format := vaultcrypto.DetectEncryptedIdentityFormat(raw)
	var identity *age.X25519Identity
	switch format {
	case "argon2id":
		identity, err = vaultcrypto.LoadIdentityWithArgon2id(identityPath, cloneBytes(passphrase))
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
	if format != "argon2id" && v.Config != nil && v.Config.Vault != nil &&
		v.Config.Vault.FormatVersion < vaultFormatVersion2 {
		params := vaultcrypto.DefaultArgon2idParams()
		if migrateErr := vaultcrypto.SaveIdentityWithArgon2id(identity, identityPath, migrationPassphrase, params); migrateErr == nil {
			v.Config.Vault.FormatVersion = vaultFormatVersion2
			v.Config.Vault.ScryptWorkFactor = 0
			if cfgPath := filepath.Join(vaultDir, "config.yaml"); cfgPath != "" {
				_ = v.Config.SaveTo(cfgPath)
			}
		} else {
			v.NeedsMigration = true
		}
	}
	vaultcrypto.Wipe(migrationPassphrase)
	return v, nil
}

func OpenWithCachedIdentity(vaultDir string, identity *age.X25519Identity) (*Vault, error) {
	if vaultDir == "" {
		return nil, ErrVaultDirEmpty
	}
	if identity == nil {
		return nil, ErrNilIdentity
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
	if err := fileutil.AtomicWriteFile(cfgPath, configData, 0o600); err != nil {
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
		return nil, ErrNilIdentity
	}
	return v.Identity.Recipient(), nil
}

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
