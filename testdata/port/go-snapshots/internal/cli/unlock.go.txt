package cli

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/ui/cliout"

	"filippo.io/age"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func UnlockVault(vaultDir string, interactive bool) (*vaultpkg.Vault, error) {
	v, _, err := UnlockVaultWithTTL(vaultDir, interactive, 0, false)
	return v, err
}

func UnlockVaultWithTTL(vaultDir string, interactive bool, ttlOverride time.Duration, cacheEnvPassphrase bool) (*vaultpkg.Vault, time.Duration, error) {
	return unlockVault(vaultDir, interactive, ttlOverride, cacheEnvPassphrase, true)
}

// UnlockVaultForSession backs the explicit `symvault unlock` command. It
// deliberately skips the cached-identity shortcut: the passphrase (or Touch
// ID) is verified again and the session entry is rewritten, so a successful
// `unlock` always leaves behind the session that `unlock --check` and other
// processes look for.
//
// Taking the shortcut here is what made the GUI unusable: the identity entry
// is renewed by every vault command, while the session entry is only renewed
// when the passphrase is actually loaded. Once the session aged out, `unlock`
// still reported success from the cached identity without recreating it, so
// `unlock --check` reported a locked vault forever and the app bounced
// straight back to its unlock screen.
func UnlockVaultForSession(vaultDir string, interactive bool, ttlOverride time.Duration) (*vaultpkg.Vault, time.Duration, error) {
	return unlockVault(vaultDir, interactive, ttlOverride, true, false)
}

func unlockVault(vaultDir string, interactive bool, ttlOverride time.Duration, cacheEnvPassphrase, useIdentityCache bool) (*vaultpkg.Vault, time.Duration, error) {
	cfg, err := resolveConfig(vaultDir, interactive)
	if err != nil {
		return nil, 0, errorspkg.NewCLIError(errorspkg.ExitConfigError, "configuration is invalid", err)
	}

	if useIdentityCache {
		if cachedIdentity, cacheErr := SessionLoadIdentity(vaultDir); cacheErr == nil && cachedIdentity != "" {
			if identity, parseErr := age.ParseX25519Identity(cachedIdentity); parseErr == nil {
				v, openErr := vaultpkg.OpenWithCachedIdentity(vaultDir, identity)
				if openErr == nil {
					metrics.RecordIdentityCacheEvent("hit")
					ttl := ConfiguredSessionTTL(v, ttlOverride)
					return v, ttl, nil
				}
			}
			metrics.RecordIdentityCacheEvent("miss")
		} else {
			metrics.RecordIdentityCacheEvent("miss")
		}
	}

	passphrase, passphraseFromEnv, _, err := resolveUnlockPassphrase(vaultDir, interactive, cfg)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		cryptopkg.Wipe(passphrase)
	}()

	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		return nil, 0, errorspkg.NewCLIError(errorspkg.ExitGeneralError, "open vault", err)
	}

	ttl := ConfiguredSessionTTL(v, ttlOverride)
	maxLifetime := ConfiguredSessionMaxLifetime(v)

	if !passphraseFromEnv || cacheEnvPassphrase {
		if err := saveSessionPassphrase(vaultDir, passphrase, ttl, maxLifetime); err != nil {
			return nil, 0, errorspkg.NewCLIError(errorspkg.ExitGeneralError, "save session", err)
		}
		if v != nil && v.Identity != nil {
			_ = saveSessionIdentity(vaultDir, v.Identity.String(), ttl, maxLifetime)
		}
	}
	if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID && (!passphraseFromEnv || cacheEnvPassphrase) {
		if err := SessionSaveBiometric(context.Background(), vaultDir, passphrase); err != nil && interactive {
			cliout.Warnf("Warning: could not update Touch ID unlock: %v", err)
		}
	}

	return v, ttl, nil
}

func resolveConfig(vaultDir string, interactive bool) (*configpkg.Config, error) {
	configPath := filepath.Join(vaultDir, "config.yaml")
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
		return configpkg.Default(), nil
	}

	for {
		cfg, loadErr := configpkg.Load(configPath)
		var valErr error
		if loadErr == nil && cfg != nil {
			valErr = cfg.Validate()
		}

		if loadErr == nil && valErr == nil {
			return cfg, nil
		}

		if !interactive {
			combinedErr := loadErr
			if combinedErr == nil {
				combinedErr = valErr
			}
			return nil, combinedErr
		}

		// Interactive fix
		fixedCfg, fixErr := InteractiveFixConfig(configPath, loadErr, cfg, valErr)
		if fixErr != nil {
			return nil, fixErr
		}
		if fixedCfg != nil {
			return fixedCfg, nil
		}
		// If fixedCfg is nil, it means user edited the file in editor, so loop to re-load and re-validate.
	}
}

// IsEnvPassphraseAllowed checks if environment passphrase unlocking is allowed.
// Environment passphrase usage is default-deny and requires explicit opt-in
// via security.allow_env_passphrase: true in config.yaml or SYMVAULT_ALLOW_ENV_PASSPHRASE=1.
func IsEnvPassphraseAllowed(cfg *configpkg.Config) bool {
	if cfg != nil && cfg.Security != nil && cfg.Security.DisableEnvPassphrase {
		return false
	}
	if cfg != nil && cfg.Security != nil && cfg.Security.AllowEnvPassphrase {
		return true
	}
	v := os.Getenv("SYMVAULT_ALLOW_ENV_PASSPHRASE")
	return v == "1" || v == "true" || v == "yes"
}

// envPassphraseIgnored reports whether an environment passphrase is available
// (cached from main() or still set in the environment) but will be ignored
// because the opt-in gate (security.allow_env_passphrase in config.yaml or
// SYMVAULT_ALLOW_ENV_PASSPHRASE=1) is not enabled. Used to surface an explicit
// hint instead of silently discarding SYMVAULT_PASSPHRASE.
func envPassphraseIgnored(cfg *configpkg.Config) bool {
	if IsEnvPassphraseAllowed(cfg) {
		return false
	}
	if HasCachedEnvPassphrase() {
		return true
	}
	return os.Getenv("SYMVAULT_PASSPHRASE") != ""
}

func resolveUnlockPassphrase(vaultDir string, interactive bool, cfg *configpkg.Config) ([]byte, bool, bool, error) {
	passphrase, err := SessionLoadPassphrase(vaultDir)
	passphraseFromEnv := false
	passphraseFromBiometric := false
	if err != nil || len(passphrase) == 0 {
		if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID && SessionHasGUISession() {
			// Touch ID is a LocalAuthentication GUI prompt, not a terminal
			// prompt: it works without a controlling TTY, so attempt it
			// whenever a GUI session exists — even for agents/scripts.
			biometricCtx, biometricCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer biometricCancel()
			if biometricPassphrase, biometricErr := SessionLoadBiometric(biometricCtx, vaultDir); biometricErr == nil && len(biometricPassphrase) > 0 {
				passphrase = biometricPassphrase
				passphraseFromBiometric = true
			}
		} else if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID && !interactive && !SessionHasGUISession() {
			cliout.Warnf("Touch ID skipped (no GUI session); use 'symvault unlock' in a graphical session or enable security.allow_env_passphrase / SYMVAULT_ALLOW_ENV_PASSPHRASE")
		}
		if len(passphrase) == 0 && IsEnvPassphraseAllowed(cfg) {
			// Check the early-cached env passphrase first (sniffed in main()
			// before any child process could inherit it).
			if cached := ConsumeCachedEnvPassphrase(); len(cached) > 0 {
				passphrase = cached
				passphraseFromEnv = true
				WarnEnvPassphrase()
			} else if p := os.Getenv("SYMVAULT_PASSPHRASE"); p != "" {
				passphrase = []byte(p)
				passphraseFromEnv = true
				WarnEnvPassphrase()
			}
		}
		if len(passphrase) == 0 {
			if envPassphraseIgnored(cfg) {
				if !interactive {
					return nil, false, false, errorspkg.NewCLIError(errorspkg.ExitLocked,
						"vault locked: SYMVAULT_PASSPHRASE is set but env passphrase unlock is disabled", nil).
						WithHint("Set SYMVAULT_ALLOW_ENV_PASSPHRASE=1 or security.allow_env_passphrase: true in config.yaml to allow SYMVAULT_PASSPHRASE for non-interactive use.")
				}
				cliout.Warnf("SYMVAULT_PASSPHRASE is set but ignored: env passphrase unlock is disabled. Set SYMVAULT_ALLOW_ENV_PASSPHRASE=1 or security.allow_env_passphrase: true in config.yaml to allow it.")
			}
			if !interactive {
				return nil, false, false, errorspkg.NewCLIError(errorspkg.ExitLocked, lockedMessageForCache(), nil)
			}
			var readErr error
			passphrase, readErr = ReadHiddenInput("Passphrase: ", nil)
			if readErr != nil {
				return nil, false, false, errorspkg.NewCLIError(errorspkg.ExitLocked, "read passphrase", readErr)
			}
		}
	}
	return passphrase, passphraseFromEnv, passphraseFromBiometric, nil
}

func WithVault(fn func(*vaultpkg.Vault, *VaultService) error) error {
	vaultDir, err := VaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewVaultNotInitialized()
	}
	v, err := UnlockVault(vaultDir, true)
	if err != nil {
		return err
	}
	vs := NewVaultService(v, nil)
	return fn(v, vs)
}

func WithVaultRaw(fn func(*vaultpkg.Vault, *VaultService) error) error {
	return WithVault(fn)
}

// WithVaultForScripting is the non-interactive variant of WithVault intended
// for scripting and subprocess use. It never prompts for input; if the vault
// is locked and no passphrase is available via session cache or environment
// variable, it returns ExitLocked immediately.
func WithVaultForScripting(fn func(*vaultpkg.Vault, *VaultService) error) error {
	vaultDir, err := VaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewVaultNotInitialized()
	}
	v, err := UnlockVault(vaultDir, false)
	if err != nil {
		return err
	}
	vs := NewVaultService(v, nil)
	return fn(v, vs)
}

func lockedMessageForCache() string {
	status := SessionGetCacheStatus()
	if !status.Persistent {
		return "vault locked: this build cannot share 'symvault unlock' sessions across processes; use 'symvault unlock', enable Touch ID, or for headless/CI set security.allow_env_passphrase: true / SYMVAULT_ALLOW_ENV_PASSPHRASE=1"
	}
	if invokedCommandIsUnlock() {
		// The user already ran `symvault unlock`; pointing them back at it
		// would be a dead end. Point at the actual fixes instead.
		return "vault locked: enable Touch ID with 'symvault auth set touchid' (or for headless/CI set security.allow_env_passphrase: true / SYMVAULT_ALLOW_ENV_PASSPHRASE=1)"
	}
	return "vault locked: run 'symvault unlock' first or enable Touch ID with 'symvault auth set touchid' (for headless/CI see security.allow_env_passphrase)"
}

func DefaultSessionTTL() time.Duration {
	return configpkg.Default().SessionTimeout
}

func ConfiguredSessionTTL(v *vaultpkg.Vault, override time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	if v != nil && v.Config != nil && v.Config.SessionTimeout > 0 {
		return v.Config.SessionTimeout
	}
	return DefaultSessionTTL()
}

func ConfiguredSessionMaxLifetime(v *vaultpkg.Vault) time.Duration {
	if v != nil && v.Config != nil && v.Config.SessionMaxLifetime > 0 {
		return v.Config.SessionMaxLifetime
	}
	return configpkg.Default().SessionMaxLifetime
}

func saveSessionPassphrase(vaultDir string, passphrase []byte, ttl, maxLifetime time.Duration) error {
	if maxLifetime == configpkg.Default().SessionMaxLifetime {
		return SessionSavePassphrase(vaultDir, passphrase, ttl)
	}
	return SessionSavePassphraseWithMaxLifetime(vaultDir, passphrase, ttl, maxLifetime)
}

func saveSessionIdentity(vaultDir, identity string, ttl, maxLifetime time.Duration) error {
	if maxLifetime == configpkg.Default().SessionMaxLifetime {
		return SessionSaveIdentity(vaultDir, identity, ttl)
	}
	return SessionSaveIdentityWithMaxLifetime(vaultDir, identity, ttl, maxLifetime)
}
