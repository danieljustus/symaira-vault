package cli

import (
	"context"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/ui/cliout"

	"filippo.io/age"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/envutil"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func UnlockVault(vaultDir string, interactive bool) (*vaultpkg.Vault, error) {
	v, _, err := UnlockVaultWithTTL(vaultDir, interactive, 0, false)
	return v, err
}

func UnlockVaultWithTTL(vaultDir string, interactive bool, ttlOverride time.Duration, cacheEnvPassphrase bool) (*vaultpkg.Vault, time.Duration, error) {
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

	cfg := loadVaultConfigForUnlock(vaultDir)

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

	if !passphraseFromEnv || cacheEnvPassphrase {
		if err := SessionSavePassphrase(vaultDir, passphrase, ttl); err != nil {
			return nil, 0, errorspkg.NewCLIError(errorspkg.ExitGeneralError, "save session", err)
		}
		if v != nil && v.Identity != nil {
			_ = SessionSaveIdentity(vaultDir, v.Identity.String(), ttl)
		}
	}
	if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID && (!passphraseFromEnv || cacheEnvPassphrase) {
		if err := SessionSaveBiometric(context.Background(), vaultDir, passphrase); err != nil && interactive {
			cliout.Warnf("Warning: could not update Touch ID unlock: %v", err)
		}
	}

	return v, ttl, nil
}

func resolveUnlockPassphrase(vaultDir string, interactive bool, cfg *configpkg.Config) ([]byte, bool, bool, error) {
	passphrase, err := SessionLoadPassphrase(vaultDir)
	passphraseFromEnv := false
	passphraseFromBiometric := false
	if err != nil || len(passphrase) == 0 {
		if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID {
			biometricCtx, biometricCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer biometricCancel()
			if biometricPassphrase, biometricErr := SessionLoadBiometric(biometricCtx, vaultDir); biometricErr == nil && len(biometricPassphrase) > 0 {
				passphrase = biometricPassphrase
				passphraseFromBiometric = true
			}
		}
		if len(passphrase) == 0 && (cfg == nil || cfg.Security == nil || !cfg.Security.DisableEnvPassphrase) {
			// Check the early-cached env passphrase first (sniffed in main()
			// before any child process could inherit it).
			if cached := consumeCachedEnvPassphrase(); len(cached) > 0 {
				passphrase = cached
				passphraseFromEnv = true
				WarnEnvPassphrase()
			} else if p := envutil.Getenv("SYMVAULT_PASSPHRASE", "OPENPASS_PASSPHRASE"); p != "" {
				passphrase = []byte(p)
				passphraseFromEnv = true
				WarnEnvPassphrase()
			}
		}
		if len(passphrase) == 0 {
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
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'symvault init' first",
			errorspkg.ErrVaultNotInitialized)
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

func loadVaultConfigForUnlock(vaultDir string) *configpkg.Config {
	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		return configpkg.Default()
	}
	return cfg
}

func lockedMessageForCache() string {
	status := SessionGetCacheStatus()
	if !status.Persistent {
		return "vault locked: this build cannot share 'symvault unlock' sessions across processes; set SYMVAULT_PASSPHRASE or OPENPASS_PASSPHRASE, or use a build with OS keyring support"
	}
	return "vault locked: run 'symvault unlock' first, enable Touch ID with 'symvault auth set touchid', or set SYMVAULT_PASSPHRASE or OPENPASS_PASSPHRASE"
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
