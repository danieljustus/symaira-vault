package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"filippo.io/age"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/metrics"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
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

	passphrase, passphraseFromEnv, passphraseFromBiometric, err := resolveUnlockPassphrase(vaultDir, interactive, cfg)
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
	if cfg.EffectiveAuthMethod() == configpkg.AuthMethodTouchID && !passphraseFromBiometric && (!passphraseFromEnv || cacheEnvPassphrase) {
		if err := SessionSaveBiometric(context.Background(), vaultDir, passphrase); err != nil && interactive {
			fmt.Fprintf(os.Stderr, "Warning: could not update Touch ID unlock: %v\n", err)
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
			if biometricPassphrase, biometricErr := SessionLoadBiometric(context.Background(), vaultDir); biometricErr == nil && len(biometricPassphrase) > 0 {
				passphrase = biometricPassphrase
				passphraseFromBiometric = true
			}
		}
		if len(passphrase) == 0 {
			if envPass := os.Getenv("OPENPASS_PASSPHRASE"); envPass != "" {
				// Use unsafe.Slice to alias the string backing array without a heap copy.
				// This way the deferred Wipe(passphrase) at the call site clears the only
				// copy of the passphrase in memory, and the os.Unsetenv does not leave a
				// lingering string on the heap.
				// #nosec G103 — intentional: unsafe.Slice avoids heap-copying the passphrase
				// so that the subsequent Wipe clears the only copy in memory.
				passphrase = unsafe.Slice(unsafe.StringData(envPass), len(envPass))
				passphraseFromEnv = true
				WarnEnvPassphrase()
			}
			_ = os.Unsetenv("OPENPASS_PASSPHRASE")
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
	return passphrase, passphraseFromEnv, passphraseFromBiometric, nil
}

func WithVault(fn func(vaultsvc.Service) error) error {
	vaultDir, err := VaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'openpass init' first",
			errorspkg.ErrVaultNotInitialized)
	}
	v, err := UnlockVault(vaultDir, true)
	if err != nil {
		return err
	}
	return fn(vaultsvc.New(slog.Default(), v))
}

func WithVaultRaw(fn func(*vaultpkg.Vault) error) error {
	vaultDir, err := VaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'openpass init' first",
			errorspkg.ErrVaultNotInitialized)
	}
	v, err := UnlockVault(vaultDir, true)
	if err != nil {
		return err
	}
	return fn(v)
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
		return "vault locked: this build cannot share 'openpass unlock' sessions across processes; set OPENPASS_PASSPHRASE or use a build with OS keyring support"
	}
	return "vault locked: run 'openpass unlock' first, enable Touch ID with 'openpass auth set touchid', or set OPENPASS_PASSPHRASE"
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
