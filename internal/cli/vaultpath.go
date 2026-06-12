package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/envutil"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
)

func VaultPath() (string, error) {
	if VaultFlag != nil && VaultFlag.Changed {
		p, err := ExpandVaultDir(Vault)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
		}
		return p, nil
	}

	if envVault := strings.TrimSpace(envutil.Getenv("SYMVAULT_VAULT", "OPENPASS_VAULT")); envVault != "" {
		p, err := ExpandVaultDir(envVault)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
		}
		return p, nil
	}

	if ProfileFlag != nil && ProfileFlag.Changed {
		profileName := strings.TrimSpace(Profile)
		if profileName != "" {
			p, err := resolveProfileVaultDir(profileName)
			if err != nil {
				return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "resolve profile", err)
			}
			return p, nil
		}
	}

	if envProfile := strings.TrimSpace(envutil.Getenv("SYMVAULT_PROFILE", "OPENPASS_PROFILE")); envProfile != "" {
		p, err := resolveProfileVaultDir(envProfile)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "resolve profile", err)
		}
		return p, nil
	}

	r := configpkg.NewPathResolver()

	cfg, cfgErr := configpkg.Load(r.ConfigPath())
	if cfgErr == nil && cfg.DefaultProfile != "" {
		p, profErr := resolveProfileVaultDir(cfg.DefaultProfile)
		if profErr == nil {
			return p, nil
		}
	}

	if isDefaultVaultFlagValue(Vault) {
		// .openpass → .symvault migration detection (kept for backward compat).
		home, homeErr := os.UserHomeDir()
		if homeErr == nil {
			legacyVault := filepath.Join(home, configpkg.LegacyDefaultVaultSubdir)
			newVault := filepath.Join(home, configpkg.LegacyVaultSubdir)
			if vaultExists(legacyVault) && !vaultExists(newVault) {
				return legacyVault, nil
			}
		}

		// .symvault → XDG: PathResolver already resolved the correct data dir
		// based on which directories exist (legacy vs XDG).
		if r.DataDir != "" {
			return r.DataDir, nil
		}
	}

	p, err := ExpandVaultDir(Vault)
	if err != nil {
		return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
	}
	return p, nil
}

func isDefaultVaultFlagValue(vaultDir string) bool {
	trimmed := strings.TrimSpace(vaultDir)
	return trimmed == "" || trimmed == "~/"+configpkg.DefaultVaultSubdir
}

func vaultExists(vaultDir string) bool {
	return fileExists(filepath.Join(vaultDir, "config.yaml")) || fileExists(filepath.Join(vaultDir, "identity.age"))
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func resolveProfileVaultDir(profileName string) (string, error) {
	r := configpkg.NewPathResolver()

	cfg, err := configpkg.Load(r.ConfigPath())
	if err != nil {
		return "", fmt.Errorf("cannot load config: %w", err)
	}

	profile := cfg.ProfileForName(profileName)
	if profile == nil {
		return "", fmt.Errorf("profile %q not found", profileName)
	}

	if profile.VaultPath == "" {
		return "", fmt.Errorf("profile %q has no vault path configured", profileName)
	}

	return ExpandVaultDir(profile.VaultPath)
}

func ExpandVaultDir(vaultDir string) (string, error) {
	if vaultDir == "~" {
		return os.UserHomeDir()
	}
	if strings.HasPrefix(vaultDir, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		return filepath.Join(home, vaultDir[2:]), nil
	}
	return filepath.Clean(vaultDir), nil
}

func GetVaultDir() string {
	dir, err := VaultPath()
	if err != nil {
		r := configpkg.NewPathResolver()
		return r.DataDir
	}
	return dir
}
