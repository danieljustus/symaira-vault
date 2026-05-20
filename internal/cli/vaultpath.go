package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
)

func VaultPath() (string, error) {
	if VaultFlag != nil && VaultFlag.Changed {
		p, err := ExpandVaultDir(Vault)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
		}
		return p, nil
	}

	if envVault := strings.TrimSpace(os.Getenv("OPENPASS_VAULT")); envVault != "" {
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

	if envProfile := strings.TrimSpace(os.Getenv("OPENPASS_PROFILE")); envProfile != "" {
		p, err := resolveProfileVaultDir(envProfile)
		if err != nil {
			return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "resolve profile", err)
		}
		return p, nil
	}

	home, err := os.UserHomeDir()
	if err == nil {
		cfg, cfgErr := configpkg.Load(filepath.Join(home, ".openpass", "config.yaml"))
		if cfgErr == nil && cfg.DefaultProfile != "" {
			p, profErr := resolveProfileVaultDir(cfg.DefaultProfile)
			if profErr == nil {
				return p, nil
			}
		}
	}

	p, err := ExpandVaultDir(Vault)
	if err != nil {
		return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "expand vault path", err)
	}
	return p, nil
}

func resolveProfileVaultDir(profileName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	cfg, err := configpkg.Load(filepath.Join(home, ".openpass", "config.yaml"))
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
		home, _ := os.UserHomeDir()
		return home + "/.openpass"
	}
	return dir
}
