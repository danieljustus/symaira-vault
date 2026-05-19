package cli

import (
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

func loadGlobalConfig() (*configpkg.Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return configpkg.Load(filepath.Join(home, ".openpass", "config.yaml"))
}

func EntryCompletionFunc(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return entryPathSuggestions(toComplete)
}

func entryPathSuggestions(toComplete string) ([]string, cobra.ShellCompDirective) {
	vaultDir, err := VaultPath()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cachedIdentity, err := SessionLoadIdentity(vaultDir)
	if err != nil || cachedIdentity == "" {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	identity, err := age.ParseX25519Identity(cachedIdentity)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	v, err := vaultpkg.OpenWithCachedIdentity(vaultDir, identity)
	if err != nil || v == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	prefix := strings.TrimSpace(toComplete)
	paths, err := vaultpkg.List(vaultDir, "")
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	matches := make([]string, 0, len(paths))
	for _, p := range paths {
		if prefix == "" || strings.HasPrefix(p, prefix) {
			matches = append(matches, p)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func ProfileCompletionFunc(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := loadGlobalConfig()
	if err != nil || cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	matches := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		if toComplete == "" || strings.HasPrefix(name, toComplete) {
			matches = append(matches, name)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}
