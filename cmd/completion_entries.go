package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

// loadGlobalConfig reads ~/.openpass/config.yaml for completion lookups.
// Errors are swallowed and returned as nil so completion never spams the
// user's shell with diagnostics.
func loadGlobalConfig() (*configpkg.Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return configpkg.Load(filepath.Join(home, ".openpass", "config.yaml"))
}

// entryCompletionFunc returns a cobra completion function that suggests vault
// entry paths for the first positional argument. It only works when the vault
// is unlocked (via the cached identity in the OS keyring) — otherwise it
// silently returns no suggestions so the shell falls back to default
// completion. We never prompt for a passphrase from completion code.
func entryCompletionFunc(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return entryPathSuggestions(toComplete)
}

// entryPathSuggestions returns vault entry paths matching the given prefix,
// or nil if the vault cannot be opened without a passphrase. Shared by all
// completion functions so behavior stays consistent.
func entryPathSuggestions(toComplete string) ([]string, cobra.ShellCompDirective) {
	vaultDir, err := vaultPath()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	cachedIdentity, err := sessionLoadIdentity(vaultDir)
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

// profileCompletionFunc suggests profile names from the user's config.yaml
// for use with the global --profile flag and the `profile` subcommand.
func profileCompletionFunc(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
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
