package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/git"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var syncPush bool
var syncForce bool

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync vault with remote (pull + optional push)",
	Long:  "Pulls changes from the remote git repository and optionally pushes local changes.",
	Example: `  # Pull only
  openpass sync

  # Pull and push
  openpass sync --push

  # Force pull (reset local changes)
  openpass sync --force`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := vaultPath()
		if err != nil {
			return err
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
				"vault not initialized. Run 'openpass init' first",
				errorspkg.ErrVaultNotInitialized)
		}

		hasRemote, _ := git.HasRemote(vaultDir, "origin")
		if !hasRemote {
			printlnQuietAware("No remote configured. Skipping sync.")
			return nil
		}

		result := git.Sync(vaultDir, syncPush)

		if result.Skipped {
			printlnQuietAware("No remote configured. Skipping sync.")
			return nil
		}

		if result.Error != nil {
			if isOfflineErr(result.Error) {
				printlnQuietAware("Warning: could not reach remote — offline")
				return nil
			}
			return fmt.Errorf("sync failed: %w", result.Error)
		}

		if result.Success {
			printlnQuietAware("Pulled from remote")
			if err := git.SetLastSyncTime(vaultDir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not record sync time: %v\n", err)
			}

			hostname, _ := os.Hostname()
			if err := git.ResolveConflicts(vaultDir, hostname); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: conflict resolution failed: %v\n", err)
			}
		} else {
			printlnQuietAware("Already up to date")
		}

		if result.PushDone {
			if result.PushSuccess {
				printlnQuietAware("Pushed to remote")
			} else {
				printlnQuietAware("Push skipped or failed")
			}
		}

		conflictFiles := findConflictFiles(vaultDir)
		if len(conflictFiles) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: %d conflict file(s) created:\n", len(conflictFiles))
			for _, f := range conflictFiles {
				fmt.Fprintf(os.Stderr, "  %s\n", f)
			}
		}

		return nil
	},
}

func init() {
	syncCmd.Flags().BoolVarP(&syncPush, "push", "p", false, "also push after pull")
	syncCmd.Flags().BoolVarP(&syncForce, "force", "f", false, "force pull (reset local changes)")
	rootCmd.AddCommand(syncCmd)
}

func isOfflineErr(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "network error - please check your connection"
}

func findConflictFiles(vaultDir string) []string {
	var conflicts []string
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() && containsConflict(e.Name()) {
			conflicts = append(conflicts, e.Name())
		}
	}
	entriesDir := filepath.Join(vaultDir, "entries")
	entriesList, err := os.ReadDir(entriesDir)
	if err == nil {
		for _, e := range entriesList {
			if containsConflict(e.Name()) {
				conflicts = append(conflicts, filepath.Join("entries", e.Name()))
			}
		}
	}
	return conflicts
}

func containsConflict(name string) bool {
	return len(name) > 11 && filepath.Base(name)[0:9] == ".conflict" ||
		(len(name) > 14 && name[0:14] == "config.conflict")
}

func maybeAutoPull(vaultDir string, cfg *configpkg.Config) {
	if cfg == nil || cfg.Git == nil {
		return
	}

	if !cfg.Git.AutoPull {
		return
	}

	hasRemote, _ := git.HasRemote(vaultDir, "origin")
	if !hasRemote {
		return
	}

	interval := cfg.Git.AutoPullInterval
	if interval <= 0 {
		interval = configpkg.Default().Git.AutoPullInterval
	}

	if !git.ShouldAutoPull(vaultDir, interval) {
		return
	}

	result := git.PullWithResult(vaultDir)
	if result.Error != nil {
		if isOfflineErr(result.Error) {
			return
		}
		return
	}

	if result.Skipped && !result.HasRemote {
		return
	}

	if err := git.SetLastSyncTime(vaultDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not record sync time: %v\n", err)
	}

	hostname, _ := os.Hostname()
	if err := git.ResolveConflicts(vaultDir, hostname); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: conflict resolution failed: %v\n", err)
	}

	conflictFiles := findConflictFiles(vaultDir)
	if len(conflictFiles) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d conflict file(s) detected after auto-pull:\n", len(conflictFiles))
		for _, f := range conflictFiles {
			fmt.Fprintf(os.Stderr, "  %s\n", f)
		}
	}
}
