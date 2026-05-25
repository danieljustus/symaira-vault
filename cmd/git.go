package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/git"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var gitCmd = &cobra.Command{
	Use:   "git <push|pull|log> [path]",
	Short: "Git operations on vault",
	Example: `  # Sync with the configured remote
  symaira git pull
  symaira git push

  # Show commit history for an entry
  symaira git log work/aws`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		action := args[0]

		if action == "log" {
			return cli.WithVaultRaw(func(v *vaultpkg.Vault) error {
				path := ""
				if len(args) > 1 {
					path = args[1]
				}
				history, err := git.Log(v.Dir, path, 0)
				if err != nil {
					return fmt.Errorf("cannot get log: %w", err)
				}
				for _, h := range history {
					printQuietAware("%s  %s  %s\n", h.Hash[:7], h.Date.Format("2006-01-02"), h.Message)
					printlnQuietAware("  Author: " + h.Author)
				}
				return nil
			})
		}

		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}
		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized, "vault not initialized. Run 'symaira init' first", errorspkg.ErrVaultNotInitialized)
		}

		switch action {
		case "push":
			if err := git.Push(vaultDir); err != nil {
				return fmt.Errorf("push failed: %w", err)
			}
			printlnQuietAware("Pushed to remote")
		case "pull":
			if err := git.Pull(vaultDir); err != nil {
				return fmt.Errorf("pull failed: %w", err)
			}
			printlnQuietAware("Pulled from remote")
		default:
			return fmt.Errorf("unknown action: %s (use push, pull, or log)", action)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(gitCmd)
}
