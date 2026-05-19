package auth

import (
	"fmt"
	"os"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var AuthUnlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the vault and cache the passphrase",
	Long: `Unlock the vault by validating the passphrase and caching it in the
OS keyring. This allows MCP servers to start without interactive prompts.

Use --check to verify if an active session exists without prompting.

Environment variable OPENPASS_PASSPHRASE can be used in CI/CD environments
but should NOT be used on shared machines (visible in process listings).`,
	Example: `  # Unlock the vault
  openpass unlock

  # Check if session is active
  openpass unlock --check

  # Unlock with custom TTL
  openpass unlock --ttl 30m`,
	RunE: func(cmd *cobra.Command, args []string) error {
		check, _ := cmd.Flags().GetBool("check")
		ttl, _ := cmd.Flags().GetDuration("ttl")
		ttlFlag := cmd.Flags().Lookup("ttl")
		ttlOverride := time.Duration(0)
		if ttlFlag != nil && ttlFlag.Changed {
			ttlOverride = ttl
		}

		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized, "vault not initialized. Run 'openpass init' first", errorspkg.ErrVaultNotInitialized)
		}

		if check {
			if cli.SessionIsExpired(vaultDir) {
				cmd.SilenceUsage = true
				return errorspkg.NewCLIError(errorspkg.ExitLocked, "no active session", errorspkg.ErrVaultLocked)
			}
			fmt.Fprintln(os.Stderr, "Session active")
			return nil
		}

		v, effectiveTTL, err := cli.UnlockVaultWithTTL(vaultDir, true, ttlOverride, true)
		if err != nil {
			return err
		}
		_ = v

		if status := cli.SessionGetCacheStatus(); !status.Persistent {
			return errorspkg.NewCLIError(errorspkg.ExitLocked, "session cache is memory-only; 'openpass unlock' cannot unlock future serve processes. Start serve with OPENPASS_PASSPHRASE or use a build with OS keyring support", nil)
		}

		fmt.Fprintf(os.Stderr, "Vault unlocked (session TTL: %s)\n", effectiveTTL)
		return nil
	},
}

func init() {
	cli.RootCmd.AddCommand(AuthUnlockCmd)
	AuthUnlockCmd.Flags().Duration("ttl", cli.DefaultSessionTTL(), "Session duration (overrides config sessionTimeout)")
	AuthUnlockCmd.Flags().Bool("check", false, "Check if session is active (exit 0 = active, exit 1 = expired)")
}
