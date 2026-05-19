package auth

import (
	"fmt"
	"os"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/session"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault (clear session)",
	Example: `  # Lock the vault (clear session)
  openpass lock`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized, "vault not initialized. Run 'openpass init' first", errorspkg.ErrVaultNotInitialized)
		}

		if err := session.ClearSession(vaultDir); err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot clear session", err)
		}

		fmt.Fprintln(os.Stderr, "Vault locked")
		return nil
	},
}

func init() {
	cli.RootCmd.AddCommand(lockCmd)
}
