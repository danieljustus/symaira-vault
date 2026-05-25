package auth

import (
	"fmt"
	"os"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/session"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault (clear session)",
	Example: `  # Lock the vault (clear session)
  symvault lock`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized, "vault not initialized. Run 'symvault init' first", errorspkg.ErrVaultNotInitialized)
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
