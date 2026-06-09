package admin

import (
	"fmt"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/session"
)

var migrateSessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Upgrade a cached session from the legacy plaintext format to encrypted",
	Long: `Upgrade a cached session from the legacy plaintext format to the
encrypted form that uses a randomly generated wrap key.

Earlier versions of Symaira Vault stored cached passphrases in plaintext
inside the OS keyring. The current implementation refuses to transparently
load a legacy plaintext session; run this command once per vault to
upgrade the cached entry.

The migration is a no-op when the session is already in the encrypted
format. The vault directory defaults to the value of --vault (or the
$SYMVAULT_VAULT environment variable).`,
	Example: `  symvault migrate session
  symvault migrate session --vault ~/.symvault
  symvault migrate session --dry-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		mgr := session.DefaultManager()
		legacy, err := mgr.HasLegacyPlaintextSession(vaultDir)
		if err != nil {
			return fmt.Errorf("inspect session: %w", err)
		}
		if !legacy {
			cli.PrintlnQuietAware("No legacy plaintext session found. Nothing to migrate.")
			return nil
		}

		if MigrateV4DryRun {
			cli.PrintlnQuietAware("Dry-run: legacy plaintext session detected. Re-run without --dry-run to upgrade.")
			return nil
		}

		upgraded, err := mgr.MigrateSession(vaultDir)
		if err != nil {
			return fmt.Errorf("migrate session: %w", err)
		}
		if !upgraded {
			cli.PrintlnQuietAware("No legacy plaintext session found. Nothing to migrate.")
			return nil
		}

		cli.PrintlnQuietAware("Session upgraded. The cached passphrase is now stored encrypted in the OS keyring.")
		return nil
	},
}

func init() {
	migrateSessionCmd.Flags().BoolVar(&MigrateV4DryRun, "dry-run", false, "Preview the migration without writing")
	MigrateCmd.AddCommand(migrateSessionCmd)
}
