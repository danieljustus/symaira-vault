package admin

import (
	"fmt"
	"os"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify vault entry integrity against manifest",
	Long: `Verify that all vault entries match their recorded manifest hashes.
This detects tampered or corrupted entry files.`,
	Example: `  # Verify manifest matches on-disk entries
  openpass verify

  # As part of a scripted health check
  openpass verify || echo "Manifest mismatch — investigate"`,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "true",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVaultRaw(func(v *vaultpkg.Vault) error {
			result, err := vaultpkg.VerifyManifestIntegrity(v.Dir, v.Identity)
			if err != nil {
				if os.IsNotExist(err) {
					cmd.Println("No manifest found. Run `openpass verify` after adding entries to create one.")
					return nil
				}
				return err
			}

			cmd.Printf("Manifest verification: %d entries match, %d missing, %d tampered, %d unknown\n",
				result.OK, len(result.Missing), len(result.Tampered), len(result.Unknown))

			if len(result.Missing) > 0 {
				cmd.Println("\nMissing entries:")
				for _, p := range result.Missing {
					cmd.Printf("  - %s\n", p)
				}
			}
			if len(result.Tampered) > 0 {
				cmd.Println("\nTampered entries:")
				for _, p := range result.Tampered {
					cmd.Printf("  - %s (hash mismatch)\n", p)
				}
			}
			if len(result.Unknown) > 0 {
				cmd.Println("\nUnknown entries (not in manifest):")
				for _, p := range result.Unknown {
					cmd.Printf("  - %s\n", p)
				}
			}

			if len(result.Tampered) > 0 {
				return fmt.Errorf("manifest integrity check failed: %d tampered entries", len(result.Tampered))
			}
			return nil
		})
	},
}

func init() {
	cli.RootCmd.AddCommand(verifyCmd)
}
