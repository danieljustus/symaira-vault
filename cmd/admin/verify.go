package admin

import (
	"fmt"
	"os"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	verifyRebuild     bool
	verifyRebuildOnly bool
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify vault entry integrity against manifest",
	Long: `Verify that all vault entries match their recorded manifest hashes.
This detects tampered or corrupted entry files.

Use --rebuild to regenerate the manifest from the on-disk .age files (use
this when entries have been added out-of-band, e.g. via git sync, and the
manifest has not been updated). Use --rebuild-only to skip the integrity
check and only rebuild.`,
	Example: `  # Verify manifest matches on-disk entries
  symvault verify

  # Rebuild the manifest from on-disk entries (fixes "unknown" entries from sync)
  symvault verify --rebuild

  # Just rebuild, skip the integrity check
  symvault verify --rebuild-only

  # As part of a scripted health check
  symvault verify || echo "Manifest mismatch — investigate"`,
	Annotations: map[string]string{
		cli.RequiresVaultAnnotation: "true",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVaultRaw(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
			if verifyRebuild || verifyRebuildOnly {
				if err := vaultpkg.RebuildManifest(v.Dir, v.Identity); err != nil {
					return fmt.Errorf("rebuild manifest: %w", err)
				}
				cmd.Println("Manifest rebuilt from on-disk entries.")
				if verifyRebuildOnly {
					return nil
				}
			}

			result, err := vaultpkg.VerifyManifestIntegrity(v.Dir, v.Identity)
			if err != nil {
				if os.IsNotExist(err) {
					cmd.Println("No manifest found. Run `symvault verify --rebuild` to create one from on-disk entries.")
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
				cmd.Println("\nHint: run `symvault verify --rebuild` to add these entries to the manifest.")
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
	verifyCmd.Flags().BoolVar(&verifyRebuild, "rebuild", false, "Rebuild the manifest from on-disk entries after the integrity check")
	verifyCmd.Flags().BoolVar(&verifyRebuildOnly, "rebuild-only", false, "Rebuild the manifest and skip the integrity check")
}
