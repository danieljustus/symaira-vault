package crud

import (
	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/ui/render"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

var listCmd = &cobra.Command{
	Use:               "list [prefix]",
	Aliases:           []string{"ls"},
	ValidArgsFunction: cli.EntryCompletionFunc,
	Short:             "List password entries",
	Example: `  # List all entries
  symvault list

  # List entries under "work/" prefix
  symvault list work/

  # JSON output
  symvault list --output json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
			cli.MaybeAutoPull(vs.VaultDir(), v.Config)
			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}

			entries, err := vs.ListEntries(prefix)
			if err != nil {
				return errorspkg.ReadFailed(err, "cannot list entries")
			}

			if cli.OutputFormat != "text" {
				outputs := make([]vaultpkg.ListEntryInfo, 0, len(entries))
				for _, path := range entries {
					output := vaultpkg.ListEntryInfo{Path: path}
					entry, err := vs.GetEntry(path)
					if err == nil {
						output.Type = string(entry.SecretMetadata.Type)
						output.UsageHint = entry.SecretMetadata.UsageHint
						output.AutoRotate = entry.SecretMetadata.AutoRotate
					}
					outputs = append(outputs, output)
				}
				if err := cli.PrintResult(outputs); err != nil {
					return err
				}
				return nil
			}

			for _, e := range entries {
				cli.PrintlnQuietAware(render.ForTerminal(taint.Wrap(e, taint.Provenance{Source: "cli.path"})))
			}

			return nil
		})
	},
}

func init() {
	cli.RootCmd.AddCommand(listCmd)
}
