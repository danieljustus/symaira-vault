package crud

import (
	"fmt"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-vault/internal/ui/render"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
	vaultsvc "github.com/danieljustus/symaira-vault/internal/vaultsvc"
)

type listEntryOutput struct {
	Path       string `json:"path"`
	Type       string `json:"type,omitempty"`
	UsageHint  string `json:"usage_hint,omitempty"`
	AutoRotate bool   `json:"auto_rotate,omitempty"`
}

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
		return cli.WithVault(func(svc vaultsvc.Service) error {
			cli.MaybeAutoPull(svc.GetDir(), svc.Vault().Config)
			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}

			entries, err := svc.List(prefix)
			if err != nil {
				return fmt.Errorf("cannot list entries: %w", err)
			}

			if cli.OutputFormat != "text" {
				outputs := make([]listEntryOutput, 0, len(entries))
				for _, path := range entries {
					output := listEntryOutput{Path: path}
					entry, err := vaultpkg.ReadEntry(svc.GetDir(), path, svc.GetIdentity())
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
