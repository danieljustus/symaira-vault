package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/ui/render"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	"github.com/danieljustus/OpenPass/internal/vault/taint"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
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
	ValidArgsFunction: entryCompletionFunc,
	Short:             "List password entries",
	Example: `  # List all entries
  openpass list

  # List entries under "work/" prefix
  openpass list work/

  # JSON output
  openpass list --output json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withVault(func(svc vaultsvc.Service) error {
			maybeAutoPull(svc.GetDir(), svc.Vault().Config)
			prefix := ""
			if len(args) > 0 {
				prefix = args[0]
			}

			entries, err := svc.List(prefix)
			if err != nil {
				return fmt.Errorf("cannot list entries: %w", err)
			}

			if outputFormat != "text" {
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
				if err := PrintResult(outputs); err != nil {
					return err
				}
				return nil
			}

			for _, e := range entries {
				printlnQuietAware(render.ForTerminal(taint.Wrap(e, taint.Provenance{Source: "cli.path"})))
			}

			return nil
		})
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
