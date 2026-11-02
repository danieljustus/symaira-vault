package crud

import (
	"fmt"
	"os"
	"strings"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/ui/render"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

// searchWorkers returns the number of concurrent decryption workers for find
// operations. It uses the vault.searchWorkers config if set (> 0), otherwise it
// lets the vault package apply its default bounded worker policy.
func searchWorkers(cfg *configpkg.Config) int {
	configured := 0
	if cfg != nil && cfg.Vault != nil && cfg.Vault.SearchWorkers > 0 {
		configured = cfg.Vault.SearchWorkers
	}
	return vaultpkg.SearchWorkerCount(configured)
}

func newFindCmd() *cobra.Command {
	var urlFilter string

	findCmd := &cobra.Command{
		Use:               "find [query]",
		Aliases:           []string{"search"},
		ValidArgsFunction: cli.EntryCompletionFunc,
		Short:             "Search for entries",
		Long:              `Searches entry paths and contents for the given query, or matches entries by URL/host.`,
		Example: `  # Search for entries containing "bank"
  symvault find bank

  # Search for entries matching a URL or host
  symvault find --url https://github.com/login
  symvault find --url github.com

  # JSON output
  symvault find bank --output json
  symvault find --url github.com --output json`,
		Args: func(cmd *cobra.Command, args []string) error {
			if urlFilter == "" && len(args) == 0 {
				return fmt.Errorf("accepts 1 arg(s), received 0")
			}
			if len(args) > 1 {
				return fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
			}
			return nil
		},
		Annotations: map[string]string{
			cli.JSONOutputAnnotation: "true",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if urlFilter != "" {
				if err := vaultpkg.ValidateURL(urlFilter); err != nil {
					return errorspkg.InvalidInput("invalid url %q: %v", urlFilter, err)
				}
			}

			return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
				cli.MaybeAutoPull(vs.VaultDir(), v.Config)
				cfg := v.Config
				workers := searchWorkers(cfg)

				query := ""
				if len(args) > 0 {
					query = args[0]
				}

				matches, err := vs.FindEntries(query, vaultpkg.FindOptions{
					MaxWorkers: workers,
					URLFilter:  urlFilter,
				})
				if err != nil {
					return errorspkg.ReadFailed(err, "search failed")
				}

				if len(matches) == 0 {
					fmt.Fprintln(os.Stderr, "No matches found")
					return nil
				}

				if cli.OutputFormat != "text" {
					type matchEntry struct {
						Path   string   `json:"path"`
						Fields []string `json:"fields,omitempty"`
					}
					out := make([]matchEntry, 0, len(matches))
					for _, m := range matches {
						out = append(out, matchEntry{Path: m.Path, Fields: m.Fields})
					}
					if err := cli.PrintResult(map[string]interface{}{"matches": out}); err != nil {
						return err
					}
					return nil
				}

				for _, m := range matches {
					cli.PrintQuietAware("%s", render.ForTerminal(taint.Wrap(m.Path, taint.Provenance{Source: "cli.path"})))
					if len(m.Fields) > 0 {
						cli.PrintQuietAware(" (matches: %s)", strings.Join(m.Fields, ", "))
					}
					cli.PrintlnQuietAware()
				}

				return nil
			})
		},
	}

	findCmd.Flags().StringVar(&urlFilter, "url", "", "Search entries matching a URL or host")
	findCmd.GroupID = cli.GroupIDEssentials
	return findCmd
}
