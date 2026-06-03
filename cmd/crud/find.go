package crud

import (
	"fmt"
	"os"
	"runtime"
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
// operations. It uses the vault.searchWorkers config if set (> 0), otherwise
// auto-scales based on vault entry count and CPU cores.
func searchWorkers(vaultDir string, cfg *configpkg.Config) int {
	if cfg != nil && cfg.Vault != nil && cfg.Vault.SearchWorkers > 0 {
		return cfg.Vault.SearchWorkers
	}

	entries, _ := vaultpkg.List(vaultDir, "", nil)
	entryCount := len(entries)
	cpuCount := runtime.GOMAXPROCS(0)

	// Scale workers with vault size: base 2, +1 per 1000 entries, capped at CPU count
	workers := entryCount/1000 + 2
	if workers > cpuCount {
		workers = cpuCount
	}
	if workers < 2 {
		workers = 2
	}
	return workers
}

var findCmd = &cobra.Command{
	Use:               "find <query>",
	Aliases:           []string{"search"},
	ValidArgsFunction: cli.EntryCompletionFunc,
	Short:             "Search for entries",
	Long:              `Searches entry paths and contents for the given query.`,
	Example: `  # Search for entries containing "bank"
  symvault find bank

  # JSON output
  symvault find bank --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVault(func(v *vaultpkg.Vault) error {
			cli.MaybeAutoPull(cli.VaultDir(v), v.Config)
			cfg := v.Config
			workers := searchWorkers(cli.VaultDir(v), cfg)

			matches, err := cli.FindEntries(v, args[0], vaultpkg.FindOptions{MaxWorkers: workers})
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

func init() {
	cli.RootCmd.AddCommand(findCmd)
}
