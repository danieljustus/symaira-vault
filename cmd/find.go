package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/ui/render"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	"github.com/danieljustus/OpenPass/internal/vault/taint"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

// searchWorkers returns the number of concurrent decryption workers for find
// operations. It uses the vault.searchWorkers config if set (> 0), otherwise
// auto-scales based on vault entry count and CPU cores.
func searchWorkers(vaultDir string, cfg *configpkg.Config) int {
	if cfg != nil && cfg.Vault != nil && cfg.Vault.SearchWorkers > 0 {
		return cfg.Vault.SearchWorkers
	}

	entries, _ := vaultpkg.List(vaultDir, "")
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
	ValidArgsFunction: entryCompletionFunc,
	Short:             "Search for entries",
	Long:              `Searches entry paths and contents for the given query.`,
	Example: `  # Search for entries containing "bank"
  openpass find bank

  # JSON output
  openpass find bank --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return withVault(func(svc vaultsvc.Service) error {
			maybeAutoPull(svc.GetDir(), svc.Vault().Config)
			cfg := svc.Vault().Config
			workers := searchWorkers(svc.GetDir(), cfg)

			matches, err := svc.Find(args[0], vaultpkg.FindOptions{MaxWorkers: workers})
			if err != nil {
				return fmt.Errorf("search failed: %w", err)
			}

			if len(matches) == 0 {
				fmt.Fprintln(os.Stderr, "No matches found")
				return nil
			}

			if outputFormat != "text" {
				type matchEntry struct {
					Path   string   `json:"path"`
					Fields []string `json:"fields,omitempty"`
				}
				out := make([]matchEntry, 0, len(matches))
				for _, m := range matches {
					out = append(out, matchEntry{Path: m.Path, Fields: m.Fields})
				}
				if err := PrintResult(map[string]interface{}{"matches": out}); err != nil {
					return err
				}
				return nil
			}

			for _, m := range matches {
				printQuietAware("%s", render.ForTerminal(taint.Wrap(m.Path, taint.Provenance{Source: "cli.path"})))
				if len(m.Fields) > 0 {
					printQuietAware(" (matches: %s)", strings.Join(m.Fields, ", "))
				}
				printlnQuietAware()
			}

			return nil
		})
	},
}

func init() {
	rootCmd.AddCommand(findCmd)
}
