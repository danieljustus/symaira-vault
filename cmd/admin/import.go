package admin

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/importer"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var (
	ImportDryRun       bool
	ImportPrefix       string
	ImportSkipExisting bool
	ImportOverwrite    bool
	ImportMapping      string
	ImportQuarantine   bool
)

var importCmd = &cobra.Command{
	Use:   "import <format> <source>",
	Short: "Import entries from another password manager",
	Long:  "Imports password entries from 1Password, Bitwarden, pass, or CSV exports.",
	Example: `  # Dry-run a Bitwarden export to see what would be imported
  openpass import bitwarden bw-export.json --dry-run

  # Import 1Password CSV under a prefix, skipping entries that already exist
  openpass import 1password export.csv --prefix work/ --skip-existing

  # Overwrite collisions
  openpass import csv data.csv --overwrite`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		format := importer.Format(strings.ToLower(strings.TrimSpace(args[0])))
		if !isSupportedImportFormat(format) {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("unsupported import format: %s", args[0]), nil)
		}

		if ImportSkipExisting && ImportOverwrite {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "--skip-existing and --overwrite cannot be used together", nil)
		}

		if ImportQuarantine && ImportPrefix != "" {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "--quarantine and --prefix cannot be used together", nil)
		}

		options := importer.ImportOptions{
			DryRun:       ImportDryRun,
			Prefix:       strings.Trim(ImportPrefix, "/"),
			SkipExisting: ImportSkipExisting,
			Overwrite:    ImportOverwrite,
			Mapping:      ImportMapping,
		}

		if ImportQuarantine {
			importID := generateImportID()
			options.Prefix = "quarantine/" + importID
			cli.PrintQuietAware("Quarantine import ID: %s\n", importID)
		}

		if _, err := importer.ParseMapping(options.Mapping); err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "invalid CSV mapping", err)
		}

		source, err := os.Open(args[1]) //nolint:gosec G304 — import source path is user-provided CLI argument
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "open import source", err)
		}
		defer func() { _ = source.Close() }()

		fi, err := source.Stat()
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "stat import source", err)
		}
		if fi.Size() > importer.MaxImportSize {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
				fmt.Sprintf("import source exceeds maximum size of %d bytes", importer.MaxImportSize), nil)
		}

		imp, err := newImporter(format, options)
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "create importer", err)
		}

		entries, err := imp.Parse(source)
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "parse import source", err)
		}

		return cli.WithVault(func(svc vaultsvc.Service) error {
			imported, skipped := 0, 0
			for _, entry := range entries {
				entryPath := importEntryPath(options.Prefix, entry.Path)
				if entryPath == "" {
					skipped++
					cli.PrintQuietAware("Skipped entry with empty path\n")
					continue
				}

				exists, err := importEntryExists(svc, entryPath)
				if err != nil {
					return fmt.Errorf("cannot check entry: %w", err)
				}

				if exists && options.SkipExisting {
					skipped++
					cli.PrintQuietAware("Skipped existing: %s\n", entryPath)
					continue
				}

				if options.DryRun {
					cli.PrintQuietAware("Would import: %s\n", entryPath)
					imported++
					continue
				}

				if exists && options.Overwrite {
					if err := svc.Delete(entryPath); err != nil {
						return fmt.Errorf("cannot overwrite entry: %w", err)
					}
				}

				record := vaultpkg.WriteRecord{Action: "import"}
				if err := svc.SetFieldsWithProvenance(entryPath, entry.Data, record); err != nil {
					return fmt.Errorf("cannot write entry: %w", err)
				}
				cli.PrintQuietAware("Imported: %s\n", entryPath)
				imported++
			}

			cli.PrintQuietAware("Import summary: %d imported, %d skipped\n", imported, skipped)
			return nil
		})
	},
}

func init() {
	importCmd.Flags().BoolVar(&ImportDryRun, "dry-run", false, "Parse import source without writing entries")
	importCmd.Flags().StringVar(&ImportPrefix, "prefix", "", "Prepend path to all imported entries")
	importCmd.Flags().BoolVar(&ImportSkipExisting, "skip-existing", false, "Skip entries that already exist")
	importCmd.Flags().BoolVar(&ImportOverwrite, "overwrite", false, "Delete existing entries before writing")
	importCmd.Flags().StringVar(&ImportMapping, "mapping", "", "CSV column mapping (format: title=col1,username=col2,...)")
	importCmd.Flags().BoolVar(&ImportQuarantine, "quarantine", false, "Import entries into quarantine/<import-id>/ for human review before agent access")
	cli.RootCmd.AddCommand(importCmd)
}

func isSupportedImportFormat(format importer.Format) bool {
	switch format {
	case importer.Format1Password, importer.FormatBitwarden, importer.FormatPass, importer.FormatCSV:
		return true
	default:
		return false
	}
}

func newImporter(format importer.Format, options importer.ImportOptions) (importer.Importer, error) {
	if format == importer.FormatCSV {
		return importer.NewCSV(options.Mapping), nil
	}
	return importer.New(format)
}

func importEntryPath(prefix, entryPath string) string {
	entryPath = strings.Trim(entryPath, "/")
	if prefix == "" {
		return entryPath
	}
	if entryPath == "" {
		return prefix
	}
	return path.Join(prefix, entryPath)
}

func generateImportID() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		nano := time.Now().UnixNano()
		if nano < 0 {
			nano = 0
		}
		// Extract lower 32 bits via modulo to avoid G115 int-conversion alerts.
		return fmt.Sprintf("import-%s-%08x", time.Now().UTC().Format("20060102"), nano%0x100000000)
	}
	return fmt.Sprintf("import-%s-%x", time.Now().UTC().Format("20060102"), buf)
}

func importEntryExists(svc vaultsvc.Service, entryPath string) (bool, error) {
	_, err := svc.GetEntry(entryPath)
	if err == nil {
		return true, nil
	}

	var cliErr *errorspkg.CLIError
	if errors.As(err, &cliErr) && cliErr.Code == errorspkg.ExitNotFound {
		return false, nil
	}
	return false, err
}

var ReviewPromoteOverwrite bool

var importReviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Review and manage quarantined imports",
}

var importReviewListCmd = &cobra.Command{
	Use:   "list",
	Short: "List quarantined import batches",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVault(func(svc vaultsvc.Service) error {
			entries, err := svc.List("quarantine/")
			if err != nil {
				return fmt.Errorf("list quarantine: %w", err)
			}
			// Group by import-id (path format: quarantine/<import-id>/<rest>)
			batches := make(map[string]int)
			for _, e := range entries {
				parts := strings.SplitN(strings.TrimPrefix(e, "quarantine/"), "/", 2)
				if len(parts) > 0 && parts[0] != "" {
					batches[parts[0]]++
				}
			}
			if len(batches) == 0 {
				cli.PrintQuietAware("No quarantined imports found.\n")
				return nil
			}
			ids := make([]string, 0, len(batches))
			for id := range batches {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				cli.PrintQuietAware("%s  (%d entries)\n", id, batches[id])
			}
			return nil
		})
	},
}

var importReviewPromoteCmd = &cobra.Command{
	Use:   "promote <import-id>",
	Short: "Promote quarantined entries to their final vault paths",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		importID := args[0]
		quarantinePrefix := "quarantine/" + importID + "/"
		return cli.WithVault(func(svc vaultsvc.Service) error {
			entries, err := svc.List(quarantinePrefix)
			if err != nil {
				return fmt.Errorf("list quarantine batch: %w", err)
			}
			if len(entries) == 0 {
				return fmt.Errorf("no quarantined entries found for import-id %q", importID)
			}
			hadError := false
			for _, entryPath := range entries {
				destPath := strings.TrimPrefix(entryPath, quarantinePrefix)
				if destPath == "" {
					continue
				}
				// Check if destination already exists
				exists, existsErr := importEntryExists(svc, destPath)
				if existsErr != nil {
					cli.PrintQuietAware("Warning: cannot check destination %s: %v\n", destPath, existsErr)
					hadError = true
					continue
				}
				if exists && !ReviewPromoteOverwrite {
					cli.PrintQuietAware("Warning: skipping %s — destination already exists (use --overwrite)\n", destPath)
					hadError = true
					continue
				}
				// Read source entry
				entry, readErr := svc.GetEntry(entryPath)
				if readErr != nil {
					cli.PrintQuietAware("Warning: failed to read %s: %v\n", entryPath, readErr)
					hadError = true
					continue
				}
				// Write to destination
				if writeErr := svc.WriteEntry(destPath, entry); writeErr != nil {
					cli.PrintQuietAware("Warning: failed to write %s: %v\n", destPath, writeErr)
					hadError = true
					continue
				}
				if deleteErr := svc.Delete(entryPath); deleteErr != nil {
					cli.PrintQuietAware("Warning: failed to delete quarantine entry %s: %v\n", entryPath, deleteErr)
					// Don't set hadError — promote succeeded
				}
				cli.PrintQuietAware("Promoted: %s\n", destPath)
			}
			if hadError {
				return fmt.Errorf("some entries could not be promoted")
			}
			return nil
		})
	},
}

func init() {
	importReviewPromoteCmd.Flags().BoolVar(&ReviewPromoteOverwrite, "overwrite", false, "Overwrite existing entries at destination")
	importReviewCmd.AddCommand(importReviewListCmd)
	importReviewCmd.AddCommand(importReviewPromoteCmd)
	importCmd.AddCommand(importReviewCmd)
}
