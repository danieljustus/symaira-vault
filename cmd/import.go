package cmd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/importer"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var (
	importDryRun       bool
	importPrefix       string
	importSkipExisting bool
	importOverwrite    bool
	importMapping      string
	importQuarantine   bool
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

		if importSkipExisting && importOverwrite {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "--skip-existing and --overwrite cannot be used together", nil)
		}

		if importQuarantine && importPrefix != "" {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "--quarantine and --prefix cannot be used together", nil)
		}

		options := importer.ImportOptions{
			DryRun:       importDryRun,
			Prefix:       strings.Trim(importPrefix, "/"),
			SkipExisting: importSkipExisting,
			Overwrite:    importOverwrite,
			Mapping:      importMapping,
		}

		if importQuarantine {
			importID := generateImportID()
			options.Prefix = "quarantine/" + importID
			printQuietAware("Quarantine import ID: %s\n", importID)
		}

		if _, err := importer.ParseMapping(options.Mapping); err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "invalid CSV mapping", err)
		}

		source, err := os.Open(args[1])
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

		return withVault(func(svc vaultsvc.Service) error {
			imported, skipped := 0, 0
			for _, entry := range entries {
				entryPath := importEntryPath(options.Prefix, entry.Path)
				if entryPath == "" {
					skipped++
					printQuietAware("Skipped entry with empty path\n")
					continue
				}

				exists, err := importEntryExists(svc, entryPath)
				if err != nil {
					return fmt.Errorf("cannot check entry: %w", err)
				}

				if exists && options.SkipExisting {
					skipped++
					printQuietAware("Skipped existing: %s\n", entryPath)
					continue
				}

				if options.DryRun {
					printQuietAware("Would import: %s\n", entryPath)
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
				printQuietAware("Imported: %s\n", entryPath)
				imported++
			}

			printQuietAware("Import summary: %d imported, %d skipped\n", imported, skipped)
			return nil
		})
	},
}

func init() {
	importCmd.Flags().BoolVar(&importDryRun, "dry-run", false, "Parse import source without writing entries")
	importCmd.Flags().StringVar(&importPrefix, "prefix", "", "Prepend path to all imported entries")
	importCmd.Flags().BoolVar(&importSkipExisting, "skip-existing", false, "Skip entries that already exist")
	importCmd.Flags().BoolVar(&importOverwrite, "overwrite", false, "Delete existing entries before writing")
	importCmd.Flags().StringVar(&importMapping, "mapping", "", "CSV column mapping (format: title=col1,username=col2,...)")
	importCmd.Flags().BoolVar(&importQuarantine, "quarantine", false, "Import entries into quarantine/<import-id>/ for human review before agent access")
	rootCmd.AddCommand(importCmd)
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
		return fmt.Sprintf("import-%s-%08x", time.Now().UTC().Format("20060102"), uint32(time.Now().UnixNano()))
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
