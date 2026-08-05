package admin

import (
	"crypto/rand"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/importer"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	ImportDryRun       bool
	ImportPrefix       string
	ImportSkipExisting bool
	ImportOverwrite    bool
	ImportMapping      string
	ImportQuarantine   bool
	ImportFormat       string
)

func newImportCmd() *cobra.Command {
	importCmd := &cobra.Command{
		Use:   "import <source>",
		Short: "Import entries from another password manager",
		Long: `Imports password entries from another password manager.

When --format is not specified, the format is auto-detected from the input file extension:
  .csv  → CSV format
  .json → JSON format
  .yaml/.yml → YAML format

CSV files are additionally header-sniffed: exports from Apple Passwords
(iCloud Keychain), Chrome/Chromium and Firefox are recognized from their
header row and mapped with a built-in profile. Use --format apple, --format
chrome or --format firefox to select a profile explicitly. Use --format to
override auto-detection or when the file extension does not match the actual
format.`,

		Example: `  # Auto-detect format from file extension
  symvault import bw-export.json --dry-run

  # Auto-detect the CSV profile from the header row (Apple Passwords, Chrome, Firefox)
  symvault import passwords.csv --dry-run

  # Explicitly specify a format (overrides auto-detection)
  symvault import bitwarden bw-export.json --dry-run

  # Import a Firefox export under a prefix, skipping entries that already exist
  symvault import logins.csv --format firefox --prefix work/ --skip-existing

  # Auto-detect CSV from .csv extension
  symvault import data.csv --overwrite`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sourcePath := args[0]

			var format importer.Format
			if ImportFormat != "" {
				format = importer.Format(strings.ToLower(strings.TrimSpace(ImportFormat)))
			} else {
				var err error
				format, err = detectFormatFromExt(sourcePath)
				if err != nil {
					return errorspkg.NewCLIError(errorspkg.ExitGeneralError, err.Error(), nil)
				}
			}
			if !isSupportedImportFormat(format) {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("unsupported import format: %s", format), nil)
			}

			// Sniff .csv files: match the header row against the built-in CSV
			// profiles (Apple Passwords, Chrome/Chromium, Firefox) before falling
			// back to the generic CSV mapping.
			if format == importer.FormatCSV && ImportFormat == "" {
				format = sniffOrKeepCSV(format, sourcePath)
			}

			// Dry-run reports the resolved format and the CSV mapping in effect,
			// so a user can verify the profile before writing anything.
			if err := reportDryRunImport(format); err != nil {
				return err
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

			source, err := os.Open(sourcePath) // #nosec G304 -- import source path is user-provided CLI argument
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

			return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
				// Batch mode: the write loop below would otherwise trigger a full
				// decrypt/re-encrypt/persist of the search index per entry (O(N²)
				// total). Suspend defers index maintenance; the deferred Resume
				// performs exactly one rebuild — even when the import fails midway —
				// and invalidates the index explicitly if that rebuild fails, so the
				// index is never left silently stale.
				if !options.DryRun {
					vaultpkg.SuspendSearchIndex(v.Dir)
					defer func() {
						if err := vaultpkg.ResumeSearchIndex(v.Dir, v.Identity); err != nil {
							cli.PrintQuietAware("Warning: search index rebuild failed after import; the index was invalidated and will be rebuilt on the next search: %v\n", err)
						}
					}()
				}

				imported, skipped, err := importEntries(vs, entries, options)
				if err != nil {
					return err
				}
				cli.PrintQuietAware("Import summary: %d imported, %d skipped\n", imported, skipped)
				return nil
			})
		},
	}
	importCmd.Flags().BoolVar(&ImportDryRun, "dry-run", false, "Parse import source without writing entries")
	importCmd.Flags().StringVar(&ImportPrefix, "prefix", "", "Prepend path to all imported entries")
	importCmd.Flags().BoolVar(&ImportSkipExisting, "skip-existing", false, "Skip entries that already exist")
	importCmd.Flags().BoolVar(&ImportOverwrite, "overwrite", false, "Delete existing entries before writing")
	importCmd.Flags().StringVar(&ImportMapping, "mapping", "", "CSV column mapping (format: title=col1,username=col2,...)")
	importCmd.Flags().BoolVar(&ImportQuarantine, "quarantine", false, "Import entries into quarantine/<import-id>/ for human review before agent access")
	importCmd.Flags().StringVar(&ImportFormat, "format", "", "Import format (auto-detected from file extension when omitted)")
	importCmd.GroupID = cli.GroupIDSharingSync
	importCmd.AddCommand(newImportReviewCmd())
	return importCmd
}

func isSupportedImportFormat(format importer.Format) bool {
	switch format {
	case importer.Format1Password, importer.FormatBitwarden, importer.FormatPass, importer.FormatCSV,
		importer.FormatApple, importer.FormatChrome, importer.FormatFirefox:
		return true
	default:
		return false
	}
}

// reportDryRunImport prints the resolved format and, for CSV imports, the
// field→column mapping in effect, so a user can verify the profile before
// writing anything.
func reportDryRunImport(format importer.Format) error {
	if !ImportDryRun {
		return nil
	}
	cli.PrintQuietAware("Import format: %s\n", format)
	if !importer.IsCSVFormat(format) {
		return nil
	}
	effective, err := importer.CSVEffectiveMapping(format, ImportMapping)
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "invalid CSV mapping", err)
	}
	mappingParts := make([]string, 0, len(effective))
	for field, column := range effective {
		mappingParts = append(mappingParts, field+"="+column)
	}
	sort.Strings(mappingParts)
	cli.PrintQuietAware("CSV mapping: %s\n", strings.Join(mappingParts, ", "))
	return nil
}

// sniffOrKeepCSV sniffs a .csv source against the built-in CSV profiles and
// returns the detected profile format, or the original format when the header
// matches none. It announces a detected profile on stdout.
func sniffOrKeepCSV(format importer.Format, sourcePath string) importer.Format {
	profile := sniffCSVProfile(sourcePath)
	if profile == importer.FormatCSV {
		return format
	}
	if p, ok := importer.CSVProfileFor(profile); ok {
		cli.PrintQuietAware("Detected %s CSV export from header row\n", p.Name)
	}
	return profile
}

// sniffCSVProfile reads the header row of a CSV file and returns the
// built-in profile it matches, or FormatCSV when no profile matches.
func sniffCSVProfile(sourcePath string) importer.Format {
	f, err := os.Open(sourcePath) // #nosec G304 -- import source path is user-provided CLI argument
	if err != nil {
		return importer.FormatCSV
	}
	defer func() { _ = f.Close() }()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return importer.FormatCSV
	}
	return importer.DetectCSVProfile(header)
}

// detectFormatFromExt derives the import format from the file extension.
// Returns an error if the extension does not match any known format.
func detectFormatFromExt(filename string) (importer.Format, error) {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".csv":
		return importer.FormatCSV, nil
	case ".json":
		return "json", nil
	case ".yaml", ".yml":
		return "yaml", nil
	default:
		return "", fmt.Errorf("cannot detect format from file extension %q; use --format to specify", ext)
	}
}

func newImporter(format importer.Format, options importer.ImportOptions) (importer.Importer, error) {
	if importer.IsCSVFormat(format) {
		if format == importer.FormatCSV {
			return importer.NewCSV(options.Mapping), nil
		}
		return importer.NewCSVProfile(format, options.Mapping)
	}
	return importer.New(format)
}

// importEntries writes the parsed entries into the vault, applying the
// import options (prefix, skip-existing, overwrite, dry-run) per entry. It
// returns the number of imported and skipped entries.
func importEntries(vs *cli.VaultService, entries []importer.ImportedEntry, options importer.ImportOptions) (imported, skipped int, err error) {
	for _, entry := range entries {
		entryPath := importEntryPath(options.Prefix, entry.Path)
		if entryPath == "" {
			skipped++
			cli.PrintQuietAware("Skipped entry with empty path\n")
			continue
		}

		exists, err := importEntryExists(vs, entryPath)
		if err != nil {
			return 0, 0, fmt.Errorf("cannot check entry: %w", err)
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
			if err := vs.DeleteEntry(entryPath); err != nil {
				return 0, 0, fmt.Errorf("cannot overwrite entry: %w", err)
			}
		}

		record := vaultpkg.WriteRecord{Action: "import"}
		if err := vs.SetFieldsWithProvenance(entryPath, entry.Data, record); err != nil {
			return 0, 0, fmt.Errorf("cannot write entry: %w", err)
		}
		if entry.SecretMetadata != nil {
			if err := vs.SetSecretMetadata(entryPath, *entry.SecretMetadata); err != nil {
				return 0, 0, fmt.Errorf("cannot set secret metadata: %w", err)
			}
		}
		cli.PrintQuietAware("Imported: %s\n", entryPath)
		imported++
	}
	return imported, skipped, nil
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

func importEntryExists(vs *cli.VaultService, entryPath string) (bool, error) {
	_, err := vs.GetEntry(entryPath)
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

func newImportReviewCmd() *cobra.Command {
	importReviewCmd := &cobra.Command{
		Use:   "review",
		Short: "Review and manage quarantined imports",
	}
	importReviewCmd.AddCommand(newImportReviewListCmd())
	importReviewCmd.AddCommand(newImportReviewPromoteCmd())
	return importReviewCmd
}

func newImportReviewListCmd() *cobra.Command {
	importReviewListCmd := &cobra.Command{
		Use:   "list",
		Short: "List quarantined import batches",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
				entries, err := vs.ListEntries("quarantine/")
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
	return importReviewListCmd
}

func newImportReviewPromoteCmd() *cobra.Command {
	importReviewPromoteCmd := &cobra.Command{
		Use:   "promote <import-id>",
		Short: "Promote quarantined entries to their final vault paths",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			importID := args[0]
			quarantinePrefix := "quarantine/" + importID + "/"
			return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
				entries, err := vs.ListEntries(quarantinePrefix)
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
					exists, existsErr := importEntryExists(vs, destPath)
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
					entry, readErr := vs.GetEntry(entryPath)
					if readErr != nil {
						cli.PrintQuietAware("Warning: failed to read %s: %v\n", entryPath, readErr)
						hadError = true
						continue
					}
					// Write to destination
					if writeErr := vs.WriteEntry(destPath, entry); writeErr != nil {
						cli.PrintQuietAware("Warning: failed to write %s: %v\n", destPath, writeErr)
						hadError = true
						continue
					}
					if deleteErr := vs.DeleteEntry(entryPath); deleteErr != nil {
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
	importReviewPromoteCmd.Flags().BoolVar(&ReviewPromoteOverwrite, "overwrite", false, "Overwrite existing entries at destination")
	return importReviewPromoteCmd
}
