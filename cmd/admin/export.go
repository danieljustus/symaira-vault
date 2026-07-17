package admin

import (
	"fmt"
	"os"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-vault/internal/audit"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/exporter"
	"github.com/danieljustus/symaira-vault/internal/fsutil"
	"github.com/danieljustus/symaira-vault/internal/importer"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	ExportFormat  string
	ExportMapping string
	ExportOutput  string
	ExportYes     bool
)

// confirmExport prompts the user for confirmation before exporting vault entries.
// Tests may replace this to control stdin behavior without modifying
// cli.ConfirmInteractive's shared implementation.
var confirmExport = cli.ConfirmInteractive

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export vault entries to CSV or JSON",
	Long:  "Exports all vault entries in CSV or JSON format for portability and backup.",
	Example: `  # Export all entries as JSON
  symvault export --format json

  # Export as CSV to a file
  symvault export --format csv --output ~/vault-export.csv

  # Export with field mapping (rename columns)
  symvault export --format csv --mapping "path=title,username=user,password=secret"`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		format := exporter.Format(ExportFormat)
		if !isSupportedExportFormat(format) {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, fmt.Sprintf("unsupported export format: %s", ExportFormat), nil)
		}

		mapping, err := importer.ParseMapping(ExportMapping)
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "invalid mapping", err)
		}

		const warningMsg = "WARNING: Vault export produces unencrypted output. All secrets will be in plaintext."
		if ExportYes {
			// Scripting mode: respect --quiet suppression via cliout.
			cliout.Warnf(warningMsg)
		} else {
			// Interactive mode: always show, even in quiet — user must see before confirming.
			fmt.Fprintln(os.Stderr, warningMsg)
		}

		confirmed, err := confirmExport("Export all vault entries as plaintext?", ExportYes)
		if err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "export confirmation failed", err)
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "Export canceled.")
			return nil
		}

		return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) (retErr error) {
			entries, err := vs.ListEntries("")
			if err != nil {
				return fmt.Errorf("list entries: %w", err)
			}

			if len(entries) == 0 {
				cli.PrintQuietAware("No entries found in vault.\n")
				return nil
			}

			exp, err := newExporter(format)
			if err != nil {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "create exporter", err)
			}

			// Read all entries
			var exportEntries []exporter.ExportEntry
			for _, entryPath := range entries {
				entry, readErr := vs.GetEntry(entryPath)
				if readErr != nil {
					return fmt.Errorf("read entry %s: %w", entryPath, readErr)
				}
				exportEntries = append(exportEntries, exporter.ExportEntry{
					Path: entryPath,
					Data: entry.Data,
				})
			}

			// Determine output destination
			out, createErr := fsutil.CreateSensitiveOutput(ExportOutput)
			if createErr != nil {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "create output file", createErr)
			}
			defer func() {
				if closeErr := out.Close(); closeErr != nil && retErr == nil {
					retErr = errorspkg.NewCLIError(errorspkg.ExitGeneralError, "close output file", closeErr)
				}
			}()

			// Export
			if err := exp.Export(out, exportEntries, mapping); err != nil {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "export entries", err)
			}

			// Best-effort audit log — do not fail the export on audit errors.
			if auditLog, auditErr := audit.New("symvault", v.Dir, v.Identity); auditErr == nil {
				if logErr := auditLog.LogEntry(audit.LogEntry{
					Action:    "export",
					OK:        true,
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				}); logErr != nil {
					cliout.Warnf("Warning: audit log write failed: %v", logErr)
				}
				if closeErr := auditLog.Close(); closeErr != nil {
					cliout.Warnf("Warning: audit log close failed: %v", closeErr)
				}
			}

			cli.PrintQuietAware("Exported %d entries\n", len(exportEntries))
			return nil
		})
	},
}

func init() {
	exportCmd.Flags().StringVar(&ExportFormat, "format", "", "Export format: csv or json (required)")
	exportCmd.Flags().StringVar(&ExportMapping, "mapping", "", "Column mapping (format: vault_field=output_header,...)")
	exportCmd.Flags().StringVar(&ExportOutput, "output", "", "Output file path (default: stdout)")
	exportCmd.Flags().BoolVarP(&ExportYes, "yes", "y", false, "Skip confirmation prompt")
	_ = exportCmd.MarkFlagRequired("format") //nolint:errcheck
	cli.RootCmd.AddCommand(exportCmd)
}

func isSupportedExportFormat(format exporter.Format) bool {
	switch format {
	case exporter.FormatCSV, exporter.FormatJSON:
		return true
	default:
		return false
	}
}

func newExporter(format exporter.Format) (exporter.Exporter, error) {
	switch format {
	case exporter.FormatCSV:
		return &exporter.CSVExporter{NoticeWriter: os.Stderr}, nil
	case exporter.FormatJSON:
		return &exporter.JSONExporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}
