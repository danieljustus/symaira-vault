package admin

import (
	"fmt"
	"io"
	"os"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/exporter"
	"github.com/danieljustus/symaira-vault/internal/importer"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	ExportFormat  string
	ExportMapping string
	ExportOutput  string
)

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

		if _, err := importer.ParseMapping(ExportMapping); err != nil {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "invalid mapping", err)
		}

		return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
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
				entry, err := vs.GetEntry(entryPath)
				if err != nil {
					return fmt.Errorf("read entry %s: %w", entryPath, err)
				}
				exportEntries = append(exportEntries, exporter.ExportEntry{
					Path: entryPath,
					Data: entry.Data,
				})
			}

			// Determine output destination
			var w io.Writer
			if ExportOutput != "" {
				f, err := os.Create(ExportOutput) //nolint:gosec G304 — output path is user-provided CLI argument
				if err != nil {
					return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "create output file", err)
				}
				defer func() { _ = f.Close() }()
				w = f
			} else {
				w = os.Stdout
			}

			// Parse mapping
			mapping, err := importer.ParseMapping(ExportMapping)
			if err != nil {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "parse mapping", err)
			}

			// Export
			if err := exp.Export(w, exportEntries, mapping); err != nil {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "export entries", err)
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
		return &exporter.CSVExporter{}, nil
	case exporter.FormatJSON:
		return &exporter.JSONExporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}
