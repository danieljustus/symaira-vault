package admin

import (
	"fmt"
	"io"
	"os"
	"sync"
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

			out, createErr := fsutil.CreateSensitiveOutput(ExportOutput)
			if createErr != nil {
				return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "create output file", createErr)
			}
			defer func() {
				if closeErr := out.Close(); closeErr != nil && retErr == nil {
					retErr = errorspkg.NewCLIError(errorspkg.ExitGeneralError, "close output file", closeErr)
				}
			}()

			workers := 0
			if v.Config != nil && v.Config.Vault != nil {
				workers = v.Config.Vault.SearchWorkers
			}
			maxWorkers := vaultpkg.SearchWorkerCount(workers)

			entryChan := make(chan struct {
				index int
				path  string
			}, len(entries))
			resultChan := make(chan exportResult, len(entries))

			done := make(chan struct{})
			var cancelOnce sync.Once
			cancel := func() { cancelOnce.Do(func() { close(done) }) }

			var wg sync.WaitGroup
			for i := 0; i < maxWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for item := range entryChan {
						select {
						case <-done:
							return
						default:
						}
						entry, readErr := vs.GetEntry(item.path)
						if readErr != nil {
							resultChan <- exportResult{
								index: item.index,
								err:   fmt.Errorf("read entry %s: %w", item.path, readErr),
							}
							cancel()
							return
						}
						resultChan <- exportResult{
							index: item.index,
							entry: exporter.ExportEntry{
								Path: item.path,
								Data: entry.Data,
							},
						}
					}
				}()
			}

			go func() {
				defer close(entryChan)
				for i, path := range entries {
					select {
					case <-done:
						return
					case entryChan <- struct {
						index int
						path  string
					}{index: i, path: path}:
					}
				}
			}()

			go func() {
				wg.Wait()
				close(resultChan)
			}()

			if format == exporter.FormatJSON {
				if err := exportJSONStreaming(out, resultChan, mapping); err != nil {
					return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "export entries", err)
				}
			} else {
				exportEntries := make([]exporter.ExportEntry, len(entries))
				for result := range resultChan {
					if result.err != nil {
						return result.err
					}
					exportEntries[result.index] = result.entry
				}

				exp, expErr := newExporter(format)
				if expErr != nil {
					return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "create exporter", expErr)
				}
				if err := exp.Export(out, exportEntries, mapping); err != nil {
					return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "export entries", err)
				}
			}

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

			cli.PrintQuietAware("Exported %d entries\n", len(entries))
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

type exportResult struct {
	index int
	entry exporter.ExportEntry
	err   error
}

func exportJSONStreaming(out io.Writer, resultChan <-chan exportResult, mapping map[string]string) error {
	stream := exporter.NewJSONStream(out, mapping)

	pending := make(map[int]exporter.ExportEntry)
	nextIdx := 0

	for result := range resultChan {
		if result.err != nil {
			return result.err
		}
		if result.index == nextIdx {
			if err := stream.WriteEntry(result.entry); err != nil {
				return err
			}
			nextIdx++
			for {
				if entry, ok := pending[nextIdx]; ok {
					delete(pending, nextIdx)
					if err := stream.WriteEntry(entry); err != nil {
						return err
					}
					nextIdx++
				} else {
					break
				}
			}
		} else {
			pending[result.index] = result.entry
		}
	}

	return stream.Close()
}
