// Package exporter provides formatters for exporting vault entries to
// CSV and JSON formats for portability and backup.
package exporter

import (
	"fmt"
	"io"
)

// Format identifies the export format.
type Format string

const (
	FormatCSV  Format = "csv"
	FormatJSON Format = "json"
)

// ExportEntry represents a single vault entry for export.
type ExportEntry struct {
	Path string         `json:"path"`
	Data map[string]any `json:"data"`
}

// Exporter writes vault entries to a specific format.
type Exporter interface {
	// Export writes the entries to the given writer.
	Export(w io.Writer, entries []ExportEntry, mapping map[string]string) error
}

// FormatValidationError returns an error for unsupported formats.
func FormatValidationError(format Format) error {
	return fmt.Errorf("unsupported export format: %s", format)
}
