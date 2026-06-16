package exporter

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
)

// CSVExporter writes vault entries in CSV format.
type CSVExporter struct{}

// Export writes entries as CSV with headers derived from entry data keys.
// If mapping is provided, it renames the output headers:
//   - mapping keys are vault field names
//   - mapping values are output column headers
func (e *CSVExporter) Export(w io.Writer, entries []ExportEntry, mapping map[string]string) error {
	if len(entries) == 0 {
		return nil
	}

	// Collect all unique data keys across all entries
	keySet := make(map[string]struct{})
	for _, entry := range entries {
		for key := range entry.Data {
			keySet[key] = struct{}{}
		}
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Build header row with optional mapping
	headers := make([]string, 0, len(keys)+1)
	headers = append(headers, "path") // path is always the first column
	fieldOrder := []string{"__path__"}

	for _, key := range keys {
		header := key
		if mapped, ok := mapping[key]; ok {
			header = mapped
		}
		headers = append(headers, header)
		fieldOrder = append(fieldOrder, key)
	}

	// Write CSV
	writer := csv.NewWriter(w)
	defer writer.Flush()

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}

	for _, entry := range entries {
		row := make([]string, 0, len(fieldOrder))
		for _, field := range fieldOrder {
			if field == "__path__" {
				row = append(row, entry.Path)
				continue
			}
			value := ""
			if v, ok := entry.Data[field]; ok {
				value = fmt.Sprintf("%v", v)
			}
			row = append(row, value)
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("write CSV row: %w", err)
		}
	}

	return nil
}
