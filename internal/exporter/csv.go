package exporter

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
)

// CSVExporter writes vault entries in CSV format.
type CSVExporter struct {
	// NoticeWriter receives per-entry notices when attachment fields are
	// omitted from the CSV output. When nil, no notices are emitted.
	NoticeWriter io.Writer
}

// Export writes entries as CSV with headers derived from entry data keys.
// If mapping is provided, it renames the output headers:
//   - mapping keys are vault field names
//   - mapping values are output column headers
func (e *CSVExporter) Export(w io.Writer, entries []ExportEntry, mapping map[string]string) error {
	if len(entries) == 0 {
		return nil
	}

	keySet := make(map[string]struct{})
	for _, entry := range entries {
		for key := range entry.Data {
			if isAttachmentField(key) {
				continue
			}
			keySet[key] = struct{}{}
		}
	}

	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	headers := make([]string, 0, len(keys)+1)
	headers = append(headers, "path")
	fieldOrder := []string{"__path__"}

	for _, key := range keys {
		header := key
		if mapped, ok := mapping[key]; ok {
			header = mapped
		}
		headers = append(headers, header)
		fieldOrder = append(fieldOrder, key)
	}

	writer := csv.NewWriter(w)

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}

	for _, entry := range entries {
		row := make([]string, 0, len(fieldOrder))
		hasAttachment := false
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
		if e.hasAttachmentFields(entry.Data) {
			hasAttachment = true
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("write CSV row: %w", err)
		}
		if hasAttachment && e.NoticeWriter != nil {
			if _, writeErr := fmt.Fprintf(e.NoticeWriter, "attachment data omitted for entry %s; use --format json for a lossless export\n", entry.Path); writeErr != nil {
				return fmt.Errorf("write attachment notice: %w", writeErr)
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush csv writer: %w", err)
	}
	return nil
}

func (e *CSVExporter) hasAttachmentFields(data map[string]any) bool {
	for key := range data {
		if isAttachmentField(key) {
			return true
		}
	}
	return false
}

func isAttachmentField(key string) bool {
	return strings.HasPrefix(key, "file_b64_") || key == "chunk_count" || key == "chunk_size"
}
