package exporter

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSONExporter writes vault entries in JSON format.
type JSONExporter struct{}

// Export writes entries as a JSON array. If mapping is provided, it renames
// the output keys in each entry's data object.
func (e *JSONExporter) Export(w io.Writer, entries []ExportEntry, mapping map[string]string) error {
	if len(entries) == 0 {
		_, err := fmt.Fprint(w, "[]")
		return err
	}

	// Apply mapping to entries if provided
	mapped := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		row := map[string]any{
			"path": entry.Path,
		}

		data := make(map[string]any, len(entry.Data))
		for k, v := range entry.Data {
			key := k
			if mappedKey, ok := mapping[k]; ok {
				key = mappedKey
			}
			data[key] = v
		}
		row["data"] = data
		mapped = append(mapped, row)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(mapped); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}
