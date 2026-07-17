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

// JSONStream writes JSON entries one at a time to reduce peak memory.
// Create with NewJSONStream, call WriteEntry for each entry in order,
// then call Close. The output is byte-identical to JSONExporter.Export
// for the same input.
type JSONStream struct {
	w       io.Writer
	mapping map[string]string
	count   int
}

// NewJSONStream returns a streaming JSON writer. The mapping renames output
// keys in each entry's data object (same semantics as JSONExporter.Export).
func NewJSONStream(w io.Writer, mapping map[string]string) *JSONStream {
	return &JSONStream{w: w, mapping: mapping}
}

// WriteEntry appends one entry to the JSON array. Entries MUST be written
// in index order (0, 1, 2, …). The method is not safe for concurrent use.
func (s *JSONStream) WriteEntry(entry ExportEntry) error {
	if s.count == 0 {
		if _, err := fmt.Fprint(s.w, "[\n"); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprint(s.w, ",\n"); err != nil {
			return err
		}
	}

	row := map[string]any{
		"path": entry.Path,
	}
	data := make(map[string]any, len(entry.Data))
	for k, v := range entry.Data {
		key := k
		if mappedKey, ok := s.mapping[k]; ok {
			key = mappedKey
		}
		data[key] = v
	}
	row["data"] = data

	b, err := json.MarshalIndent(row, "  ", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	// MarshalIndent omits the prefix on the first line; prepend one level
	// of array indentation to match json.Encoder output.
	if _, err := s.w.Write([]byte("  ")); err != nil {
		return err
	}
	if _, err := s.w.Write(b); err != nil {
		return err
	}

	s.count++
	return nil
}

// Close finalizes the JSON array. It writes the closing bracket and trailing
// newline (matching json.Encoder.Encode behavior) or "[]" for zero entries.
func (s *JSONStream) Close() error {
	if s.count == 0 {
		_, err := fmt.Fprint(s.w, "[]")
		return err
	}
	_, err := fmt.Fprint(s.w, "\n]\n")
	return err
}
