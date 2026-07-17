package exporter

import (
	"bytes"
	"encoding/csv"
	"io"
	"strings"
	"testing"
)

func TestCSVExporter_RoundTrip(t *testing.T) {
	entries := []ExportEntry{
		{Path: "github.com/user", Data: map[string]any{"username": "alice", "password": "s3cret"}},
		{Path: "work/aws", Data: map[string]any{"access_key": "AKIAIOSFODNN7", "username": "bob"}},
	}

	var buf bytes.Buffer
	exp := &CSVExporter{}

	if err := exp.Export(&buf, entries, nil); err != nil {
		t.Fatalf("Export: %v", err)
	}

	reader := csv.NewReader(&buf)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	if len(records) != 3 {
		t.Fatalf("got %d rows, want 3 (header + 2 data rows)", len(records))
	}

	// Header row: path, access_key, password, username (sorted)
	header := records[0]
	if header[0] != "path" {
		t.Errorf("first column = %q, want %q", header[0], "path")
	}

	// First data row
	if records[1][0] != "github.com/user" {
		t.Errorf("row 1 path = %q, want %q", records[1][0], "github.com/user")
	}

	// Second data row
	if records[2][0] != "work/aws" {
		t.Errorf("row 2 path = %q, want %q", records[2][0], "work/aws")
	}
}

func TestCSVExporter_RoundTripWithMapping(t *testing.T) {
	entries := []ExportEntry{
		{Path: "test", Data: map[string]any{"username": "alice", "password": "s3cret"}},
	}

	mapping := map[string]string{"username": "user", "password": "secret"}

	var buf bytes.Buffer
	exp := &CSVExporter{}

	if err := exp.Export(&buf, entries, mapping); err != nil {
		t.Fatalf("Export: %v", err)
	}

	reader := csv.NewReader(&buf)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	header := records[0]
	for _, h := range header[1:] {
		if h == "username" || h == "password" {
			t.Errorf("unmapped header %q should have been renamed by mapping", h)
		}
	}
}

func TestCSVExporter_EmptyEntries(t *testing.T) {
	var buf bytes.Buffer
	exp := &CSVExporter{}

	if err := exp.Export(&buf, nil, nil); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %d bytes", buf.Len())
	}
}

func TestCSVExporter_WriteErrorPropagation(t *testing.T) {
	w := &failWriter{errAfter: 0}
	exp := &CSVExporter{}
	entries := []ExportEntry{
		{Path: "test", Data: map[string]any{"key": "value"}},
	}

	err := exp.Export(w, entries, nil)
	if err == nil {
		t.Fatal("expected error from failing writer, got nil")
	}
}

func TestCSVExporter_FlushErrorPropagation(t *testing.T) {
	w := &failFlushWriter{err: io.ErrShortWrite}
	exp := &CSVExporter{}
	entries := []ExportEntry{
		{Path: "test", Data: map[string]any{"key": "value"}},
	}

	err := exp.Export(w, entries, nil)
	if err == nil {
		t.Fatal("expected error from failing flush, got nil")
	}
	if !strings.Contains(err.Error(), "flush csv writer") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "flush csv writer")
	}
}

// failWriter returns errAfter successful Write calls, then returns err on
// subsequent calls. This simulates a write failure after the CSV data has been
// buffered.
type failWriter struct {
	n        int
	errAfter int
	err      error
}

func (f *failWriter) Write(p []byte) (int, error) {
	f.n++
	if f.n > f.errAfter {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

type failFlushWriter struct {
	err error
}

func (w *failFlushWriter) Write(p []byte) (int, error) {
	return 0, w.err
}
