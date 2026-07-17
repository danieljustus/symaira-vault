package exporter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
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

func TestCSVExporter_AttachmentFieldsExcluded(t *testing.T) {
	entries := []ExportEntry{
		{
			Path: "github.com/user",
			Data: map[string]any{
				"username":      "alice",
				"password":      "s3cret",
				"file_b64_0001": "dGhpcyBpcyBhIHRlc3Q=",
				"file_b64_0002": "YW5vdGhlciBjaHVuaw==",
				"chunk_count":   "2",
				"chunk_size":    "4096",
			},
		},
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

	if len(records) != 2 {
		t.Fatalf("got %d rows, want 2 (header + 1 data)", len(records))
	}

	header := records[0]
	for _, h := range header[1:] {
		if strings.HasPrefix(h, "file_b64_") || h == "chunk_count" || h == "chunk_size" {
			t.Errorf("attachment field %q should not appear in headers", h)
		}
	}

	wantHeaders := []string{"path", "password", "username"}
	if len(header) != len(wantHeaders) {
		t.Fatalf("header count = %d, want %d: got %v", len(header), len(wantHeaders), header)
	}
	for i, want := range wantHeaders {
		if header[i] != want {
			t.Errorf("header[%d] = %q, want %q", i, header[i], want)
		}
	}

	dataRow := records[1]
	if dataRow[0] != "github.com/user" {
		t.Errorf("row path = %q, want %q", dataRow[0], "github.com/user")
	}
	if dataRow[1] != "s3cret" {
		t.Errorf("row password = %q, want %q", dataRow[1], "s3cret")
	}
	if dataRow[2] != "alice" {
		t.Errorf("row username = %q, want %q", dataRow[2], "alice")
	}
}

func TestCSVExporter_AttachmentFieldsOnly_EntryStillValid(t *testing.T) {
	entries := []ExportEntry{
		{
			Path: "work/attachment-only",
			Data: map[string]any{
				"file_b64_0001": "dGVzdA==",
				"chunk_count":   "1",
				"chunk_size":    "1024",
			},
		},
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

	if len(records) != 2 {
		t.Fatalf("got %d rows, want 2 (header + 1 data)", len(records))
	}

	header := records[0]
	if len(header) != 1 || header[0] != "path" {
		t.Errorf("header = %v, want [path] only", header)
	}

	dataRow := records[1]
	if len(dataRow) != 1 || dataRow[0] != "work/attachment-only" {
		t.Errorf("data row = %v, want [work/attachment-only]", dataRow)
	}
}

func TestCSVExporter_AttachNoticeEmitted(t *testing.T) {
	entries := []ExportEntry{
		{
			Path: "github.com/user",
			Data: map[string]any{"username": "alice", "file_b64_0001": "dGVzdA==", "chunk_count": "1"},
		},
		{
			Path: "work/aws",
			Data: map[string]any{"access_key": "AKIAIOSFODNN7"},
		},
	}

	var csvBuf bytes.Buffer
	var noticeBuf bytes.Buffer
	exp := &CSVExporter{NoticeWriter: &noticeBuf}

	if err := exp.Export(&csvBuf, entries, nil); err != nil {
		t.Fatalf("Export: %v", err)
	}

	notices := noticeBuf.String()
	if !strings.Contains(notices, "github.com/user") {
		t.Errorf("notice missing affected path, got: %q", notices)
	}
	if strings.Contains(notices, "work/aws") {
		t.Errorf("notice should not mention unaffected entry, got: %q", notices)
	}
	if !strings.Contains(notices, "lossless") {
		t.Errorf("notice should mention lossless JSON export, got: %q", notices)
	}
	if !strings.Contains(notices, "--format json") {
		t.Errorf("notice should mention --format json, got: %q", notices)
	}

	lines := strings.Split(strings.TrimSpace(notices), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 notice line, got %d: %q", len(lines), notices)
	}
}

func TestCSVExporter_NoNoticeWhenNoAttachments(t *testing.T) {
	entries := []ExportEntry{
		{Path: "test", Data: map[string]any{"username": "alice"}},
	}

	var csvBuf bytes.Buffer
	var noticeBuf bytes.Buffer
	exp := &CSVExporter{NoticeWriter: &noticeBuf}

	if err := exp.Export(&csvBuf, entries, nil); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if noticeBuf.Len() != 0 {
		t.Errorf("expected no notices, got: %q", noticeBuf.String())
	}
}

func TestCSVExporter_NoNoticeWhenNoticeWriterNil(t *testing.T) {
	entries := []ExportEntry{
		{Path: "test", Data: map[string]any{"file_b64_0001": "dGVzdA=="}},
	}

	var csvBuf bytes.Buffer
	exp := &CSVExporter{}

	if err := exp.Export(&csvBuf, entries, nil); err != nil {
		t.Fatalf("Export: %v", err)
	}
}

func TestJSONExporter_AttachmentFieldsPreserved(t *testing.T) {
	entries := []ExportEntry{
		{
			Path: "github.com/user",
			Data: map[string]any{
				"username":      "alice",
				"password":      "s3cret",
				"file_b64_0001": "dGhpcyBpcyBhIHRlc3Q=",
				"chunk_count":   "2",
				"chunk_size":    "4096",
			},
		},
	}

	var buf bytes.Buffer
	exp := &JSONExporter{}

	if err := exp.Export(&buf, entries, nil); err != nil {
		t.Fatalf("Export: %v", err)
	}

	var result []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("got %d entries, want 1", len(result))
	}

	data := result[0]["data"].(map[string]any)
	wantKeys := []string{"username", "password", "file_b64_0001", "chunk_count", "chunk_size"}
	for _, key := range wantKeys {
		if _, ok := data[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}
}
