package exporter

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONStream_SingleEntry(t *testing.T) {
	entry := ExportEntry{
		Path: "test/path",
		Data: map[string]any{"password": "s3cret", "user": "alice"},
	}

	var buf bytes.Buffer
	stream := NewJSONStream(&buf, nil)
	if err := stream.WriteEntry(entry); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var result []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("got %d entries, want 1", len(result))
	}
	if result[0]["path"] != "test/path" {
		t.Errorf("path = %q, want %q", result[0]["path"], "test/path")
	}
	data := result[0]["data"].(map[string]any)
	if data["password"] != "s3cret" {
		t.Errorf("password = %q, want %q", data["password"], "s3cret")
	}
}

func TestJSONStream_MultipleEntries(t *testing.T) {
	entries := []ExportEntry{
		{Path: "a/b", Data: map[string]any{"k1": "v1"}},
		{Path: "c/d", Data: map[string]any{"k2": "v2"}},
		{Path: "e/f", Data: map[string]any{"k3": "v3"}},
	}

	var buf bytes.Buffer
	stream := NewJSONStream(&buf, nil)
	for _, entry := range entries {
		if err := stream.WriteEntry(entry); err != nil {
			t.Fatalf("WriteEntry %s: %v", entry.Path, err)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var result []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("got %d entries, want 3", len(result))
	}
	for i, want := range []string{"a/b", "c/d", "e/f"} {
		if result[i]["path"] != want {
			t.Errorf("entry %d path = %q, want %q", i, result[i]["path"], want)
		}
	}
}

func TestJSONStream_Empty(t *testing.T) {
	var buf bytes.Buffer
	stream := NewJSONStream(&buf, nil)
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if buf.String() != "[]" {
		t.Errorf("empty output = %q, want %q", buf.String(), "[]")
	}
}

func TestJSONStream_MappingApplied(t *testing.T) {
	entry := ExportEntry{
		Path: "test",
		Data: map[string]any{"username": "alice", "password": "s3cret"},
	}
	mapping := map[string]string{"username": "user", "password": "secret"}

	var buf bytes.Buffer
	stream := NewJSONStream(&buf, mapping)
	if err := stream.WriteEntry(entry); err != nil {
		t.Fatalf("WriteEntry: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var result []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	data := result[0]["data"].(map[string]any)
	if _, ok := data["username"]; ok {
		t.Error("original key 'username' should have been mapped")
	}
	if data["user"] != "alice" {
		t.Errorf("mapped key 'user' = %q, want %q", data["user"], "alice")
	}
	if _, ok := data["password"]; ok {
		t.Error("original key 'password' should have been mapped")
	}
	if data["secret"] != "s3cret" {
		t.Errorf("mapped key 'secret' = %q, want %q", data["secret"], "s3cret")
	}
}

func TestJSONStream_ByteIdenticalToExport(t *testing.T) {
	entries := []ExportEntry{
		{Path: "a/b", Data: map[string]any{"password": "s3cret", "user": "alice"}},
		{Path: "c/d", Data: map[string]any{"token": "abc123", "host": "example.com"}},
	}
	mapping := map[string]string{"user": "username"}

	var batchBuf bytes.Buffer
	batchExp := &JSONExporter{}
	if err := batchExp.Export(&batchBuf, entries, mapping); err != nil {
		t.Fatalf("batch Export: %v", err)
	}

	var streamBuf bytes.Buffer
	stream := NewJSONStream(&streamBuf, mapping)
	for _, entry := range entries {
		if err := stream.WriteEntry(entry); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !bytes.Equal(batchBuf.Bytes(), streamBuf.Bytes()) {
		t.Errorf("output mismatch.\nbatch:  %q\nstream: %q", batchBuf.String(), streamBuf.String())
	}
}

func TestJSONStream_ByteIdenticalToExport_NilMapping(t *testing.T) {
	entries := []ExportEntry{
		{Path: "x", Data: map[string]any{"a": "1", "b": "2"}},
		{Path: "y", Data: map[string]any{"c": "3"}},
	}

	var batchBuf bytes.Buffer
	batchExp := &JSONExporter{}
	if err := batchExp.Export(&batchBuf, entries, nil); err != nil {
		t.Fatalf("batch Export: %v", err)
	}

	var streamBuf bytes.Buffer
	stream := NewJSONStream(&streamBuf, nil)
	for _, entry := range entries {
		if err := stream.WriteEntry(entry); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !bytes.Equal(batchBuf.Bytes(), streamBuf.Bytes()) {
		t.Errorf("output mismatch (nil mapping).\nbatch:  %q\nstream: %q", batchBuf.String(), streamBuf.String())
	}
}

func TestJSONStream_ByteIdenticalToExport_EmptyMapping(t *testing.T) {
	entries := []ExportEntry{
		{Path: "only", Data: map[string]any{"file_b64_0001": "dGVzdA==", "chunk_count": "1"}},
	}

	var batchBuf bytes.Buffer
	batchExp := &JSONExporter{}
	if err := batchExp.Export(&batchBuf, entries, map[string]string{}); err != nil {
		t.Fatalf("batch Export: %v", err)
	}

	var streamBuf bytes.Buffer
	stream := NewJSONStream(&streamBuf, map[string]string{})
	for _, entry := range entries {
		if err := stream.WriteEntry(entry); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !bytes.Equal(batchBuf.Bytes(), streamBuf.Bytes()) {
		t.Errorf("output mismatch (empty mapping).\nbatch:  %q\nstream: %q", batchBuf.String(), streamBuf.String())
	}
}

func TestJSONStream_ByteIdenticalToExport_LargerDataMaps(t *testing.T) {
	entries := []ExportEntry{
		{
			Path: "work/prod/db",
			Data: map[string]any{
				"host":     "db.example.com",
				"port":     "5432",
				"user":     "admin",
				"password": "supersecret",
				"name":     "production",
				"sslmode":  "require",
			},
		},
		{
			Path: "work/prod/api",
			Data: map[string]any{
				"base_url":   "https://api.example.com",
				"api_key":    "ak_test_12345",
				"timeout_ms": "30000",
			},
		},
		{
			Path: "personal/email",
			Data: map[string]any{
				"email":    "user@example.com",
				"password": "emailpass",
				"server":   "imap.example.com",
			},
		},
	}

	var batchBuf bytes.Buffer
	batchExp := &JSONExporter{}
	if err := batchExp.Export(&batchBuf, entries, nil); err != nil {
		t.Fatalf("batch Export: %v", err)
	}

	var streamBuf bytes.Buffer
	stream := NewJSONStream(&streamBuf, nil)
	for _, entry := range entries {
		if err := stream.WriteEntry(entry); err != nil {
			t.Fatalf("WriteEntry: %v", err)
		}
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !bytes.Equal(batchBuf.Bytes(), streamBuf.Bytes()) {
		t.Errorf("output mismatch (larger data maps).\nbatch:  %q\nstream: %q", batchBuf.String(), streamBuf.String())
	}
}
