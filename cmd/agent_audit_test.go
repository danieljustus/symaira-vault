package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/audit"
)

func writeAuditLogFile(t *testing.T, path string, entries []audit.LogEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create audit log: %v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode entry: %v", err)
		}
	}
}

func TestReadAuditLog(t *testing.T) {
	vaultDir := t.TempDir()
	logPath := filepath.Join(vaultDir, "audit-test.log")

	now := time.Now().UTC()
	entries := []audit.LogEntry{
		{Timestamp: now.Add(-1 * time.Hour).Format(time.RFC3339), Agent: "test-agent", Action: "get_entry", Path: "secret/test", OK: true},
		{Timestamp: now.Add(-2 * time.Hour).Format(time.RFC3339), Agent: "test-agent", Action: "list_entries", OK: true},
		{Timestamp: now.Add(-3 * time.Hour).Format(time.RFC3339), Agent: "test-agent", Action: "get_entry", Path: "secret/other", Field: "password", OK: false, Reason: "denied"},
	}
	writeAuditLogFile(t, logPath, entries)

	result, err := readAuditLog(logPath, 0)
	if err != nil {
		t.Fatalf("readAuditLog() error: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("got %d entries, want 3", len(result))
	}

	if result[0].Action != "get_entry" {
		t.Errorf("first entry action = %q, want %q", result[0].Action, "get_entry")
	}
	if result[2].Reason != "denied" {
		t.Errorf("third entry reason = %q, want %q", result[2].Reason, "denied")
	}
}

func TestReadAuditLog_WithLimit(t *testing.T) {
	vaultDir := t.TempDir()
	logPath := filepath.Join(vaultDir, "audit-test.log")

	now := time.Now().UTC()
	entries := make([]audit.LogEntry, 10)
	for i := range entries {
		entries[i] = audit.LogEntry{
			Timestamp: now.Add(-time.Duration(i) * time.Hour).Format(time.RFC3339),
			Agent:     "test-agent",
			Action:    "get_entry",
			OK:        true,
		}
	}
	writeAuditLogFile(t, logPath, entries)

	result, err := readAuditLog(logPath, 3)
	if err != nil {
		t.Fatalf("readAuditLog() error: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("got %d entries, want 3", len(result))
	}
}

func TestReadAuditLog_EmptyFile(t *testing.T) {
	vaultDir := t.TempDir()
	logPath := filepath.Join(vaultDir, "audit-empty.log")

	if err := os.WriteFile(logPath, []byte{}, 0644); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	result, err := readAuditLog(logPath, 0)
	if err != nil {
		t.Fatalf("readAuditLog() error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("got %d entries, want 0", len(result))
	}
}

func TestReadAuditLog_SkipInvalidLines(t *testing.T) {
	vaultDir := t.TempDir()
	logPath := filepath.Join(vaultDir, "audit-test.log")

	now := time.Now().UTC().Format(time.RFC3339)
	content := `{"ts":"` + now + `","agent":"a","action":"get","ok":true}
not valid json
{"ts":"` + now + `","agent":"b","action":"list","ok":true}
`
	if err := os.WriteFile(logPath, []byte(content), 0644); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	result, err := readAuditLog(logPath, 0)
	if err != nil {
		t.Fatalf("readAuditLog() error: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("got %d entries, want 2 (invalid lines should be skipped)", len(result))
	}
}

func TestReadAuditLog_NotFound(t *testing.T) {
	vaultDir := t.TempDir()

	_, err := readAuditLog(filepath.Join(vaultDir, "audit-nonexistent.log"), 0)
	if err == nil {
		t.Fatal("expected error for non-existent audit log")
	}
}

func TestSinceFilter(t *testing.T) {
	now := time.Now().UTC()
	recentTS := now.Add(-1 * time.Hour).Format(time.RFC3339)
	oldTS := now.Add(-25 * time.Hour).Format(time.RFC3339)
	mediumTS := now.Add(-5 * time.Hour).Format(time.RFC3339)

	entries := []audit.LogEntry{
		{Timestamp: recentTS, Action: "recent"},
		{Timestamp: oldTS, Action: "old"},
		{Timestamp: mediumTS, Action: "medium"},
	}

	filtered := sinceFilter(entries, "24h")

	if len(filtered) != 2 {
		t.Fatalf("filtered count = %d, want 2", len(filtered))
	}

	for _, e := range filtered {
		if e.Action == "old" {
			t.Error("should not include 'old' entry")
		}
	}
}

func TestSinceFilter_AllSinceFilter(t *testing.T) {
	now := time.Now().UTC()
	entries := []audit.LogEntry{
		{Timestamp: now.Add(-1 * time.Hour).Format(time.RFC3339), Action: "recent"},
		{Timestamp: now.Add(-2 * time.Hour).Format(time.RFC3339), Action: "still-recent"},
	}

	filtered := sinceFilter(entries, "24h")

	if len(filtered) != 2 {
		t.Fatalf("filtered count = %d, want 2 (all entries within 24h)", len(filtered))
	}
}

func TestSinceFilter_NoSince(t *testing.T) {
	entries := []audit.LogEntry{
		{Timestamp: "2024-01-01T00:00:00Z", Action: "old"},
	}

	filtered := sinceFilter(entries, "")

	if len(filtered) != 1 {
		t.Fatalf("filtered count = %d, want 1 (no filter)", len(filtered))
	}
}

func TestSinceFilter_InvalidDuration(t *testing.T) {
	now := time.Now().UTC()
	entries := []audit.LogEntry{
		{Timestamp: now.Add(-1 * time.Hour).Format(time.RFC3339), Action: "recent"},
		{Timestamp: now.Add(-24 * time.Hour).Format(time.RFC3339), Action: "old"},
	}

	filtered := sinceFilter(entries, "not-a-duration")

	if len(filtered) != 2 {
		t.Fatalf("filtered count = %d, want 2 (invalid duration fallback)", len(filtered))
	}
}

func TestSinceFilter_MalformedTimestamp(t *testing.T) {
	now := time.Now().UTC()

	entries := []audit.LogEntry{
		{Timestamp: now.Add(-1 * time.Hour).Format(time.RFC3339), Action: "valid-ts"},
		{Timestamp: "not-a-timestamp", Action: "bad-ts"},
	}

	filtered := sinceFilter(entries, "2h")

	if len(filtered) != 1 {
		t.Fatalf("filtered count = %d, want 1 (bad timestamp skipped)", len(filtered))
	}
	if filtered[0].Action != "valid-ts" {
		t.Errorf("remaining entry action = %q, want %q", filtered[0].Action, "valid-ts")
	}
}
