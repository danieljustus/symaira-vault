package audit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestLog(t *testing.T, dir, agent string, entries []LogEntry) {
	t.Helper()
	path := filepath.Join(dir, "audit-"+agent+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, e := range entries {
		data, _ := json.Marshal(e)
		data = append(data, '\n')
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
}

func writeTestLogWithHMAC(t *testing.T, dir, agent string, entries []LogEntry, key []byte) {
	t.Helper()
	path := filepath.Join(dir, "audit-"+agent+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	mac := hmac.New(sha256.New, key)
	var prevHMAC []byte
	for i := range entries {
		if len(key) > 0 {
			entries[i].HMAC = computeHMACWith(mac, prevHMAC, entries[i])
			if hb, derr := hex.DecodeString(entries[i].HMAC); derr == nil {
				prevHMAC = hb
			}
		}
		data, _ := json.Marshal(entries[i])
		data = append(data, '\n')
		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRedactPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"", ""},
		{"/home/user/.symvault/entries/github.age", "redacted:"},
		{"/home/user/.symvault/entries/work/aws.age", "redacted:"},
	}
	for _, tt := range tests {
		got := RedactPath(tt.path)
		if tt.want == "" && got != "" {
			t.Errorf("RedactPath(%q) = %q, want empty", tt.path, got)
		}
		if tt.want != "" && len(got) <= len(tt.want) {
			t.Errorf("RedactPath(%q) = %q, want prefix %q", tt.path, got, tt.want)
		}
	}
}

func TestRedactPathDeterministic(t *testing.T) {
	path := "/home/user/.symvault/entries/github.age"
	got1 := RedactPath(path)
	got2 := RedactPath(path)
	if got1 != got2 {
		t.Errorf("RedactPath not deterministic: %q != %q", got1, got2)
	}
}

func TestLoadAuditLogFiles(t *testing.T) {
	dir := t.TempDir()
	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "get_entry", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "set_entry", OK: true},
		{Timestamp: "2026-01-03T00:00:00Z", Agent: "test", Action: "get_entry", OK: false},
	}
	writeTestLog(t, dir, "test", entries)

	got, err := LoadAuditLogFiles("test", dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
}

func TestLoadAuditLogFilesLimit(t *testing.T) {
	dir := t.TempDir()
	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "a", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "b", OK: true},
		{Timestamp: "2026-01-03T00:00:00Z", Agent: "test", Action: "c", OK: true},
		{Timestamp: "2026-01-04T00:00:00Z", Agent: "test", Action: "d", OK: true},
		{Timestamp: "2026-01-05T00:00:00Z", Agent: "test", Action: "e", OK: true},
	}
	writeTestLog(t, dir, "test", entries)

	got, err := LoadAuditLogFiles("test", dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Action != "d" || got[1].Action != "e" {
		t.Errorf("expected last 2 entries, got %v", got)
	}
}

func TestLoadAuditLogFilesZeroLimit(t *testing.T) {
	dir := t.TempDir()
	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "a", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "b", OK: true},
	}
	writeTestLog(t, dir, "test", entries)

	got, err := LoadAuditLogFiles("test", dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("limit=0 should return all entries, got %d", len(got))
	}
}

func TestLoadAuditLogFilesWithRotated(t *testing.T) {
	dir := t.TempDir()
	entries1 := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "old", OK: true},
	}
	entries2 := []LogEntry{
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "new", OK: true},
	}
	writeTestLog(t, dir, "test", entries1)
	// Rotate: rename current to rotated
	rotated := filepath.Join(dir, "audit-test.log.rotated.20260101-120000")
	os.Rename(filepath.Join(dir, "audit-test.log"), rotated)
	writeTestLog(t, dir, "test", entries2)

	got, err := LoadAuditLogFiles("test", dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got[0].Action != "old" || got[1].Action != "new" {
		t.Errorf("entries not in chronological order: %v", got)
	}
}

func TestMatchesSinceFilter(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		timestamp string
		since     string
		want      bool
	}{
		{now.Format(time.RFC3339), "1h", true},
		{now.Add(-30 * time.Minute).Format(time.RFC3339), "1h", true},
		{now.Add(-2 * time.Hour).Format(time.RFC3339), "1h", false},
		{now.Add(-6 * 24 * time.Hour).Format(time.RFC3339), "7d", true},
		{now.Add(-8 * 24 * time.Hour).Format(time.RFC3339), "7d", false},
		{now.Format(time.RFC3339), "", true},
	}
	for _, tt := range tests {
		got := MatchesSinceFilter(tt.timestamp, tt.since)
		if got != tt.want {
			t.Errorf("MatchesSinceFilter(%q, %q) = %v, want %v", tt.timestamp, tt.since, got, tt.want)
		}
	}
}

func TestVerifyExportLog(t *testing.T) {
	key := []byte("test-hmac-key-32-bytes-long!!")

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "a", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "b", OK: true},
		{Timestamp: "2026-01-03T00:00:00Z", Agent: "test", Action: "c", OK: true},
	}

	// Sign entries
	mac := hmac.New(sha256.New, key)
	var prevHMAC []byte
	for i := range entries {
		entries[i].HMAC = computeHMACWith(mac, prevHMAC, entries[i])
		if hb, derr := hex.DecodeString(entries[i].HMAC); derr == nil {
			prevHMAC = hb
		}
	}

	statuses, err := VerifyExportLog(entries, key)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range statuses {
		if s != "verified" {
			t.Errorf("entry %d: expected verified, got %s", i, s)
		}
	}
}

func TestVerifyExportLogTampered(t *testing.T) {
	key := []byte("test-hmac-key-32-bytes-long!!")

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "a", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "b", OK: true},
	}

	// Sign entries
	mac := hmac.New(sha256.New, key)
	var prevHMAC []byte
	for i := range entries {
		entries[i].HMAC = computeHMACWith(mac, prevHMAC, entries[i])
		if hb, derr := hex.DecodeString(entries[i].HMAC); derr == nil {
			prevHMAC = hb
		}
	}

	// Tamper with entry
	entries[1].Action = "tampered"

	statuses, err := VerifyExportLog(entries, key)
	if err != nil {
		t.Fatal(err)
	}
	if statuses[0] != "verified" {
		t.Errorf("entry 0: expected verified, got %s", statuses[0])
	}
	if statuses[1] != "tampered" {
		t.Errorf("entry 1: expected tampered, got %s", statuses[1])
	}
}

func TestVerifyExportLogLegacy(t *testing.T) {
	key := []byte("test-hmac-key-32-bytes-long!!")

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "a", OK: true}, // no HMAC
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "b", OK: true},
	}

	// Only sign second entry
	mac := hmac.New(sha256.New, key)
	entries[1].HMAC = computeHMACWith(mac, nil, entries[1])

	statuses, err := VerifyExportLog(entries, key)
	if err != nil {
		t.Fatal(err)
	}
	if statuses[0] != "legacy" {
		t.Errorf("entry 0: expected legacy, got %s", statuses[0])
	}
	if statuses[1] != "verified" {
		t.Errorf("entry 1: expected verified, got %s", statuses[1])
	}
}

func TestVerifyExportLogEmptyKey(t *testing.T) {
	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "a", OK: true},
	}
	_, err := VerifyExportLog(entries, nil)
	if err == nil {
		t.Error("expected error for empty key")
	}
}

func TestExportAuditLogJSON(t *testing.T) {
	dir := t.TempDir()
	home := dir

	// Create audit dir
	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "get_entry", OK: true, Path: "github/token"},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "set_entry", OK: true, Path: "work/aws"},
	}
	writeTestLog(t, auditDir, "test", entries)

	// Override home dir for testing
	t.Setenv("HOME", home)

	var buf bytes.Buffer
	opts := ExportOptions{Agent: "test"}
	result, err := ExportAuditLog(opts, &buf, "json")
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 entries, got %d", result.Total)
	}

	var decoded ExportResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Entries) != 2 {
		t.Errorf("expected 2 entries in JSON, got %d", len(decoded.Entries))
	}
}

func TestExportAuditLogTable(t *testing.T) {
	dir := t.TempDir()
	home := dir

	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "get_entry", OK: true},
	}
	writeTestLog(t, auditDir, "test", entries)

	t.Setenv("HOME", home)

	var buf bytes.Buffer
	opts := ExportOptions{Agent: "test"}
	_, err := ExportAuditLog(opts, &buf, "table")
	if err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("TIME")) {
		t.Error("table output missing header")
	}
	if !bytes.Contains(buf.Bytes(), []byte("get_entry")) {
		t.Error("table output missing entry action")
	}
	_ = output
}

func TestExportAuditLogActionFilter(t *testing.T) {
	dir := t.TempDir()
	home := dir

	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "get_entry", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "set_entry", OK: true},
		{Timestamp: "2026-01-03T00:00:00Z", Agent: "test", Action: "get_entry", OK: true},
	}
	writeTestLog(t, auditDir, "test", entries)

	t.Setenv("HOME", home)

	var buf bytes.Buffer
	opts := ExportOptions{Agent: "test", Action: "set_entry"}
	result, err := ExportAuditLog(opts, &buf, "json")
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("action filter: expected 1 entry for set_entry, got %d", result.Total)
	}
	if len(result.Entries) > 0 && result.Entries[0].Action != "set_entry" {
		t.Errorf("expected set_entry action, got %s", result.Entries[0].Action)
	}
}

func TestExportAuditLogFailedOnly(t *testing.T) {
	dir := t.TempDir()
	home := dir

	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "get_entry", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "set_entry", OK: false},
		{Timestamp: "2026-01-03T00:00:00Z", Agent: "test", Action: "get_entry", OK: true},
	}
	writeTestLog(t, auditDir, "test", entries)

	t.Setenv("HOME", home)

	var buf bytes.Buffer
	opts := ExportOptions{Agent: "test", FailedOnly: true}
	result, err := ExportAuditLog(opts, &buf, "json")
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("failed-only filter: expected 1 entry, got %d", result.Total)
	}
}

func TestExportAuditLogRedactPaths(t *testing.T) {
	dir := t.TempDir()
	home := dir

	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "get_entry", OK: true, Path: "github/token"},
	}
	writeTestLog(t, auditDir, "test", entries)

	t.Setenv("HOME", home)

	var buf bytes.Buffer
	opts := ExportOptions{Agent: "test", RedactPaths: true}
	result, err := ExportAuditLog(opts, &buf, "json")
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 entry, got %d", result.Total)
	}
	if result.Entries[0].Path != "" {
		t.Errorf("path should be cleared when redacting, got %q", result.Entries[0].Path)
	}
	if result.Entries[0].RedactedPath == "" {
		t.Error("redacted path should be set")
	}
}

func TestExportAuditLogVerifyHMAC(t *testing.T) {
	dir := t.TempDir()
	home := dir

	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	key := []byte("test-hmac-key-32-bytes-long!!")
	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "get_entry", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "set_entry", OK: true},
	}
	writeTestLogWithHMAC(t, auditDir, "test", entries, key)

	t.Setenv("HOME", home)

	var buf bytes.Buffer
	opts := ExportOptions{Agent: "test", VerifyHMAC: true, HMACKey: key}
	result, err := ExportAuditLog(opts, &buf, "json")
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified != 2 {
		t.Errorf("expected 2 verified, got %d", result.Verified)
	}
	if result.Tampered != 0 {
		t.Errorf("expected 0 tampered, got %d", result.Tampered)
	}
}

func TestExportAuditLogVerifyHMACKeyRequired(t *testing.T) {
	var buf bytes.Buffer
	opts := ExportOptions{VerifyHMAC: true}
	_, err := ExportAuditLog(opts, &buf, "json")
	if err == nil {
		t.Error("expected error when VerifyHMAC is true but no key provided")
	}
}

func TestExportAuditLogEmpty(t *testing.T) {
	dir := t.TempDir()
	home := dir

	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	t.Setenv("HOME", home)

	var buf bytes.Buffer
	opts := ExportOptions{Agent: "nonexistent"}
	result, err := ExportAuditLog(opts, &buf, "json")
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 0 {
		t.Errorf("expected 0 entries, got %d", result.Total)
	}
}

func TestStreamExportAuditLog(t *testing.T) {
	dir := t.TempDir()
	home := dir

	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "a", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "b", OK: true},
		{Timestamp: "2026-01-03T00:00:00Z", Agent: "test", Action: "c", OK: true},
	}
	writeTestLog(t, auditDir, "test", entries)

	t.Setenv("HOME", home)

	var count int
	callback := func(entry ExportEntry) bool {
		count++
		return true
	}

	result, err := StreamExportAuditLog(ExportOptions{Agent: "test"}, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 3 {
		t.Errorf("expected 3 entries, got %d", result.Total)
	}
	if count != 3 {
		t.Errorf("callback called %d times, expected 3", count)
	}
}

func TestStreamExportAuditLogEarlyStop(t *testing.T) {
	dir := t.TempDir()
	home := dir

	auditDir := filepath.Join(home, ".symvault")
	os.MkdirAll(auditDir, 0o700)

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Agent: "test", Action: "a", OK: true},
		{Timestamp: "2026-01-02T00:00:00Z", Agent: "test", Action: "b", OK: true},
		{Timestamp: "2026-01-03T00:00:00Z", Agent: "test", Action: "c", OK: true},
	}
	writeTestLog(t, auditDir, "test", entries)

	t.Setenv("HOME", home)

	var count int
	callback := func(entry ExportEntry) bool {
		count++
		return count < 2
	}

	result, err := StreamExportAuditLog(ExportOptions{Agent: "test"}, callback)
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 {
		t.Errorf("expected 2 entries (early stop), got %d", result.Total)
	}
}

func TestParseSinceDuration(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
		err   bool
	}{
		{"1h", time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"invalid", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseSinceDuration(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("ParseSinceDuration(%q) error = %v, wantErr %v", tt.input, err, tt.err)
		}
		if got != tt.want {
			t.Errorf("ParseSinceDuration(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
