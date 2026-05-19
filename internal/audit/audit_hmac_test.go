package audit

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHMACChainValidPasses(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("hmac-valid-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	for i := 0; i < 5; i++ {
		_ = logger.LogEntry(LogEntry{
			Agent:  "test-agent",
			Action: fmt.Sprintf("get-%d", i),
			Path:   "test/path",
			OK:     true,
			DurMs:  int64(i * 10),
		})
	}

	result, err := logger.Verify()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid chain, got Valid=false (verified=%d, tampered=%d, legacy=%d)",
			result.Verified, result.Tampered, result.Legacy)
	}
	if result.Total != 5 {
		t.Fatalf("Total = %d, want 5", result.Total)
	}
	if result.Verified != 5 {
		t.Fatalf("Verified = %d, want 5", result.Verified)
	}
	if result.Tampered != 0 {
		t.Fatalf("Tampered = %d, want 0", result.Tampered)
	}
	if result.Legacy != 0 {
		t.Fatalf("Legacy = %d, want 0", result.Legacy)
	}
	if result.FirstBadIdx != -1 {
		t.Fatalf("FirstBadIdx = %d, want -1", result.FirstBadIdx)
	}
}

func TestHMACTamperedEntryDetected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("hmac-tamper-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for i := 0; i < 3; i++ {
		_ = logger.LogEntry(LogEntry{
			Agent:  "test-agent",
			Action: fmt.Sprintf("get-%d", i),
			Path:   "test/path",
			OK:     true,
		})
	}
	_ = logger.Close()

	logFile := filepath.Join(home, ".openpass", "audit-hmac-tamper-test.log")
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %d", len(lines))
	}

	var tamperedLines []string
	for i, line := range lines {
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON on line %d: %v", i, err)
		}
		if i == 1 {
			entry["action"] = "tampered-action"
		}
		marshaled, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal error on line %d: %v", i, err)
		}
		tamperedLines = append(tamperedLines, string(marshaled))
	}

	tamperedContent := strings.Join(tamperedLines, "\n") + "\n"
	if err := os.WriteFile(logFile, []byte(tamperedContent), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	auditDir := filepath.Join(home, ".openpass")
	ks := NewKeystore(auditDir, nil)
	key, err := ks.LoadHMACKey()
	if err != nil {
		t.Fatalf("LoadHMACKey() error = %v", err)
	}

	result, err := VerifyLog(logFile, key)
	if err != nil {
		t.Fatalf("VerifyLog() error = %v", err)
	}
	if result.Valid {
		t.Fatal("expected tampered entry to be detected, got Valid=true")
	}
	if result.Tampered < 1 {
		t.Fatalf("Tampered = %d, want >= 1", result.Tampered)
	}
	if result.FirstBadIdx != 1 {
		t.Fatalf("FirstBadIdx = %d, want 1", result.FirstBadIdx)
	}
}

func TestHMACLegacyLogAccepted(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}

	logFile := filepath.Join(auditDir, "audit-legacy-test.log")
	legacyEntries := []string{
		`{"ts":"2024-01-01T00:00:00Z","agent":"test","action":"get","path":"a","ok":true}`,
		`{"ts":"2024-01-01T00:00:01Z","agent":"test","action":"set","path":"b","ok":false,"reason":"denied"}`,
		`{"ts":"2024-01-01T00:00:02Z","agent":"test","action":"list","ok":true}`,
	}
	if err := os.WriteFile(logFile, []byte(strings.Join(legacyEntries, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	logger, err := New("legacy-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	_ = logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "new-entry",
		Path:   "test/path",
		OK:     true,
	})

	result, err := logger.Verify()
	_ = logger.Close()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid chain after legacy entries (verified=%d, tampered=%d, legacy=%d)",
			result.Verified, result.Tampered, result.Legacy)
	}
	if result.Total != 4 {
		t.Fatalf("Total = %d, want 4", result.Total)
	}
	if result.Legacy != 3 {
		t.Fatalf("Legacy = %d, want 3", result.Legacy)
	}
	if result.Verified != 1 {
		t.Fatalf("Verified = %d, want 1", result.Verified)
	}
}

func TestHMACEmptyLog(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("hmac-empty-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	result, err := logger.Verify()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Valid {
		t.Fatal("expected empty log to be valid")
	}
	if result.Total != 0 {
		t.Fatalf("Total = %d, want 0", result.Total)
	}
}

func TestHMACChainContinuity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("hmac-chain-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	_ = logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "first",
		Path:   "test/path",
		OK:     true,
	})

	hmac1 := logger.prevHMAC
	if len(hmac1) != 32 {
		t.Fatalf("prevHMAC length = %d, want 32", len(hmac1))
	}

	_ = logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "second",
		Path:   "test/path",
		OK:     true,
	})

	hmac2 := logger.prevHMAC
	if hex.EncodeToString(hmac1) == hex.EncodeToString(hmac2) {
		t.Fatal("expected different HMACs for different entries")
	}

	result, err := logger.Verify()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Valid {
		t.Fatal("expected valid chain")
	}
	if result.Verified != 2 {
		t.Fatalf("Verified = %d, want 2", result.Verified)
	}
}

func TestHMACLoggerNilSafety(t *testing.T) {
	var l *Logger
	_ = l.LogEntry(LogEntry{
		Agent:  "test",
		Action: "get",
		OK:     true,
	})

	result, err := l.Verify()
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	if result != nil {
		t.Fatal("expected nil result for nil logger")
	}
}

func TestHMACMultipleWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("hmac-multi-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	for i := 0; i < 10; i++ {
		_ = logger.LogEntry(LogEntry{
			Agent:  "test-agent",
			Action: fmt.Sprintf("action-%d", i),
			Path:   "test/path",
			OK:     i%2 == 0,
		})
	}

	content, err := os.ReadFile(filepath.Join(home, ".openpass", "audit-hmac-multi-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 10 {
		t.Fatalf("expected 10 lines, got %d", len(lines))
	}

	for i, line := range lines {
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON on line %d: %v", i, err)
		}
		if entry.HMAC == "" {
			t.Fatalf("line %d: expected HMAC field to be set", i)
		}
		if len(entry.HMAC) != hexHMACSize {
			t.Fatalf("line %d: HMAC length = %d, want %d", i, len(entry.HMAC), hexHMACSize)
		}
	}

	result, err := logger.Verify()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid chain (verified=%d, tampered=%d, legacy=%d)",
			result.Verified, result.Tampered, result.Legacy)
	}
}

func TestHMACVerifyFileNotFound(t *testing.T) {
	result, err := VerifyLog("/nonexistent/path/audit.log", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent files")
	}
	if result != nil {
		t.Fatal("expected nil result for error")
	}
}

func TestHMACCanonicalJSONExcludesHMAC(t *testing.T) {
	entry := LogEntry{
		Agent:  "test",
		Action: "get",
		Path:   "some/path",
		OK:     true,
		HMAC:   "abc123",
	}

	canonical := canonicalJSON(entry)
	if strings.Contains(string(canonical), "hmac") {
		t.Fatalf("canonicalJSON should exclude hmac field, got: %s", canonical)
	}
	if !strings.Contains(string(canonical), "test") {
		t.Fatal("canonicalJSON missing agent field")
	}
}

func TestHMACReopenRetainsChain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("hmac-reopen-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_ = logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "first",
		Path:   "test/path",
		OK:     true,
	})
	_ = logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "second",
		Path:   "test/path",
		OK:     true,
	})
	_ = logger.Close()

	logger2, err := New("hmac-reopen-test", "")
	if err != nil {
		t.Fatalf("New() error on reopen = %v", err)
	}
	defer func() { _ = logger2.Close() }()

	logger2.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "third",
		Path:   "test/path",
		OK:     true,
	})

	result, err := logger2.Verify()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid chain after reopen (verified=%d, tampered=%d, legacy=%d)",
			result.Verified, result.Tampered, result.Legacy)
	}
	if result.Verified != 3 {
		t.Fatalf("Verified = %d, want 3", result.Verified)
	}
}

func TestHMACMixedLegacyAndNew(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("MkdirAll error = %v", err)
	}

	logFile := filepath.Join(auditDir, "audit-mixed-test.log")
	legacyLine := `{"ts":"2024-01-01T00:00:00Z","agent":"test","action":"legacy-get","path":"a","ok":true}` + "\n"
	if err := os.WriteFile(logFile, []byte(legacyLine), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	logger, err := New("mixed-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	_ = logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "new-get",
		Path:   "test/path",
		OK:     true,
	})

	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var legacy, newEntry LogEntry
	if err := json.Unmarshal([]byte(lines[0]), &legacy); err != nil {
		t.Fatalf("legacy line invalid: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &newEntry); err != nil {
		t.Fatalf("new line invalid: %v", err)
	}
	if legacy.HMAC != "" {
		t.Fatal("legacy entry should not have HMAC")
	}
	if newEntry.HMAC == "" {
		t.Fatal("new entry should have HMAC")
	}
}
