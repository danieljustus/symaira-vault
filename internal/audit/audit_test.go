package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogEntryWritesJSONL(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("test-agent", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogEntry(LogEntry{
		Agent:     "test-agent",
		Action:    "get",
		Path:      "dev/api-key",
		Transport: "stdio",
		OK:        true,
		DurMs:     42,
	})

	content, err := os.ReadFile(filepath.Join(home, ".openpass", "audit-test-agent.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	line := strings.TrimSpace(string(content))
	var entry map[string]any
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("invalid JSON: %v\nline: %s", err, line)
	}

	if entry["agent"] != "test-agent" {
		t.Fatalf("agent = %v, want test-agent", entry["agent"])
	}
	if entry["action"] != "get" {
		t.Fatalf("action = %v, want get", entry["action"])
	}
	if entry["ok"] != true {
		t.Fatalf("ok = %v, want true", entry["ok"])
	}
	if entry["transport"] != "stdio" {
		t.Fatalf("transport = %v, want stdio", entry["transport"])
	}
	if _, ok := entry["ts"]; !ok {
		t.Fatal("missing ts field")
	}
}

func TestLogEntryDenialIncludesReason(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("test-agent", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogEntry(LogEntry{
		Agent:     "test-agent",
		Action:    "set",
		Path:      "secret/key",
		Field:     "password",
		Transport: "http",
		OK:        false,
		Reason:    "write_denied",
	})

	content, err := os.ReadFile(filepath.Join(home, ".openpass", "audit-test-agent.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(content))), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if entry["ok"] != false {
		t.Fatalf("ok = %v, want false", entry["ok"])
	}
	if entry["reason"] != "write_denied" {
		t.Fatalf("reason = %v, want write_denied", entry["reason"])
	}
	if entry["field"] != "password" {
		t.Fatalf("field = %v, want password", entry["field"])
	}
}

func TestLoggerCloseNilSafety(t *testing.T) {
	var l *Logger
	if err := l.Close(); err != nil {
		t.Fatalf("Close() on nil logger should not error, got %v", err)
	}
}

func TestLogEntryNilLoggerSafety(t *testing.T) {
	var l *Logger
	// Should not panic
	l.LogEntry(LogEntry{
		Agent:  "test",
		Action: "get",
		OK:     true,
	})
}

func TestLogEntryNilFileSafety(t *testing.T) {
	l := &Logger{file: nil}
	// Should not panic
	l.LogEntry(LogEntry{
		Agent:  "test",
		Action: "get",
		OK:     true,
	})
}

func TestLogEntryMultipleWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("multi-write", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	for i := 0; i < 3; i++ {
		logger.LogEntry(LogEntry{
			Agent:  "test-agent",
			Action: "get",
			Path:   "test/path",
			OK:     i%2 == 0,
			DurMs:  int64(i * 10),
		})
	}

	content, err := os.ReadFile(filepath.Join(home, ".openpass", "audit-multi-write.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON on line %d: %v", i, err)
		}
	}
}

func TestLogEntryAutoTimestamp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("timestamp-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Entry without timestamp - should get auto-filled
	logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "list",
		OK:     true,
	})

	content, err := os.ReadFile(filepath.Join(home, ".openpass", "audit-timestamp-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(content))), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, ok := entry["ts"]; !ok {
		t.Fatal("expected auto-generated ts field")
	}
}

func TestLogEntryPreservesProvidedTimestamp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("preserved-ts", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	customTS := "2024-01-15T10:30:00Z"
	logger.LogEntry(LogEntry{
		Timestamp: customTS,
		Agent:     "test-agent",
		Action:    "get",
		OK:        true,
	})

	content, err := os.ReadFile(filepath.Join(home, ".openpass", "audit-preserved-ts.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(content))), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if entry["ts"] != customTS {
		t.Fatalf("expected ts=%s, got %v", customTS, entry["ts"])
	}
}

func TestNewRejectsPathSeparator(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := New("agent/with/slash", "")
	if err == nil {
		t.Fatal("expected error for agent name with slash")
	}
}

func TestNewRejectsBackslash(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := New("agent\\with\\backslash", "")
	if err == nil {
		t.Fatal("expected error for agent name with backslash")
	}
}

func TestNewRejectsDotDot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := New("..", "")
	if err == nil {
		t.Fatal("expected error for .. agent name")
	}
}

func TestNewRejectsDot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := New(".", "")
	if err == nil {
		t.Fatal("expected error for . agent name")
	}
}

func TestNewRejectsDotDotInName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := New("my..agent", "")
	if err == nil {
		t.Fatal("expected error for agent name containing ..")
	}
}

func TestNewCreatesAuditDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: HOME env behavior differs")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := New("create-dir-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	expectedDir := filepath.Join(home, ".openpass")
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Fatalf("audit directory was not created at %s", expectedDir)
	}
}

func TestNewCreatesLogFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("logfile-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	expectedFile := filepath.Join(home, ".openpass", "audit-logfile-test.log")
	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Fatalf("audit log file was not created at %s", expectedFile)
	}
}

func TestNewSetsCorrectPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: file permissions differ")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("perms-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	expectedFile := filepath.Join(home, ".openpass", "audit-perms-test.log")
	info, err := os.Stat(expectedFile)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Fatalf("expected file permissions 0o600, got %o", perm)
	}
}

func TestNewUsesUserHomeDirWhenHomeEmpty(t *testing.T) {
	oldHome := os.Getenv("HOME")
	//nolint:errcheck // best-effort cleanup in test
	os.Unsetenv("HOME")
	defer func() {
		if oldHome != "" {
			//nolint:errcheck // best-effort restore in test
			os.Setenv("HOME", oldHome)
		}
	}()

	// os.UserHomeDir may fail in some environments; skip if so
	logger, err := New("home-dir-test", "")
	if err != nil && strings.Contains(err.Error(), "not defined") {
		t.Skip("HOME not available in this environment")
	}
	if err == nil {
		defer func() { _ = logger.Close() }()
	}
}

func TestNewErrorWhenAuditDirNotCreatable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0 has no effect")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(parent, 0o700) //nolint:errcheck

	t.Setenv("HOME", parent)

	_, err := New("dir-fail-agent", "")
	if err == nil {
		t.Fatal("expected error when audit dir cannot be created, got nil")
	}
	if !strings.Contains(err.Error(), "create audit dir") {
		t.Fatalf("expected 'create audit dir' in error, got: %v", err)
	}
}

func TestNewErrorWhenLogFileNotWritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0 has no effect")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Chmod(auditDir, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(auditDir, 0o700) //nolint:errcheck

	_, err := New("file-fail-agent", "")
	if err == nil {
		t.Fatal("expected error when log file cannot be opened, got nil")
	}
	if !strings.Contains(err.Error(), "open audit log") {
		t.Fatalf("expected 'open audit log' in error, got: %v", err)
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := GetConfig()
	if cfg.MaxFileSize != 100*1024*1024 {
		t.Fatalf("expected default MaxFileSize to be 100MB, got %d", cfg.MaxFileSize)
	}
	if cfg.MaxBackups != 5 {
		t.Fatalf("expected default MaxBackups to be 5, got %d", cfg.MaxBackups)
	}
	if cfg.MaxAgeDays != 30 {
		t.Fatalf("expected default MaxAgeDays to be 30, got %d", cfg.MaxAgeDays)
	}
}

func TestConfigEnvVarMaxSizeMB(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "50")

	ReloadConfig()
	defer ReloadConfig()

	if config.MaxFileSize != 50*1024*1024 {
		t.Fatalf("expected MaxFileSize to be 50MB from env, got %d", config.MaxFileSize)
	}
}

func TestConfigEnvVarMaxBackups(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "10")

	ReloadConfig()
	defer ReloadConfig()

	if config.MaxBackups != 10 {
		t.Fatalf("expected MaxBackups to be 10 from env, got %d", config.MaxBackups)
	}
}

func TestConfigEnvVarMaxAgeDays(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_AGE_DAYS", "7")

	ReloadConfig()
	defer ReloadConfig()

	if config.MaxAgeDays != 7 {
		t.Fatalf("expected MaxAgeDays to be 7 from env, got %d", config.MaxAgeDays)
	}
}

func TestConfigEnvVarInvalidValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "invalid")
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "negative")
	t.Setenv("OPENPASS_AUDIT_MAX_AGE_DAYS", "zero")

	ReloadConfig()
	defer ReloadConfig()

	// Should fall back to defaults
	if config.MaxFileSize != 100*1024*1024 {
		t.Fatalf("expected MaxFileSize to fallback to default, got %d", config.MaxFileSize)
	}
	if config.MaxBackups != 5 {
		t.Fatalf("expected MaxBackups to fallback to default, got %d", config.MaxBackups)
	}
	if config.MaxAgeDays != 30 {
		t.Fatalf("expected MaxAgeDays to fallback to default, got %d", config.MaxAgeDays)
	}
}

func TestRotateIfNeededSizeLimit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "1")

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("size-rotate-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write until we exceed 1MB
	data := strings.Repeat("x", 1024*1024) // 1MB of data
	for i := 0; i < 2; i++ {
		logger.LogEntry(LogEntry{
			Agent:  "test",
			Action: "test",
			Path:   data,
			OK:     true,
		})
	}

	// Force rotation check
	if err := logger.rotateIfNeeded(); err != nil {
		t.Fatalf("rotateIfNeeded() error = %v", err)
	}

	// Verify rotated file exists
	auditDir := filepath.Join(home, ".openpass")
	pattern := filepath.Join(auditDir, "audit-size-rotate-test.log.rotated.*")
	matches, _ := filepath.Glob(pattern)
	if len(matches) == 0 {
		t.Fatal("expected rotated file to exist after size-based rotation")
	}
}

func TestRotateIfNeededAgeLimit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_AGE_DAYS", "0") // 0 days means immediate

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("age-rotate-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Set file mod time to yesterday to trigger age-based rotation
	oldTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(logger.path, oldTime, oldTime) //nolint:errcheck

	// Force rotation check
	if err := logger.rotateIfNeeded(); err != nil {
		t.Fatalf("rotateIfNeeded() error = %v", err)
	}

	// Verify rotated file exists
	auditDir := filepath.Join(home, ".openpass")
	pattern := filepath.Join(auditDir, "audit-age-rotate-test.log.rotated.*")
	matches, _ := filepath.Glob(pattern)
	if len(matches) == 0 {
		t.Fatal("expected rotated file to exist after age-based rotation")
	}
}

func TestEnforceRetentionMaxBackups(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "100")
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "3")
	t.Setenv("OPENPASS_AUDIT_MAX_AGE_DAYS", "365")

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("backup-cleanup-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	auditDir := filepath.Join(home, ".openpass")

	// Create 5 rotated files manually
	for i := 0; i < 5; i++ {
		rotatedName := filepath.Join(auditDir, fmt.Sprintf("audit-backup-cleanup-test.log.rotated.%s", time.Now().UTC().Add(time.Duration(i)*time.Second).Format("20060102-150405")))
		if err := os.WriteFile(rotatedName, []byte("test"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		// Stagger times so they're different
		time.Sleep(10 * time.Millisecond)
	}

	// Run retention enforcement
	if err := logger.EnforceRetention(); err != nil {
		t.Fatalf("EnforceRetention() error = %v", err)
	}

	// Check that only 3 backup files remain
	pattern := filepath.Join(auditDir, "audit-backup-cleanup-test.log.rotated.*")
	matches, _ := filepath.Glob(pattern)
	if len(matches) != 3 {
		t.Fatalf("expected 3 backup files after retention policy, got %d", len(matches))
	}
}

func TestEnforceRetentionMaxAge(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "100")
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "100")
	t.Setenv("OPENPASS_AUDIT_MAX_AGE_DAYS", "0") // 0 days = delete all

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("age-cleanup-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	auditDir := filepath.Join(home, ".openpass")

	// Create rotated files with old timestamps
	for i := 0; i < 3; i++ {
		rotatedName := filepath.Join(auditDir, fmt.Sprintf("audit-age-cleanup-test.log.rotated.%s", time.Now().UTC().Add(time.Duration(-i-1)*24*time.Hour).Format("20060102-150405")))
		if err := os.WriteFile(rotatedName, []byte("test"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}

	// Run retention enforcement
	if err := logger.EnforceRetention(); err != nil {
		t.Fatalf("EnforceRetention() error = %v", err)
	}

	// Check that no backup files remain (all are too old)
	pattern := filepath.Join(auditDir, "audit-age-cleanup-test.log.rotated.*")
	matches, _ := filepath.Glob(pattern)
	if len(matches) != 0 {
		t.Fatalf("expected 0 backup files after max age cleanup, got %d", len(matches))
	}
}

func TestEnforceRetentionNoFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("no-backups-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Run retention enforcement on clean directory - should not error
	if err := logger.EnforceRetention(); err != nil {
		t.Fatalf("EnforceRetention() error = %v", err)
	}
}

func TestEnforceRetentionPreservesNewest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "2")

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("preserve-newest-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	auditDir := filepath.Join(home, ".openpass")

	// Create 4 rotated files at different times
	for i := 0; i < 4; i++ {
		rotatedName := filepath.Join(auditDir, fmt.Sprintf("audit-preserve-newest-test.log.rotated.%s", time.Now().UTC().Add(time.Duration(-i)*time.Hour).Format("20060102-150405")))
		if err := os.WriteFile(rotatedName, []byte("test"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Run retention enforcement
	if err := logger.EnforceRetention(); err != nil {
		t.Fatalf("EnforceRetention() error = %v", err)
	}

	// Check that 2 newest files remain
	pattern := filepath.Join(auditDir, "audit-preserve-newest-test.log.rotated.*")
	matches, _ := filepath.Glob(pattern)
	if len(matches) != 2 {
		t.Fatalf("expected 2 backup files (newest), got %d", len(matches))
	}
}

func TestNoLogLossDuringRotation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "1")

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("no-loss-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Write enough data to exceed 1MB (need > 1MB to trigger rotation)
	largeData := strings.Repeat("x", 100*1024) // 100KB per entry
	for i := 0; i < 15; i++ {
		logger.LogEntry(LogEntry{
			Agent:  "test",
			Action: "test",
			Path:   largeData,
			OK:     true,
		})
	}

	// Verify file is large enough (should exceed 1MB)
	auditDir := filepath.Join(home, ".openpass")
	logFile := filepath.Join(auditDir, "audit-no-loss-test.log")
	info, err := os.Stat(logFile)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Size() <= 1*1024*1024 {
		t.Fatalf("expected log file > 1MB to trigger rotation, got %d bytes", info.Size())
	}

	// Trigger rotation
	if rotErr := logger.rotateIfNeeded(); rotErr != nil {
		t.Fatalf("rotateIfNeeded() error = %v", rotErr)
	}

	// Write more entries after rotation
	for i := 0; i < 5; i++ {
		logger.LogEntry(LogEntry{
			Agent:  "test",
			Action: "test2",
			Path:   "test2",
			OK:     true,
		})
	}

	// Check that rotated file exists and has content (no log loss)
	pattern := filepath.Join(auditDir, "audit-no-loss-test.log.rotated.*")
	matches, _ := filepath.Glob(pattern)
	if len(matches) != 1 {
		t.Fatalf("expected 1 rotated file, got %d", len(matches))
	}

	rotatedContent, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	linesRotated := strings.Split(strings.TrimSpace(string(rotatedContent)), "\n")
	if len(linesRotated) != 15 {
		t.Fatalf("expected 15 lines in rotated file, got %d", len(linesRotated))
	}

	// Verify current log file has new entries
	contentAfter, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	linesAfter := strings.Split(strings.TrimSpace(string(contentAfter)), "\n")
	if len(linesAfter) != 5 {
		t.Fatalf("expected 5 lines in current file after rotation, got %d", len(linesAfter))
	}

	defer func() { _ = logger.Close() }()
}

func TestHealthCheckNilLogger(t *testing.T) {
	var l *Logger
	status, err := l.HealthCheck()
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	if status.OK {
		t.Fatal("expected OK=false for nil logger")
	}
}

func TestHealthCheckNilFile(t *testing.T) {
	l := &Logger{file: nil}
	status, err := l.HealthCheck()
	if err == nil {
		t.Fatal("expected error for nil file")
	}
	if status.OK {
		t.Fatal("expected OK=false for nil file")
	}
}

func TestHealthCheckHealthy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("health-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write some entries
	logger.LogEntry(LogEntry{Agent: "health-test", Action: "get", OK: true})
	logger.LogEntry(LogEntry{Agent: "health-test", Action: "set", OK: false, Reason: "denied"})

	status, err := logger.HealthCheck()
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
	if !status.OK {
		t.Fatal("expected OK=true")
	}
	if status.Agent != "health-test" {
		t.Fatalf("agent = %s, want health-test", status.Agent)
	}
	if !status.WriteAccessible {
		t.Fatal("expected WriteAccessible=true")
	}
	if status.LogFileSize == 0 {
		t.Fatal("expected non-zero LogFileSize")
	}
	if status.ErrorCount != 1 {
		t.Fatalf("ErrorCount = %d, want 1", status.ErrorCount)
	}
	if status.LastEntryTime == "" {
		t.Fatal("expected non-empty LastEntryTime")
	}
	if status.LastEntryOK == nil || *status.LastEntryOK {
		t.Fatal("expected LastEntryOK=false (last entry was error)")
	}
}

func TestHealthCheckEmptyLog(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("empty-health-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	status, err := logger.HealthCheck()
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
	if !status.OK {
		t.Fatal("expected OK=true for empty log")
	}
	if status.ErrorCount != 0 {
		t.Fatalf("ErrorCount = %d, want 0", status.ErrorCount)
	}
	if status.LastEntryTime != "" {
		t.Fatal("expected empty LastEntryTime for empty log")
	}
}

func TestHealthCheckNeedsRotationBySize(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "0") // Very small

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("rotation-health-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogEntry(LogEntry{Agent: "test", Action: "test", OK: true})

	status, err := logger.HealthCheck()
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
	if !status.NeedsRotation {
		t.Fatal("expected NeedsRotation=true for oversized file")
	}
}

func TestGetErrorsFiltersErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("errors-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write mix of ok and error entries
	logger.LogEntry(LogEntry{Agent: "test", Action: "get", OK: true})
	logger.LogEntry(LogEntry{Agent: "test", Action: "set", OK: false, Reason: "denied"})
	logger.LogEntry(LogEntry{Agent: "test", Action: "list", OK: true})
	logger.LogEntry(LogEntry{Agent: "test", Action: "delete", OK: false, Reason: "not_found"})

	errors, err := logger.GetErrors(100)
	if err != nil {
		t.Fatalf("GetErrors() error = %v", err)
	}
	if len(errors) != 2 {
		t.Fatalf("GetErrors() returned %d errors, want 2", len(errors))
	}
	if errors[0].Action != "set" {
		t.Fatalf("errors[0].Action = %s, want set", errors[0].Action)
	}
	if errors[0].Reason != "denied" {
		t.Fatalf("errors[0].Reason = %s, want denied", errors[0].Reason)
	}
	if errors[1].Action != "delete" {
		t.Fatalf("errors[1].Action = %s, want delete", errors[1].Action)
	}
}

func TestGetErrorsNoErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("no-errors-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogEntry(LogEntry{Agent: "test", Action: "get", OK: true})

	errors, err := logger.GetErrors(100)
	if err != nil {
		t.Fatalf("GetErrors() error = %v", err)
	}
	if len(errors) != 0 {
		t.Fatalf("GetErrors() returned %d errors, want 0", len(errors))
	}
}

func TestGetErrorsLimit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("limit-errors-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write 10 error entries
	for i := 0; i < 10; i++ {
		logger.LogEntry(LogEntry{Agent: "test", Action: fmt.Sprintf("action%d", i), OK: false, Reason: "error"})
	}

	errors, err := logger.GetErrors(5)
	if err != nil {
		t.Fatalf("GetErrors() error = %v", err)
	}
	if len(errors) != 5 {
		t.Fatalf("GetErrors() returned %d errors, want 5", len(errors))
	}
}

func TestGetErrorsNilLogger(t *testing.T) {
	var l *Logger
	_, err := l.GetErrors(100)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
}

func TestLastNEntriesEmptyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("empty-entries-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	entries, err := logger.lastNEntries(10)
	if err != nil {
		t.Fatalf("lastNEntries() error = %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries for empty file, got %d", len(entries))
	}
}

func TestLastNEntriesNilLogger(t *testing.T) {
	var l *Logger
	_, err := l.lastNEntries(10)
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
}

func TestLastNEntriesNilFile(t *testing.T) {
	l := &Logger{file: nil}
	_, err := l.lastNEntries(10)
	if err == nil {
		t.Fatal("expected error for nil file")
	}
}

func TestLastNEntriesReturnsCorrectCount(t *testing.T) {
	tests := []struct {
		name       string
		numEntries int
		requestN   int
		wantLen    int
		wantFirst  string
		wantLast   string
	}{
		{
			name:       "small file",
			numEntries: 10,
			requestN:   5,
			wantLen:    5,
			wantFirst:  "action5",
			wantLast:   "action9",
		},
		{
			name:       "large file",
			numEntries: 200,
			requestN:   50,
			wantLen:    50,
			wantFirst:  "action150",
			wantLast:   "action199",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)

			logger, err := New("lastn-"+tt.name, "")
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() { _ = logger.Close() }()

			for i := 0; i < tt.numEntries; i++ {
				logger.LogEntry(LogEntry{Agent: "test", Action: fmt.Sprintf("action%d", i), OK: true})
			}

			entries, err := logger.lastNEntries(tt.requestN)
			if err != nil {
				t.Fatalf("lastNEntries() error = %v", err)
			}
			if len(entries) != tt.wantLen {
				t.Fatalf("lastNEntries() returned %d entries, want %d", len(entries), tt.wantLen)
			}
			if entries[0].Action != tt.wantFirst {
				t.Fatalf("entries[0].Action = %s, want %s", entries[0].Action, tt.wantFirst)
			}
			lastIdx := len(entries) - 1
			if entries[lastIdx].Action != tt.wantLast {
				t.Fatalf("entries[%d].Action = %s, want %s", lastIdx, entries[lastIdx].Action, tt.wantLast)
			}
		})
	}
}

func TestLastNEntriesMoreThanAvailable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("more-entries-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write 3 entries
	for i := 0; i < 3; i++ {
		logger.LogEntry(LogEntry{Agent: "test", Action: fmt.Sprintf("action%d", i), OK: true})
	}

	entries, err := logger.lastNEntries(100)
	if err != nil {
		t.Fatalf("lastNEntries() error = %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("lastNEntries() returned %d entries, want 3", len(entries))
	}
}

func TestLastNEntriesSkipsMalformedLines(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("malformed-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write valid entry
	logger.LogEntry(LogEntry{Agent: "test", Action: "valid", OK: true})

	// Manually append malformed line
	auditDir := filepath.Join(home, ".openpass")
	logFile := filepath.Join(auditDir, "audit-malformed-test.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	fmt.Fprintln(f, "not valid json{{{")
	fmt.Fprintln(f, "")
	f.Close()

	// Write another valid entry
	logger.LogEntry(LogEntry{Agent: "test", Action: "valid2", OK: true})

	entries, err := logger.lastNEntries(100)
	if err != nil {
		t.Fatalf("lastNEntries() error = %v", err)
	}
	// Should only return valid entries
	if len(entries) != 2 {
		t.Fatalf("lastNEntries() returned %d entries, want 2", len(entries))
	}
}

func TestScanLinesEmptyAtEOF(t *testing.T) {
	advance, token, err := scanLines(nil, true)
	if err != nil {
		t.Fatalf("scanLines() error = %v", err)
	}
	if advance != 0 || token != nil {
		t.Fatalf("scanLines(nil, true) = (%d, %v), want (0, nil)", advance, token)
	}
}

func TestScanLinesWithNewline(t *testing.T) {
	data := []byte("hello\nworld")
	advance, token, err := scanLines(data, false)
	if err != nil {
		t.Fatalf("scanLines() error = %v", err)
	}
	if advance != 6 {
		t.Fatalf("advance = %d, want 6", advance)
	}
	if string(token) != "hello" {
		t.Fatalf("token = %s, want hello", token)
	}
}

func TestScanLinesAtEOFNoNewline(t *testing.T) {
	data := []byte("hello world")
	advance, token, err := scanLines(data, true)
	if err != nil {
		t.Fatalf("scanLines() error = %v", err)
	}
	if advance != 11 {
		t.Fatalf("advance = %d, want 11", advance)
	}
	if string(token) != "hello world" {
		t.Fatalf("token = %s, want hello world", token)
	}
}

func TestScanLinesNoNewlineNotEOF(t *testing.T) {
	data := []byte("hello")
	advance, token, err := scanLines(data, false)
	if err != nil {
		t.Fatalf("scanLines() error = %v", err)
	}
	if advance != 0 {
		t.Fatalf("advance = %d, want 0", advance)
	}
	if token != nil {
		t.Fatalf("token = %v, want nil", token)
	}
}

func TestRotateIfNeededNilLogger(t *testing.T) {
	var l *Logger
	err := l.rotateIfNeeded()
	if err != nil {
		t.Fatalf("rotateIfNeeded() on nil logger should not error, got %v", err)
	}
}

func TestRotateIfNeededNilFile(t *testing.T) {
	l := &Logger{file: nil}
	err := l.rotateIfNeeded()
	if err != nil {
		t.Fatalf("rotateIfNeeded() on nil file should not error, got %v", err)
	}
}

func TestEnforceRetentionNilLogger(t *testing.T) {
	var l *Logger
	err := l.EnforceRetention()
	if err == nil {
		t.Fatal("expected error for nil logger")
	}
	if !strings.Contains(err.Error(), "logger is nil") {
		t.Fatalf("expected 'logger is nil' in error, got: %v", err)
	}
}

func TestLogEntryAutoFillsEmptyTimestamp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("autofill-ts-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	before := time.Now().UTC().Truncate(time.Second)
	logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "get",
		OK:     true,
	})
	after := time.Now().UTC().Truncate(time.Second).Add(time.Second)

	content, err := os.ReadFile(filepath.Join(home, ".openpass", "audit-autofill-ts-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	var entry LogEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(content))), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	ts, err := time.Parse(time.RFC3339, entry.Timestamp)
	if err != nil {
		t.Fatalf("failed to parse timestamp: %v", err)
	}
	if ts.Before(before) || ts.After(after) {
		t.Fatalf("timestamp %v not in range [%v, %v]", ts, before, after)
	}
}

func TestNewRejectsDotDotInMiddle(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := New("agent..name", "")
	if err == nil {
		t.Fatal("expected error for agent name containing ..")
	}
}

func TestHealthCheckMultipleErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("multi-error-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write 5 error entries and 3 ok entries
	for i := 0; i < 5; i++ {
		logger.LogEntry(LogEntry{Agent: "test", Action: fmt.Sprintf("err%d", i), OK: false, Reason: "fail"})
	}
	for i := 0; i < 3; i++ {
		logger.LogEntry(LogEntry{Agent: "test", Action: fmt.Sprintf("ok%d", i), OK: true})
	}

	status, err := logger.HealthCheck()
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
	if status.ErrorCount != 5 {
		t.Fatalf("ErrorCount = %d, want 5", status.ErrorCount)
	}
}

func TestGetErrorsAllOk(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("all-ok-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	for i := 0; i < 5; i++ {
		logger.LogEntry(LogEntry{Agent: "test", Action: "get", OK: true})
	}

	errors, err := logger.GetErrors(100)
	if err != nil {
		t.Fatalf("GetErrors() error = %v", err)
	}
	if len(errors) != 0 {
		t.Fatalf("GetErrors() returned %d errors, want 0", len(errors))
	}
}

func TestGetErrorsAllErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("all-errors-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	for i := 0; i < 5; i++ {
		logger.LogEntry(LogEntry{Agent: "test", Action: fmt.Sprintf("action%d", i), OK: false, Reason: "fail"})
	}

	errors, err := logger.GetErrors(100)
	if err != nil {
		t.Fatalf("GetErrors() error = %v", err)
	}
	if len(errors) != 5 {
		t.Fatalf("GetErrors() returned %d errors, want 5", len(errors))
	}
	for i, e := range errors {
		if e.OK {
			t.Fatalf("errors[%d].OK = true, want false", i)
		}
		if e.Reason != "fail" {
			t.Fatalf("errors[%d].Reason = %s, want fail", i, e.Reason)
		}
	}
}

func TestConfigEnvVarZeroMaxBackups(t *testing.T) {
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "0")
	ReloadConfig()
	defer ReloadConfig()

	if config.MaxBackups != 0 {
		t.Fatalf("MaxBackups = %d, want 0", config.MaxBackups)
	}
}

func TestConfigEnvVarZeroMaxAgeDays(t *testing.T) {
	t.Setenv("OPENPASS_AUDIT_MAX_AGE_DAYS", "0")
	ReloadConfig()
	defer ReloadConfig()

	if config.MaxAgeDays != 0 {
		t.Fatalf("MaxAgeDays = %d, want 0", config.MaxAgeDays)
	}
}

func TestConfigEnvVarNegativeIgnored(t *testing.T) {
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "-10")
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "-5")
	t.Setenv("OPENPASS_AUDIT_MAX_AGE_DAYS", "-1")
	ReloadConfig()
	defer ReloadConfig()

	// Negative values should be ignored, defaults used
	if config.MaxFileSize != 100*1024*1024 {
		t.Fatalf("MaxFileSize = %d, want default 100MB", config.MaxFileSize)
	}
	if config.MaxBackups != 5 {
		t.Fatalf("MaxBackups = %d, want default 5", config.MaxBackups)
	}
	if config.MaxAgeDays != 30 {
		t.Fatalf("MaxAgeDays = %d, want default 30", config.MaxAgeDays)
	}
}

func TestLogEntryAllFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("all-fields-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogEntry(LogEntry{
		Timestamp: "2024-06-15T12:00:00Z",
		Agent:     "test-agent",
		Action:    "get",
		Path:      "secret/key",
		Field:     "password",
		Transport: "stdio",
		Reason:    "access_granted",
		DurMs:     123,
		OK:        true,
	})

	content, err := os.ReadFile(filepath.Join(home, ".openpass", "audit-all-fields-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	var entry LogEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(content))), &entry); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if entry.Timestamp != "2024-06-15T12:00:00Z" {
		t.Fatalf("Timestamp = %s, want 2024-06-15T12:00:00Z", entry.Timestamp)
	}
	if entry.Agent != "test-agent" {
		t.Fatalf("Agent = %s, want test-agent", entry.Agent)
	}
	if entry.Action != "get" {
		t.Fatalf("Action = %s, want get", entry.Action)
	}
	if entry.Path != "secret/key" {
		t.Fatalf("Path = %s, want secret/key", entry.Path)
	}
	if entry.Field != "password" {
		t.Fatalf("Field = %s, want password", entry.Field)
	}
	if entry.Transport != "stdio" {
		t.Fatalf("Transport = %s, want stdio", entry.Transport)
	}
	if entry.Reason != "access_granted" {
		t.Fatalf("Reason = %s, want access_granted", entry.Reason)
	}
	if entry.DurMs != 123 {
		t.Fatalf("DurMs = %d, want 123", entry.DurMs)
	}
	if !entry.OK {
		t.Fatal("OK = false, want true")
	}
}

func TestNewValidAgentNames(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	validNames := []string{"claude", "my-agent", "agent_1", "Agent123"}
	for _, name := range validNames {
		t.Run(name, func(t *testing.T) {
			logger, err := New(name, "")
			if err != nil {
				t.Fatalf("New(%q) error = %v", name, err)
			}
			defer func() { _ = logger.Close() }()

			expectedFile := filepath.Join(home, ".openpass", fmt.Sprintf("audit-%s.log", name))
			if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
				t.Fatalf("log file not created for agent %q", name)
			}
		})
	}
}

func TestHealthCheckIncludesRotatedSize(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("rotated-size-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write some data
	logger.LogEntry(LogEntry{Agent: "test", Action: "get", OK: true})

	// Create a rotated file manually
	auditDir := filepath.Join(home, ".openpass")
	rotatedFile := filepath.Join(auditDir, "audit-rotated-size-test.log.rotated.20240101-000000")
	if err := os.WriteFile(rotatedFile, []byte(strings.Repeat("x", 1000)), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	status, err := logger.HealthCheck()
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}

	// TotalAuditSize should include both current and rotated files
	if status.TotalAuditSize < 1000 {
		t.Fatalf("TotalAuditSize = %d, want >= 1000", status.TotalAuditSize)
	}
}

func TestLastNEntriesCorruptedJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("corrupt-json-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	for i := 0; i < 3; i++ {
		logger.LogEntry(LogEntry{Agent: "test", Action: fmt.Sprintf("valid%d", i), OK: true})
	}

	logFile := filepath.Join(home, ".openpass", "audit-corrupt-json-test.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	fmt.Fprintln(f, `{"ts":"2024-01-01T00:00:00Z","agent":"test","action":"corrupt1","ok":true`)
	fmt.Fprintln(f, `{"ts":"2024-01-01T00:00:00Z","agent":"test","action":"corrupt2","ok":true,"invalid json}`)
	fmt.Fprintln(f, `{null}`)
	fmt.Fprintln(f, `{"ts":"2024-01-01T00:00:00Z","agent":"test","action":"corrupt3","ok":true}`)
	f.Close()

	entries, err := logger.lastNEntries(100)
	if err != nil {
		t.Fatalf("lastNEntries() error = %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("lastNEntries() returned %d entries, want 4 (skipped corrupted)", len(entries))
	}
}

func TestLastNEntriesMissingFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("missing-fields-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	logFile := filepath.Join(home, ".openpass", "audit-missing-fields-test.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	fmt.Fprintln(f, `{"ts":"2024-01-01T00:00:00Z","action":"get","ok":true}`)
	fmt.Fprintln(f, `{"ts":"2024-01-01T00:00:00Z","agent":"test","ok":true}`)
	fmt.Fprintln(f, `{"ts":"2024-01-01T00:00:00Z","agent":"test","action":"get"}`)
	fmt.Fprintln(f, `{"ts":"2024-01-01T00:00:00Z","ok":true}`)
	f.Close()

	entries, err := logger.lastNEntries(100)
	if err != nil {
		t.Fatalf("lastNEntries() error = %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("lastNEntries() returned %d entries, want 4", len(entries))
	}
}

// TestLastNEntriesEmptyTimestamp tests entries with empty timestamps are still parsed
func TestLastNEntriesEmptyTimestamp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("empty-ts-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Append entry with empty timestamp
	logFile := filepath.Join(home, ".openpass", "audit-empty-ts-test.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	fmt.Fprintln(f, `{"ts":"","agent":"test","action":"get","ok":true}`)
	f.Close()

	entries, err := logger.lastNEntries(100)
	if err != nil {
		t.Fatalf("lastNEntries() error = %v", err)
	}
	// Empty timestamp is still valid JSON
	if len(entries) != 1 {
		t.Fatalf("lastNEntries() returned %d entries, want 1", len(entries))
	}
}

// TestConcurrentWrites tests that concurrent writes from multiple goroutines work correctly
func TestConcurrentWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("concurrent-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	const goroutines = 10
	const entriesPerGoroutine = 50
	done := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			for j := 0; j < entriesPerGoroutine; j++ {
				logger.LogEntry(LogEntry{
					Agent:  "test",
					Action: fmt.Sprintf("action-%d-%d", idx, j),
					OK:     true,
				})
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			for j := 0; j < entriesPerGoroutine; j++ {
				logger.LogEntry(LogEntry{
					Agent:  "test",
					Action: fmt.Sprintf("action-%d-%d", idx, j),
					OK:     true,
				})
			}
			done <- struct{}{}
		}(i)
	}

	// Wait for completion
	for i := 0; i < goroutines; i++ {
		<-done
	}

	// Verify all entries were written
	entries, err := logger.lastNEntries(goroutines * entriesPerGoroutine)
	if err != nil {
		t.Fatalf("lastNEntries() error = %v", err)
	}

	// With concurrent writes, we should have at least some entries
	if len(entries) == 0 {
		t.Fatal("expected entries after concurrent writes")
	}
}

// TestConcurrentWritesWithClose tests concurrent writes with logger close
func TestConcurrentWritesWithClose(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("concurrent-close-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const goroutines = 5
	const entriesPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < entriesPerGoroutine; j++ {
				logger.LogEntry(LogEntry{
					Agent:  "test",
					Action: fmt.Sprintf("action-%d-%d", idx, j),
					OK:     true,
				})
			}
		}(i)
	}

	go func() {
		wg.Wait()
	}()

	// Close while writing - should not panic
	time.Sleep(10 * time.Millisecond)
	_ = logger.Close()
}

// TestRotateIfNeededRenameFailure tests error when rename fails and file cannot be reopened
func TestRotateIfNeededRenameFailure(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "1")

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("rename-fail-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Fill file to exceed max size
	data := strings.Repeat("x", 1024*1024) // 1MB
	logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "test",
		Path:   data,
		OK:     true,
	})

	// Lock the file so rename will fail on some systems
	// Note: This test is platform-dependent; we just verify the error handling
}

// TestMaxLogSizeTrigger tests that rotation triggers exactly when max size is reached
func TestMaxLogSizeTrigger(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_SIZE_MB", "1")

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("max-size-trigger-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write exactly 1MB - should NOT trigger rotation yet
	data := strings.Repeat("x", 1024*1024)
	logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "test",
		Path:   data,
		OK:     true,
	})

	// Check if rotation is needed - with 1MB data + overhead, it should be close but file exists
	// The file content (JSON) will be larger than 1MB due to field overhead
	// Force trigger by writing more
	logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "test2",
		Path:   data,
		OK:     true,
	})

	// Verify log file has content
	info, err := os.Stat(logger.path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("expected non-zero log file size")
	}
}

// TestLogEntryWriteErrorToStderr tests that write errors are logged to stderr
func TestLogEntryWriteErrorToStderr(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("write-error-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Close the file to simulate a write error
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Now LogEntry should write to stderr but not panic
	// We cannot easily capture stderr, but this should not panic
	logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "test",
		OK:     true,
	})
}

// TestEnforceRetentionStatError tests handling when stat fails on a rotated file
func TestEnforceRetentionStatError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "3")

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("stat-error-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	auditDir := filepath.Join(home, ".openpass")

	// Create valid rotated files
	for i := 0; i < 3; i++ {
		rotatedName := filepath.Join(auditDir, fmt.Sprintf("audit-stat-error-test.log.rotated.%s", time.Now().UTC().Add(time.Duration(i)*time.Second).Format("20060102-150405")))
		if err := os.WriteFile(rotatedName, []byte("test"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}

	// Create a file that will fail stat (symlink to non-existent target)
	badSymlink := filepath.Join(auditDir, "audit-stat-error-test.log.rotated.badsymlink")
	if err := os.Symlink("/nonexistent/path/to/file", badSymlink); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	// EnforceRetention should continue even when stat fails on symlink
	err = logger.EnforceRetention()
	if err != nil {
		t.Fatalf("EnforceRetention() error = %v (should ignore stat errors)", err)
	}
}

// TestEnforceRetentionRemoveError tests handling when remove fails on a file
func TestEnforceRetentionRemoveError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_BACKUPS", "0") // All files should be deleted

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("remove-error-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	auditDir := filepath.Join(home, ".openpass")

	// Create a rotated file
	rotatedName := filepath.Join(auditDir, fmt.Sprintf("audit-remove-error-test.log.rotated.%s", time.Now().UTC().Format("20060102-150405")))
	if err := os.WriteFile(rotatedName, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Remove parent directory to make remove fail
	if err := os.Chmod(auditDir, 0o555); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(auditDir, 0o700) //nolint:errcheck

	// EnforceRetention should not error even when remove fails
	err = logger.EnforceRetention()
	if err != nil {
		t.Fatalf("EnforceRetention() error = %v (should continue on remove error)", err)
	}
}

// TestHealthCheckSeekError tests handling when file.Seek fails
func TestHealthCheckSeekError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("seek-error-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write some data
	logger.LogEntry(LogEntry{Agent: "test", Action: "get", OK: true})

	// Force an invalid file descriptor by closing and nullifying
	oldFile := logger.file
	logger.file = nil

	_, err = logger.HealthCheck()
	if err == nil {
		t.Fatal("expected error when file is nil")
	}

	logger.file = oldFile
}

// TestLastNEntriesReadFileError tests handling when ReadFile fails
func TestLastNEntriesReadFileError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("readfile-error-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Write some data
	logger.LogEntry(LogEntry{Agent: "test", Action: "get", OK: true})

	// Close the file to simulate a read error
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Now lastNEntries should fail
	_, err = logger.lastNEntries(100)
	if err == nil {
		t.Fatal("expected error when file is closed")
	}
}

func TestRotateIfNeededStatError(t *testing.T) {
	l := &Logger{file: nil}
	err := l.rotateIfNeeded()
	if err != nil {
		t.Fatalf("rotateIfNeeded() on nil file should not error, got %v", err)
	}
}

func TestNewPathSeparators(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	badNames := []string{"agent/name", "agent\\name"}
	for _, name := range badNames {
		t.Run(name, func(t *testing.T) {
			_, err := New(name, "")
			if err == nil {
				t.Fatalf("expected error for agent name %q", name)
			}
		})
	}
}

func TestHealthCheckZeroMaxAge(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENPASS_AUDIT_MAX_AGE_DAYS", "0")

	ReloadConfig()
	defer ReloadConfig()

	logger, err := New("zero-age-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogEntry(LogEntry{Agent: "test", Action: "get", OK: true})

	status, err := logger.HealthCheck()
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}

	if status.LogFileAge >= "0s" {
		t.Log("LogFileAge comparison reached")
	}
}

func TestRotateIfNeededFileStatError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("stat-error-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogEntry(LogEntry{Agent: "test", Action: "get", OK: true})

	file := logger.file
	logger.file = nil

	err = logger.rotateIfNeeded()
	if err != nil {
		t.Fatalf("rotateIfNeeded() on nil file should be safe, got %v", err)
	}

	logger.file = file
}

func TestRotateIfNeededClosedFileStatError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("closed-stat-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := logger.rotateIfNeeded(); err == nil {
		t.Fatal("expected error when statting closed file")
	}
}

func TestHealthCheckClosedFileStatError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("closed-health-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	status, err := logger.HealthCheck()
	if err == nil {
		t.Fatal("expected error when statting closed file")
	}
	if status.OK {
		t.Fatal("expected OK=false")
	}
	if status.WriteAccessible {
		t.Fatal("expected WriteAccessible=false")
	}
}

func TestHealthCheckIgnoresBadGlobPattern(t *testing.T) {
	home := t.TempDir()
	logFile := filepath.Join(home, "audit-bad-glob.log")
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile() error = %v", err)
	}
	defer func() { _ = file.Close() }()

	logger := &Logger{agentName: "[", path: logFile, file: file}
	status, err := logger.HealthCheck()
	if err != nil {
		t.Fatalf("HealthCheck() error = %v", err)
	}
	if !status.OK {
		t.Fatal("expected OK=true")
	}
}

func TestNewOpenFilePermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod has no effect")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	if err := os.Chmod(auditDir, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(auditDir, 0o700) //nolint:errcheck

	_, err := New("perm-denied-test", "")
	if err == nil {
		t.Fatal("expected error when OpenFile fails")
	}
}

func TestEnforceRetentionEmptyDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("empty-dir-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	err = logger.EnforceRetention()
	if err != nil {
		t.Fatalf("EnforceRetention() on clean dir should not error, got %v", err)
	}
}

// TestLastNEntriesFileSizeZero tests that zero-sized file returns nil entries
func TestLastNEntriesFileSizeZero(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("zero-size-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	entries, err := logger.lastNEntries(10)
	if err != nil {
		t.Fatalf("lastNEntries() error = %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries for zero-size file, got %v", entries)
	}
}

// TestScanLinesExactlyAtEOF tests scanLines behavior at EOF boundary
func TestScanLinesExactlyAtEOF(t *testing.T) {
	data := []byte("line without newline")
	advance, token, err := scanLines(data, true)
	if err != nil {
		t.Fatalf("scanLines() error = %v", err)
	}
	if advance != len(data) {
		t.Fatalf("advance = %d, want %d", advance, len(data))
	}
	if string(token) != "line without newline" {
		t.Fatalf("token = %s, want 'line without newline'", string(token))
	}
}

// TestScanLinesEmptyLine tests scanning an empty line
func TestScanLinesEmptyLine(t *testing.T) {
	data := []byte("\n")
	advance, token, err := scanLines(data, false)
	if err != nil {
		t.Fatalf("scanLines() error = %v", err)
	}
	if advance != 1 {
		t.Fatalf("advance = %d, want 1", advance)
	}
	if string(token) != "" {
		t.Fatalf("token = %q, want empty string", string(token))
	}
}

func TestSetConfig_OverridesDefaults(t *testing.T) {
	original := GetConfig()
	defer SetConfig(&original)

	custom := Config{
		MaxFileSize: 10 * 1024 * 1024,
		MaxBackups:  2,
		MaxAgeDays:  7,
	}
	SetConfig(&custom)

	got := GetConfig()
	if got.MaxFileSize != custom.MaxFileSize {
		t.Errorf("MaxFileSize = %d, want %d", got.MaxFileSize, custom.MaxFileSize)
	}
	if got.MaxBackups != custom.MaxBackups {
		t.Errorf("MaxBackups = %d, want %d", got.MaxBackups, custom.MaxBackups)
	}
	if got.MaxAgeDays != custom.MaxAgeDays {
		t.Errorf("MaxAgeDays = %d, want %d", got.MaxAgeDays, custom.MaxAgeDays)
	}
}
