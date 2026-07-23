package health_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/health"
)

func writeAuditLogEntries(t *testing.T, dir, agentName string, n int) string {
	t.Helper()
	logger, err := audit.New(agentName, dir, nil)
	if err != nil {
		t.Fatalf("audit.New() error = %v", err)
	}
	for i := 0; i < n; i++ {
		if err := logger.LogEntry(audit.LogEntry{Agent: "test-agent", Action: fmt.Sprintf("get-%d", i), Path: "test/path", OK: true}); err != nil {
			t.Fatalf("LogEntry() error = %v", err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return filepath.Join(dir, fmt.Sprintf("audit-%s.log", agentName))
}

// TestRunChecks_AuditLog_VerifiedUnderArchivedKeyAfterRotation is the #685
// regression: a log written entirely under a key that has since been
// rotated must be reported as verified (under the older generation), not
// as an integrity failure, once the archived key is available.
func TestRunChecks_AuditLog_VerifiedUnderArchivedKeyAfterRotation(t *testing.T) {
	dir := t.TempDir()
	writeAuditLogEntries(t, dir, "rotation-doctor-test", 3)

	ks := audit.NewKeystore(dir, nil)
	if _, err := ks.RotateKey(); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	results := health.RunChecks(dir, health.Options{Only: []string{"audit.log"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected audit.log result")
	}
	r := results[0]
	if r.Status != health.StatusOK {
		t.Fatalf("expected OK after rotation with a matching archive, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "verified under an older key generation") {
		t.Errorf("message = %q, want it to mention verification under an older key generation", r.Message)
	}
}

// TestRunChecks_AuditLog_LostArchiveReportsUnverifiableNotTampered covers
// #685's core distinction: when the archive for a rotated-out key is gone
// (e.g. deleted, or a keychain reset that never produced one), the doctor
// must report the affected log as unverifiable, never as "integrity check
// failed" alongside genuine tamper cases.
func TestRunChecks_AuditLog_LostArchiveReportsUnverifiableNotTampered(t *testing.T) {
	dir := t.TempDir()
	writeAuditLogEntries(t, dir, "lost-archive-doctor-test", 3)

	ks := audit.NewKeystore(dir, nil)
	if _, err := ks.RotateKey(); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	archivePath := audit.RotateKeyArchivePath(dir)
	if err := os.Remove(archivePath); err != nil {
		t.Fatalf("remove archive: %v", err)
	}

	results := health.RunChecks(dir, health.Options{Only: []string{"audit.log"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected audit.log result")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Fatalf("expected warn for an unverifiable log, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "cannot verify") {
		t.Errorf("message = %q, want it to say the log cannot be verified", r.Message)
	}
	if strings.Contains(r.Message, "integrity check failed") {
		t.Errorf("message = %q, a missing key must not be reported the same as tampering", r.Message)
	}
}

// TestRunChecks_AuditLog_GenuineTamperStillFlagged ensures the #685 fix does
// not soften real tamper detection: a log with an actually altered entry
// must still be reported as an integrity failure.
func TestRunChecks_AuditLog_GenuineTamperStillFlagged(t *testing.T) {
	dir := t.TempDir()
	logPath := writeAuditLogEntries(t, dir, "genuine-tamper-doctor-test", 3)

	content, err := os.ReadFile(logPath)
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
	if err := os.WriteFile(logPath, []byte(strings.Join(tamperedLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	results := health.RunChecks(dir, health.Options{Only: []string{"audit.log"}, NoNetwork: true})
	if len(results) == 0 {
		t.Fatal("expected audit.log result")
	}
	r := results[0]
	if r.Status != health.StatusWarn {
		t.Fatalf("expected warn for a genuinely tampered log, got %s: %s", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "integrity check failed") {
		t.Errorf("message = %q, want it to report an integrity check failure", r.Message)
	}
}
