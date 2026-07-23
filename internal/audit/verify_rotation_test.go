package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestVerifyLogAgainstKeys_VerifiesUnderArchivedKeyAfterRotation is the core
// #685 regression: a log written entirely under a key that has since been
// rotated out must verify successfully against the archived key, not be
// reported as tampered just because the current key doesn't match.
func TestVerifyLogAgainstKeys_VerifiesUnderArchivedKeyAfterRotation(t *testing.T) {
	dir := t.TempDir()

	logger, err := New("rotation-test", dir, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := logger.LogEntry(LogEntry{Agent: "test-agent", Action: fmt.Sprintf("get-%d", i), Path: "test/path", OK: true}); err != nil {
			t.Fatalf("LogEntry() error = %v", err)
		}
	}
	logPath := logger.path
	_ = logger.Close()

	ks := NewKeystore(dir, nil)
	newKey, err := ks.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	// Sanity check: the whole-file-fails-from-the-start signature the fix
	// keys off actually reproduces here.
	directResult, err := VerifyLog(logPath, newKey)
	if err != nil {
		t.Fatalf("VerifyLog(newKey) error = %v", err)
	}
	if directResult.Valid || directResult.Verified != 0 {
		t.Fatalf("expected the current (post-rotation) key to fail from the start, got Valid=%v Verified=%d", directResult.Valid, directResult.Verified)
	}

	archivedKeys, err := ks.LoadArchivedKeys()
	if err != nil {
		t.Fatalf("LoadArchivedKeys() error = %v", err)
	}
	if len(archivedKeys) != 1 {
		t.Fatalf("archivedKeys = %d, want 1", len(archivedKeys))
	}

	result, err := VerifyLogAgainstKeys(logPath, newKey, archivedKeys)
	if err != nil {
		t.Fatalf("VerifyLogAgainstKeys() error = %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected the archived key to verify the log, got Valid=false (tampered=%d)", result.Tampered)
	}
	if result.Unverifiable {
		t.Fatal("expected Unverifiable=false when an archived key verifies the log")
	}
	if result.VerifiedKeyGeneration == "" {
		t.Error("expected VerifiedKeyGeneration to be set to the archived key's label")
	}
	if result.Tampered != 0 {
		t.Fatalf("Tampered = %d, want 0", result.Tampered)
	}
}

// TestVerifyLogAgainstKeys_MissingArchivedKey_ReportsUnverifiableNotTampered
// covers #685's core distinction: when no key (current or archived)
// verifies a log from the start, that must be reported as unverifiable —
// e.g. after a keychain reset with no matching archive — never as tampered.
func TestVerifyLogAgainstKeys_MissingArchivedKey_ReportsUnverifiableNotTampered(t *testing.T) {
	dir := t.TempDir()

	logger, err := New("lost-key-test", dir, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := logger.LogEntry(LogEntry{Agent: "test-agent", Action: fmt.Sprintf("get-%d", i), Path: "test/path", OK: true}); err != nil {
			t.Fatalf("LogEntry() error = %v", err)
		}
	}
	logPath := logger.path
	_ = logger.Close()

	// A key unrelated to the one that actually signed the log, with no
	// archived candidates available at all (simulates a keychain reset that
	// lost the key with no rotation archive to fall back to).
	unrelatedKey := make([]byte, hmacKeySize)
	for i := range unrelatedKey {
		unrelatedKey[i] = byte(i + 1)
	}

	result, err := VerifyLogAgainstKeys(logPath, unrelatedKey, nil)
	if err != nil {
		t.Fatalf("VerifyLogAgainstKeys() error = %v", err)
	}
	if result.Valid {
		t.Fatal("expected Valid=false when no key verifies the log")
	}
	if !result.Unverifiable {
		t.Fatal("expected Unverifiable=true for a missing/lost key generation")
	}
	if result.Tampered != 0 {
		t.Fatalf("Tampered = %d, want 0 — a missing key must not be reported as tampering", result.Tampered)
	}
}

// TestVerifyLogAgainstKeys_GenuineTamperStaysTampered ensures the archived-
// key fallback never launders a real tamper into a false "verified under an
// older generation" or "unverifiable" result: when the primary key verifies
// a prefix of the log before failing, that proves the primary key is
// correct, so the result must stay Tampered even when archived keys exist.
func TestVerifyLogAgainstKeys_GenuineTamperStaysTampered(t *testing.T) {
	dir := t.TempDir()

	logger, err := New("genuine-tamper-test", dir, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := logger.LogEntry(LogEntry{Agent: "test-agent", Action: fmt.Sprintf("get-%d", i), Path: "test/path", OK: true}); err != nil {
			t.Fatalf("LogEntry() error = %v", err)
		}
	}
	logPath := logger.path
	_ = logger.Close()

	ks := NewKeystore(dir, nil)
	key, err := ks.LoadHMACKey()
	if err != nil {
		t.Fatalf("LoadHMACKey() error = %v", err)
	}

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

	// A decoy archived key that must NOT be consulted, since the current
	// key already proves itself correct on the verified prefix.
	decoyKey := make([]byte, hmacKeySize)
	for i := range decoyKey {
		decoyKey[i] = byte(i + 7)
	}

	result, err := VerifyLogAgainstKeys(logPath, key, []ArchivedKey{{Label: "decoy", Key: decoyKey}})
	if err != nil {
		t.Fatalf("VerifyLogAgainstKeys() error = %v", err)
	}
	if result.Valid {
		t.Fatal("expected Valid=false for a genuinely tampered entry")
	}
	if result.Unverifiable {
		t.Fatal("expected Unverifiable=false for a genuine tamper — the primary key verified a prefix")
	}
	if result.VerifiedKeyGeneration != "" {
		t.Errorf("VerifiedKeyGeneration = %q, want empty for a genuine tamper", result.VerifiedKeyGeneration)
	}
	if result.Tampered < 1 {
		t.Fatalf("Tampered = %d, want >= 1", result.Tampered)
	}
	if result.FirstBadIdx != 1 {
		t.Fatalf("FirstBadIdx = %d, want 1", result.FirstBadIdx)
	}
}
