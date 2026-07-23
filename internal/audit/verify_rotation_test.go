package audit

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

// TestVerifyLogAgainstKeysStraddlesRotation covers the general case that the
// original whole-file trial fallback (issue #685) could not handle: a
// single physical log file with some entries signed under an old HMAC key
// and later entries signed under a new one, because key rotation and log
// file rotation are independent (rotating the key does not start a new log
// file). Per-entry kid lookup must verify both halves correctly.
func TestVerifyLogAgainstKeysStraddlesRotation(t *testing.T) {
	// Guard against global audit config left polluted by an earlier test
	// (rotateIfNeeded uses the package-level config; this test must not
	// trigger a log-file rotation of its own).
	ReloadConfig()
	defer ReloadConfig()

	home := t.TempDir()
	t.Setenv("HOME", home)

	logger1, err := New("straddle-test", "", nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for i := 0; i < 3; i++ {
		_ = logger1.LogEntry(LogEntry{
			Agent:  "test-agent",
			Action: fmt.Sprintf("pre-rotation-%d", i),
			Path:   "test/path",
			OK:     true,
		})
	}
	_ = logger1.Close()

	auditDir := filepath.Join(home, configpkg.DefaultVaultSubdir)
	ks := NewKeystore(auditDir, nil)
	oldKey, err := ks.LoadHMACKey()
	if err != nil {
		t.Fatalf("LoadHMACKey() error = %v", err)
	}

	newKey, archivePath, err := ks.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if archivePath == "" {
		t.Fatal("expected non-empty archive path")
	}

	// A logger constructed after rotation (e.g. a fresh process) picks up
	// the new key but keeps appending to the same physical log file.
	logger2, err := New("straddle-test", "", nil)
	if err != nil {
		t.Fatalf("New() error on reopen = %v", err)
	}
	defer func() { _ = logger2.Close() }()
	if hex.EncodeToString(logger2.hmacKey) != hex.EncodeToString(newKey) {
		t.Fatal("logger constructed after rotation should use the rotated key")
	}
	for i := 0; i < 3; i++ {
		_ = logger2.LogEntry(LogEntry{
			Agent:  "test-agent",
			Action: fmt.Sprintf("post-rotation-%d", i),
			Path:   "test/path",
			OK:     true,
		})
	}

	logFile := filepath.Join(auditDir, "audit-straddle-test.log")

	keys, currentKid, err := LoadVerificationKeys(ks)
	if err != nil {
		t.Fatalf("LoadVerificationKeys() error = %v", err)
	}
	if _, ok := keys[KeyFingerprint(oldKey)]; !ok {
		t.Fatal("expected archived (pre-rotation) key present in verification key set")
	}
	if currentKid != KeyFingerprint(newKey) {
		t.Fatalf("currentKid = %s, want %s", currentKid, KeyFingerprint(newKey))
	}

	result, err := VerifyLogAgainstKeys(logFile, keys, currentKid)
	if err != nil {
		t.Fatalf("VerifyLogAgainstKeys() error = %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid straddling log, got Valid=false (verified=%d tampered=%d unverifiable=%d legacy=%d)",
			result.Verified, result.Tampered, result.Unverifiable, result.Legacy)
	}
	if result.Total != 6 {
		t.Fatalf("Total = %d, want 6", result.Total)
	}
	if result.Verified != 6 {
		t.Fatalf("Verified = %d, want 6", result.Verified)
	}
	if result.Tampered != 0 {
		t.Fatalf("Tampered = %d, want 0", result.Tampered)
	}
	if result.Unverifiable != 0 {
		t.Fatalf("Unverifiable = %d, want 0", result.Unverifiable)
	}
}

// TestVerifyLogAgainstKeysStraddlesRotationMissingArchiveIsUnverifiable
// mirrors the real #685 report: a log file straddling rotation, but the old
// key was never recovered. The pre-rotation entries must be reported
// unverifiable, not tampered, while the post-rotation entries (signed under
// the key we do have, via kid) verify normally.
func TestVerifyLogAgainstKeysStraddlesRotationMissingArchiveIsUnverifiable(t *testing.T) {
	// See TestVerifyLogAgainstKeysStraddlesRotation for why this guard is needed.
	ReloadConfig()
	defer ReloadConfig()

	home := t.TempDir()
	t.Setenv("HOME", home)

	logger1, err := New("straddle-lost-key-test", "", nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for i := 0; i < 2; i++ {
		_ = logger1.LogEntry(LogEntry{Agent: "test-agent", Action: fmt.Sprintf("pre-%d", i), Path: "p", OK: true})
	}
	_ = logger1.Close()

	auditDir := filepath.Join(home, configpkg.DefaultVaultSubdir)
	ks := NewKeystore(auditDir, nil)

	newKey, _, err := ks.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	logger2, err := New("straddle-lost-key-test", "", nil)
	if err != nil {
		t.Fatalf("New() error on reopen = %v", err)
	}
	defer func() { _ = logger2.Close() }()
	for i := 0; i < 2; i++ {
		_ = logger2.LogEntry(LogEntry{Agent: "test-agent", Action: fmt.Sprintf("post-%d", i), Path: "p", OK: true})
	}

	logFile := filepath.Join(auditDir, "audit-straddle-lost-key-test.log")
	currentKid := KeyFingerprint(newKey)

	// Verify with only the current key on hand — the archived key was lost.
	result, err := VerifyLogAgainstKeys(logFile, map[string][]byte{currentKid: newKey}, currentKid)
	if err != nil {
		t.Fatalf("VerifyLogAgainstKeys() error = %v", err)
	}
	if !result.Valid {
		t.Fatalf("missing archived key must not be reported as tampered (tampered=%d)", result.Tampered)
	}
	if result.Tampered != 0 {
		t.Fatalf("Tampered = %d, want 0 (missing key is unverifiable, not tampered)", result.Tampered)
	}
	if result.Unverifiable != 2 {
		t.Fatalf("Unverifiable = %d, want 2 (the two pre-rotation entries)", result.Unverifiable)
	}
	if result.Verified != 2 {
		t.Fatalf("Verified = %d, want 2 (the two post-rotation entries)", result.Verified)
	}
}

// TestKeystoreRotateKeyTwiceSameDayBothRecoverable covers the second #685
// follow-up limitation: RotateKeyArchivePath used to be keyed only by date
// (YYYY-MM-DD), so a second rotation on the same day silently overwrote the
// first day's archive. Archive paths are now keyed by the old key's
// fingerprint, so both generations from two same-day rotations must remain
// individually recoverable.
func TestKeystoreRotateKeyTwiceSameDayBothRecoverable(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeystore(dir, nil)

	key0, err := ks.LoadOrCreateHMACKey()
	if err != nil {
		t.Fatalf("LoadOrCreateHMACKey() error = %v", err)
	}

	key1, archive1, err := ks.RotateKey()
	if err != nil {
		t.Fatalf("first RotateKey() error = %v", err)
	}

	key2, archive2, err := ks.RotateKey()
	if err != nil {
		t.Fatalf("second RotateKey() error = %v", err)
	}

	if archive1 == archive2 {
		t.Fatalf("expected distinct archive paths for two same-day rotations, both were %s", archive1)
	}

	archived, err := ks.LoadArchivedKeys()
	if err != nil {
		t.Fatalf("LoadArchivedKeys() error = %v", err)
	}
	if len(archived) != 2 {
		t.Fatalf("LoadArchivedKeys() returned %d key(s), want 2 (got %v)", len(archived), keysOf(archived))
	}

	got0, ok := archived[KeyFingerprint(key0)]
	if !ok {
		t.Fatalf("first rotated-out key generation (fingerprint %s) not recoverable, got %v", KeyFingerprint(key0), keysOf(archived))
	}
	if hex.EncodeToString(got0) != hex.EncodeToString(key0) {
		t.Fatal("recovered first archived key does not match original")
	}

	got1, ok := archived[KeyFingerprint(key1)]
	if !ok {
		t.Fatalf("second rotated-out key generation (fingerprint %s) not recoverable, got %v", KeyFingerprint(key1), keysOf(archived))
	}
	if hex.EncodeToString(got1) != hex.EncodeToString(key1) {
		t.Fatal("recovered second archived key does not match original")
	}

	current, err := ks.LoadHMACKey()
	if err != nil {
		t.Fatalf("LoadHMACKey() error = %v", err)
	}
	if hex.EncodeToString(current) != hex.EncodeToString(key2) {
		t.Fatal("current key after two rotations does not match latest RotateKey() result")
	}
}
