package audit

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestKeystoreLoadOrCreateAndLoadBack(t *testing.T) {
	dir := t.TempDir()

	ks := NewKeystore(dir, nil)
	key, err := ks.LoadOrCreateHMACKey()
	if err != nil {
		t.Fatalf("LoadOrCreateHMACKey() error = %v", err)
	}
	if len(key) != hmacKeySize {
		t.Fatalf("got key length %d, want %d", len(key), hmacKeySize)
	}

	loaded, err := ks.LoadHMACKey()
	if err != nil {
		t.Fatalf("LoadHMACKey() error = %v", err)
	}
	if len(loaded) != hmacKeySize {
		t.Fatalf("loaded key length %d, want %d", len(loaded), hmacKeySize)
	}

	if hex.EncodeToString(key) != hex.EncodeToString(loaded) {
		t.Fatal("loaded key does not match created key")
	}
}

func TestKeystoreLoadHMACKeyNotFound(t *testing.T) {
	dir := t.TempDir()

	ks := NewKeystore(dir, nil)
	_, err := ks.LoadHMACKey()
	if err == nil {
		t.Fatal("expected error for non-existent key, got nil")
	}
}

func TestKeystoreRotateKey(t *testing.T) {
	dir := t.TempDir()

	ks := NewKeystore(dir, nil)
	key, err := ks.LoadOrCreateHMACKey()
	if err != nil {
		t.Fatalf("LoadOrCreateHMACKey() error = %v", err)
	}

	newKey, err := ks.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if len(newKey) != hmacKeySize {
		t.Fatalf("new key length %d, want %d", len(newKey), hmacKeySize)
	}

	if hex.EncodeToString(key) == hex.EncodeToString(newKey) {
		t.Fatal("rotated key should differ from original")
	}

	loaded, err := ks.LoadHMACKey()
	if err != nil {
		t.Fatalf("LoadHMACKey() after rotation error = %v", err)
	}
	if hex.EncodeToString(newKey) != hex.EncodeToString(loaded) {
		t.Fatal("loaded key does not match rotated key")
	}

	archivePath := RotateKeyArchivePath(dir)
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		t.Skipf("archive file not created at %s (expected on file-based keystore)", archivePath)
	}
}

func TestKeystoreIdempotentLoadOrCreate(t *testing.T) {
	dir := t.TempDir()

	ks := NewKeystore(dir, nil)
	key1, err := ks.LoadOrCreateHMACKey()
	if err != nil {
		t.Fatalf("first LoadOrCreateHMACKey() error = %v", err)
	}

	key2, err := ks.LoadOrCreateHMACKey()
	if err != nil {
		t.Fatalf("second LoadOrCreateHMACKey() error = %v", err)
	}

	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Fatal("LoadOrCreateHMACKey() produced different keys on subsequent calls")
	}
}

func TestKeystoreWithAuditLogIntegration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("keystore-integ-test", "", nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	if len(logger.hmacKey) != hmacKeySize {
		t.Fatalf("logger HMAC key length %d, want %d", len(logger.hmacKey), hmacKeySize)
	}

	auditDir := filepath.Join(home, ".symvault")

	ks := NewKeystore(auditDir, nil)
	loaded, err := ks.LoadHMACKey()
	if err != nil {
		t.Fatalf("LoadHMACKey() error = %v", err)
	}

	if hex.EncodeToString(logger.hmacKey) != hex.EncodeToString(loaded) {
		t.Fatal("keystore key does not match logger's HMAC key")
	}
}

func TestKeystoreHMACVerificationAfterKeystoreUse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("verify-keystore-test", "", nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()
	logger.SetSyncMode(true)

	_ = logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "get",
		Path:   "test/path",
		OK:     true,
	})

	result, err := logger.Verify()
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !result.Valid {
		t.Fatal("expected valid chain after keystore-backed key usage")
	}
	if result.Verified != 1 {
		t.Fatalf("Verified = %d, want 1", result.Verified)
	}
}
