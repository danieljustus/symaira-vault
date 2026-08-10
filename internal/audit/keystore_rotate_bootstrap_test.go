package audit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestRotateKeyBootstrapsWhenNoKeyExists is the #803 regression: rotating a
// vault that has no stored HMAC key must succeed (bootstrap) instead of
// failing with "load existing key for rotation", must not write an archive
// file, and must leave a usable key behind.
func TestRotateKeyBootstrapsWhenNoKeyExists(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeystore(t, dir)

	// Sanity: no key exists yet.
	if _, err := ks.LoadHMACKey(); !IsHMACKeyNotFound(err) {
		t.Fatalf("precondition: LoadHMACKey() error = %v, want not-found", err)
	}

	newKey, archivePath, err := ks.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey() on vault without a key error = %v", err)
	}
	if len(newKey) != hmacKeySize {
		t.Fatalf("bootstrapped key length %d, want %d", len(newKey), hmacKeySize)
	}
	if archivePath != "" {
		t.Fatalf("bootstrap archivePath = %q, want empty (nothing to archive)", archivePath)
	}

	// The bootstrapped key must be loadable afterwards.
	loaded, err := ks.LoadHMACKey()
	if err != nil {
		t.Fatalf("LoadHMACKey() after bootstrap error = %v", err)
	}
	if string(loaded) != string(newKey) {
		t.Fatal("loaded key does not match bootstrapped key")
	}

	// No archive file may be written for a bootstrap.
	matches, err := filepath.Glob(filepath.Join(dir, hmacKeyFileName+".rotated.*"))
	if err != nil {
		t.Fatalf("glob archive files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("bootstrap wrote %d archive file(s): %v", len(matches), matches)
	}
}

// TestRotateKeyWithExistingKeyStillArchives guards the #803 risk that the
// bootstrap path masks real rotation: with an existing key, rotation must
// still archive the old key under its fingerprint, unchanged.
func TestRotateKeyWithExistingKeyStillArchives(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeystore(t, dir)

	oldKey, err := ks.LoadOrCreateHMACKey()
	if err != nil {
		t.Fatalf("LoadOrCreateHMACKey() error = %v", err)
	}

	newKey, archivePath, err := ks.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if string(newKey) == string(oldKey) {
		t.Fatal("rotated key should differ from original")
	}

	wantArchive := RotateKeyArchivePath(dir, oldKey)
	if archivePath != wantArchive {
		t.Fatalf("archivePath = %s, want %s", archivePath, wantArchive)
	}
	data, err := os.ReadFile(wantArchive)
	if err != nil {
		t.Fatalf("archive file missing after rotation: %v", err)
	}
	// Archive format is unchanged: hex-encoded old key, named by fingerprint.
	if !filepath.HasPrefix(filepath.Base(wantArchive), hmacKeyFileName+".rotated.") {
		t.Fatalf("archive filename %q does not use the fingerprint scheme", filepath.Base(wantArchive))
	}
	if len(data) == 0 {
		t.Fatal("archive file is empty")
	}

	archived, err := ks.LoadArchivedKeys()
	if err != nil {
		t.Fatalf("LoadArchivedKeys() error = %v", err)
	}
	loadedOld, ok := archived[KeyFingerprint(oldKey)]
	if !ok {
		t.Fatalf("LoadArchivedKeys() missing old key fingerprint %s", KeyFingerprint(oldKey))
	}
	if string(loadedOld) != string(oldKey) {
		t.Fatal("archived key does not match original key")
	}
}

// TestRotateKeyCorruptEntryFailsNotBootstraps is the #803 risk guard: a key
// that exists but is unreadable (corrupt hex) must NOT be treated as "no
// key". Rotation must fail loudly instead of silently overwriting the entry.
func TestRotateKeyCorruptEntryFailsNotBootstraps(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeystore(t, dir)

	// Seed a corrupt (non-hex) value for this audit dir directly in the
	// keyring store, as if a previous write had been corrupted.
	if err := getFallback().Set(keyringService, keyringAccount(dir), "not-hex-at-all"); err != nil {
		t.Fatalf("seed corrupt keyring value: %v", err)
	}
	// Precondition: load fails with a decode error, not a not-found error.
	if _, err := ks.LoadHMACKey(); err == nil || IsHMACKeyNotFound(err) {
		t.Fatalf("precondition: LoadHMACKey() error = %v, want corrupt-key error", err)
	}

	_, archivePath, err := ks.RotateKey()
	if err == nil {
		t.Fatal("RotateKey() succeeded on a corrupt key, want error")
	}
	if archivePath != "" {
		t.Fatalf("corrupt-key rotation returned archivePath %q, want empty", archivePath)
	}
	// The corrupt entry must not have been replaced by a bootstrap.
	if _, err := ks.LoadHMACKey(); err == nil || IsHMACKeyNotFound(err) {
		t.Fatalf("corrupt entry was overwritten: LoadHMACKey() error = %v", err)
	}
}

func TestIsHMACKeyNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "keyring not found", err: keyring.ErrNotFound, want: true},
		{name: "memory sentinel", err: errMemoryKeyringNotFound, want: true},
		{name: "generic error", err: errors.New("boom"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHMACKeyNotFound(tt.err); got != tt.want {
				t.Errorf("IsHMACKeyNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
