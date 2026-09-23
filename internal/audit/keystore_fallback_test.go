//go:build !(darwin || linux || windows)

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFallbackKeystoreRotationPersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	firstStore := NewKeystore(dir, nil)
	first, archive, err := firstStore.RotateKey()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if archive != "" {
		t.Fatalf("bootstrap archive = %q, want empty", archive)
	}

	secondStore := NewKeystore(dir, nil)
	second, archive, err := secondStore.RotateKey()
	if err != nil {
		t.Fatalf("rotate from a fresh keystore instance: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("rotation did not replace the key")
	}
	if want := RotateKeyArchivePath(dir, first); archive != want {
		t.Fatalf("archive = %q, want %q", archive, want)
	}

	for _, path := range []string{
		filepath.Join(dir, hmacKeyFileName),
		filepath.Join(dir, hmacKeyFileName+".kek"),
		archive,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %04o, want 0600", path, info.Mode().Perm())
		}
	}
	stored, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(stored, []byte(localEncryptionMarker)) {
		t.Fatal("archive is not locally encrypted")
	}
	loaded, err := NewKeystore(dir, nil).LoadHMACKey()
	if err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	if !bytes.Equal(loaded, second) {
		t.Fatal("reloaded key does not match rotated key")
	}
}
