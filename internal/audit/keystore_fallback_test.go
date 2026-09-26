//go:build !(darwin || linux || windows)

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
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

func TestFallbackKeystoreUsesVaultIdentityForAgeKeyRotation(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	firstStore := NewKeystore(dir, identity)
	first, archive, err := firstStore.RotateKey()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if archive != "" {
		t.Fatalf("bootstrap archive = %q, want empty", archive)
	}

	currentPath := filepath.Join(dir, hmacKeyFileName)
	firstEnvelope, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(firstEnvelope, []byte("age-encryption.org/")) {
		t.Fatal("bootstrap key is not age encrypted")
	}
	if _, err := os.Stat(currentPath + ".kek"); !os.IsNotExist(err) {
		t.Fatalf("unexpected local KEK: stat error = %v", err)
	}

	second, archive, err := NewKeystore(dir, identity).RotateKey()
	if err != nil {
		t.Fatalf("rotate from a fresh keystore instance: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("rotation did not replace the key")
	}
	if want := RotateKeyArchivePath(dir, first); archive != want {
		t.Fatalf("archive = %q, want %q", archive, want)
	}
	archivedEnvelope, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(archivedEnvelope, firstEnvelope) {
		t.Fatal("rotation did not preserve the prior age envelope")
	}
	archivedKey, err := vaultcrypto.Decrypt(archivedEnvelope, identity)
	if err != nil || !bytes.Equal(archivedKey, first) {
		t.Fatalf("decrypt archived key: err=%v, matches=%v", err, bytes.Equal(archivedKey, first))
	}
	currentEnvelope, err := os.ReadFile(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	currentKey, err := vaultcrypto.Decrypt(currentEnvelope, identity)
	if err != nil || !bytes.Equal(currentKey, second) {
		t.Fatalf("decrypt rotated key: err=%v, matches=%v", err, bytes.Equal(currentKey, second))
	}
}
