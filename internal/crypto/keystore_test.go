package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

func TestSaveEncryptedKey_NilIdentity(t *testing.T) {
	err := SaveEncryptedKey("/tmp/test", []byte("key"), nil)
	if err == nil {
		t.Fatal("SaveEncryptedKey() error = nil, want error for nil identity")
	}
}

func TestSaveEncryptedKey_Roundtrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error = %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted-key")

	keyMaterial := []byte("my-secret-key-material-32-bytes-long!")
	if err := SaveEncryptedKey(path, keyMaterial, identity); err != nil {
		t.Fatalf("SaveEncryptedKey() error = %v", err)
	}

	// Verify file exists and has age header
	isEnc, err := IsEncryptedKeyFile(path)
	if err != nil {
		t.Fatalf("IsEncryptedKeyFile() error = %v", err)
	}
	if !isEnc {
		t.Fatal("IsEncryptedKeyFile() = false, want true")
	}

	// Load and decrypt
	loaded, err := LoadEncryptedKey(path, identity)
	if err != nil {
		t.Fatalf("LoadEncryptedKey() error = %v", err)
	}
	if string(loaded) != string(keyMaterial) {
		t.Fatalf("LoadEncryptedKey() = %q, want %q", string(loaded), string(keyMaterial))
	}
}

func TestLoadEncryptedKey_NotFound(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error = %v", err)
	}

	_, err = LoadEncryptedKey("/nonexistent/path/key", identity)
	if err == nil {
		t.Fatal("LoadEncryptedKey() error = nil, want ErrKeyFileNotFound")
	}
}

func TestLoadEncryptedKey_LegacyPlaintext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy-key")

	legacyData := []byte("legacy-plaintext-key-not-encrypted")
	if err := os.WriteFile(path, legacyData, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Without identity, should still return plaintext for legacy format
	data, err := LoadEncryptedKey(path, nil)
	if err != nil {
		t.Fatalf("LoadEncryptedKey() error = %v, want legacy data returned", err)
	}
	if string(data) != string(legacyData) {
		t.Fatalf("LoadEncryptedKey() = %q, want %q", string(data), string(legacyData))
	}
}

func TestLoadEncryptedKey_NilIdentityWithEncrypted(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error = %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted-key")

	keyMaterial := []byte("secret-key-data")
	if err := SaveEncryptedKey(path, keyMaterial, identity); err != nil {
		t.Fatalf("SaveEncryptedKey() error = %v", err)
	}

	// Load with nil identity should fail because file is age-encrypted
	_, err = LoadEncryptedKey(path, nil)
	if err == nil {
		t.Fatal("LoadEncryptedKey() error = nil, want ErrIdentityRequired")
	}
}

func TestIsEncryptedKeyFile_NotFound(t *testing.T) {
	isEnc, err := IsEncryptedKeyFile("/nonexistent/path/file")
	if err != nil {
		t.Fatalf("IsEncryptedKeyFile() error = %v", err)
	}
	if isEnc {
		t.Fatal("IsEncryptedKeyFile() = true, want false for nonexistent file")
	}
}

func TestIsEncryptedKeyFile_Plaintext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(path, []byte("not age encrypted"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	isEnc, err := IsEncryptedKeyFile(path)
	if err != nil {
		t.Fatalf("IsEncryptedKeyFile() error = %v", err)
	}
	if isEnc {
		t.Fatal("IsEncryptedKeyFile() = true, want false for plaintext file")
	}
}
