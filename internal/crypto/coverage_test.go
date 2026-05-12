package crypto

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
)

func TestValidateIdentityPathTraversal(t *testing.T) {
	err := validateIdentityPath("../evil/identity.age")
	if err == nil {
		t.Fatal("validateIdentityPath() error = nil, want error for path traversal")
	}
}

func TestValidateIdentityPathAbsolute(t *testing.T) {
	// A path without ".." should pass validation
	if err := validateIdentityPath("/home/user/.openpass/identity.age"); err != nil {
		t.Fatalf("validateIdentityPath() error = %v, want nil for safe path", err)
	}
}

func TestValidateIdentityPathAllowsLiteralDotsInName(t *testing.T) {
	if err := validateIdentityPath("/home/user/my..vault/identity.age"); err != nil {
		t.Fatalf("validateIdentityPath() error = %v, want nil for literal dots in path segment", err)
	}
}

func TestSaveIdentityPathTraversal(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	err = SaveIdentity(identity, "../evil/identity.age", []byte("passphrase"), 0)
	if err == nil {
		t.Fatal("SaveIdentity() error = nil, want error for path traversal")
	}
}

func TestSaveIdentityNonWritablePath(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0 has no effect")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	dir := t.TempDir()
	if errChmod := os.Chmod(dir, 0o500); errChmod != nil {
		t.Fatalf("Chmod() error = %v", errChmod)
	}
	defer os.Chmod(dir, 0o700) //nolint:errcheck

	err = SaveIdentity(identity, filepath.Join(dir, "identity.age"), []byte("passphrase"), 0)
	if err == nil {
		t.Fatal("SaveIdentity() error = nil, want error for non-writable path")
	}
}

func TestLoadIdentityPathTraversal(t *testing.T) {
	_, err := LoadIdentity("../evil/identity.age", []byte("passphrase"))
	if err == nil {
		t.Fatal("LoadIdentity() error = nil, want error for path traversal")
	}
}

func TestLoadIdentityCorruptContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.age")
	if err := os.WriteFile(path, []byte("this is not valid age ciphertext"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := LoadIdentity(path, []byte("passphrase"))
	if err == nil {
		t.Fatal("LoadIdentity() error = nil, want error for corrupt content")
	}
}

func TestEncryptWithRecipientsNilInList(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	_, err = EncryptWithRecipients([]byte("hello"), identity.Recipient(), nil)
	if err == nil {
		t.Fatal("EncryptWithRecipients() error = nil, want error for nil recipient in list")
	}
}

func TestDecryptWithPassphraseWrongPassphrase(t *testing.T) {
	ciphertext, err := EncryptWithPassphrase([]byte("secret"), []byte("correct"), 0)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase() error = %v", err)
	}

	_, err = DecryptWithPassphrase(ciphertext, []byte("wrong"))
	if err == nil {
		t.Fatal("DecryptWithPassphrase() error = nil, want error for wrong passphrase")
	}
}
