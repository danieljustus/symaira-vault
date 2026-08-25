package mobilebind_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/mobilebind"
)

func TestMobileBind_CryptoEndToEnd(t *testing.T) {
	// 1. Generate identity
	idStr, err := mobilebind.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if !strings.HasPrefix(idStr, "AGE-SECRET-KEY-") {
		t.Fatalf("expected AGE-SECRET-KEY prefix, got %q", idStr)
	}

	// 2. Derive public key
	pubKey, err := mobilebind.IdentityPublicKey(idStr)
	if err != nil {
		t.Fatalf("IdentityPublicKey: %v", err)
	}
	if !strings.HasPrefix(pubKey, "age1") {
		t.Fatalf("expected age1 prefix, got %q", pubKey)
	}

	// 3. Fingerprint
	fp := mobilebind.PublicKeyFingerprint(pubKey)
	if fp == "" {
		t.Fatalf("empty fingerprint")
	}

	// 4. Encrypt and decrypt with public key / identity
	plaintext := []byte("secret payload for mobile client")
	ciphertext, err := mobilebind.EncryptWithPublicKey(pubKey, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithPublicKey: %v", err)
	}

	decrypted, err := mobilebind.DecryptWithIdentity(idStr, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithIdentity: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted %q != plaintext %q", string(decrypted), string(plaintext))
	}

	// 5. Passphrase encryption / decryption
	passphrase := "correct-horse-battery-staple"
	passCiphertext, err := mobilebind.EncryptWithPassphrase(passphrase, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase: %v", err)
	}

	passDecrypted, err := mobilebind.DecryptWithPassphrase(passphrase, passCiphertext)
	if err != nil {
		t.Fatalf("DecryptWithPassphrase: %v", err)
	}
	if string(passDecrypted) != string(plaintext) {
		t.Fatalf("passphrase decrypted %q != plaintext %q", string(passDecrypted), string(plaintext))
	}
}

func TestMobileBind_VaultEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	vaultDir := filepath.Join(tempDir, "testvault")
	passphrase := "mobile-test-passphrase"

	// 1. Init vault
	if err := mobilebind.InitVault(vaultDir, passphrase); err != nil {
		t.Fatalf("InitVault: %v", err)
	}

	// 2. Open vault and retrieve identity
	idStr, err := mobilebind.OpenVaultWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("OpenVaultWithPassphrase: %v", err)
	}

	// 3. Write entry JSON
	entryJSON := `{"data":{"username":"alice","password":"secretpassword123","url":"https://example.com"}}`
	if err := mobilebind.WriteEntryJSON(vaultDir, "services/example", entryJSON, idStr); err != nil {
		t.Fatalf("WriteEntryJSON: %v", err)
	}

	// 4. Read entry JSON
	readJSON, err := mobilebind.ReadEntryJSON(vaultDir, "services/example", idStr)
	if err != nil {
		t.Fatalf("ReadEntryJSON: %v", err)
	}
	if !strings.Contains(readJSON, "secretpassword123") {
		t.Fatalf("ReadEntryJSON missing password: %s", readJSON)
	}

	// 5. List entries JSON
	listJSON, err := mobilebind.ListEntriesJSON(vaultDir, "", idStr)
	if err != nil {
		t.Fatalf("ListEntriesJSON: %v", err)
	}
	if !strings.Contains(listJSON, "services/example") {
		t.Fatalf("ListEntriesJSON missing path: %s", listJSON)
	}

	// 6. Verify manifest
	valid, err := mobilebind.VerifyManifestIntegrity(vaultDir, idStr)
	if err != nil {
		t.Fatalf("VerifyManifestIntegrity: %v", err)
	}
	if !valid {
		t.Fatalf("expected valid manifest")
	}

	_ = os.RemoveAll(vaultDir)
}
