package crypto

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestGenerateIdentityString_Success(t *testing.T) {
	identityStr, err := GenerateIdentityString()
	if err != nil {
		t.Fatalf("GenerateIdentityString() error = %v", err)
	}
	if identityStr == "" {
		t.Fatal("GenerateIdentityString() returned empty string")
	}
	if !strings.HasPrefix(identityStr, "AGE-SECRET-KEY-") {
		t.Errorf("unexpected format: %s", identityStr)
	}
}

func TestSaveIdentity_PathTraversal(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}

	err = SaveIdentity(identity, "../../../etc/passwd", []byte("passphrase"), 0)
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Errorf("expected error to mention 'escapes', got: %v", err)
	}
}

func TestLoadIdentity_PathTraversal(t *testing.T) {
	_, err := LoadIdentity("../../../etc/passwd", []byte("passphrase"))
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
	if !strings.Contains(err.Error(), "escapes") {
		t.Errorf("expected error to mention 'escapes', got: %v", err)
	}
}

func TestLoadIdentity_CorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupted.age")

	if err := os.WriteFile(path, []byte("this is not valid encrypted data"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := LoadIdentity(path, []byte("anypassphrase"))
	if err == nil {
		t.Fatal("expected error for corrupted file, got nil")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestLoadIdentity_WrongPassphrase(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "identity.age")
	passphrase := []byte("correct passphrase")

	if err := SaveIdentity(identity, path, passphrase, 0); err != nil {
		t.Fatalf("SaveIdentity failed: %v", err)
	}

	_, err = LoadIdentity(path, []byte("wrong passphrase"))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestLoadIdentity_FileReadError(t *testing.T) {
	_, err := LoadIdentity("/this/path/does/not/exist/identity.age", []byte("passphrase"))
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
	if !strings.Contains(err.Error(), "read file") {
		t.Errorf("expected error to contain 'read file', got: %v", err)
	}
}

func TestEncryptWithPassphrase_Success(t *testing.T) {
	plaintext := []byte("test passphrase encryption")
	passphrase := []byte("my secret passphrase")

	ciphertext, err := EncryptWithPassphrase(plaintext, passphrase, 0)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase() error = %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}

	passphrase = []byte("my secret passphrase")
	decrypted, err := DecryptWithPassphrase(ciphertext, passphrase)
	if err != nil {
		t.Fatalf("DecryptWithPassphrase() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestEncryptWithPassphrase_EmptyPlaintext(t *testing.T) {
	_, err := EncryptWithPassphrase([]byte{}, []byte("passphrase"), 0)
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Errorf("expected ErrEmptyPlaintext, got: %v", err)
	}
}

func TestEncryptWithPassphrase_EmptyPassphrase(t *testing.T) {
	_, err := EncryptWithPassphrase([]byte("test"), []byte(""), 0)
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestDecryptWithPassphrase_EmptyCiphertext(t *testing.T) {
	_, err := DecryptWithPassphrase([]byte{}, []byte("passphrase"))
	if !errors.Is(err, ErrEmptyCiphertext) {
		t.Errorf("expected ErrEmptyCiphertext, got: %v", err)
	}
}

func TestDecryptWithPassphrase_EmptyPassphrase(t *testing.T) {
	_, err := DecryptWithPassphrase([]byte("encrypted"), []byte(""))
	if err == nil {
		t.Fatal("expected error for empty passphrase")
	}
}

func TestDecryptWithPassphrase_CorruptedCiphertext(t *testing.T) {
	plaintext := []byte("test")
	ciphertext, err := EncryptWithPassphrase(plaintext, []byte("correct"), 0)
	if err != nil {
		t.Fatalf("EncryptWithPassphrase() error = %v", err)
	}

	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	for i := range corrupted {
		corrupted[i] ^= 0xFF
	}

	_, err = DecryptWithPassphrase(corrupted, []byte("correct"))
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestDecryptWithPassphrase_NonEncryptedData(t *testing.T) {
	randomData := make([]byte, 100)
	for i := range randomData {
		randomData[i] = byte(i)
	}

	_, err := DecryptWithPassphrase(randomData, []byte("anypassphrase"))
	if err == nil {
		t.Fatal("expected error for non-encrypted data")
	}
}

func TestGenerateTOTP_InvalidBase32Secret(t *testing.T) {
	_, err := GenerateTOTP("INVALID!@#$%^&*()", "SHA1", 6, 30)
	if err == nil {
		t.Fatal("expected error for invalid Base32 secret")
	}
}

func TestGenerateTOTP_Base32NoPadding(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	code, err := GenerateTOTP(secret, "SHA1", 6, 30)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}
	if len(code.Code) != 6 {
		t.Errorf("code length = %d, want 6", len(code.Code))
	}
}

func TestGenerateTOTP_AlgorithmCaseInsensitive(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"

	codes := make(map[string]bool)
	for _, algo := range []string{"sha1", "SHA1", "Sha1", "sHa1"} {
		code, err := GenerateTOTP(secret, algo, 6, 30)
		if err != nil {
			t.Fatalf("GenerateTOTP(%q) error = %v", algo, err)
		}
		codes[code.Code] = true
	}
	if len(codes) != 1 {
		t.Errorf("expected same code for case variations, got %d unique codes", len(codes))
	}
}

func TestGenerateTOTP_ZeroDigitsEdgeCase(t *testing.T) {
	code, err := GenerateTOTP("JBSWY3DPEHPK3PXP", "SHA1", 0, 30)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}
	if len(code.Code) != 6 {
		t.Errorf("expected 6 digits as default, got %d", len(code.Code))
	}
}

func TestGenerateTOTP_ZeroPeriodEdgeCase(t *testing.T) {
	code, err := GenerateTOTP("JBSWY3DPEHPK3PXP", "SHA1", 6, 0)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}
	if code.Period != 30 {
		t.Errorf("expected period 30 as default, got %d", code.Period)
	}
}

func TestGenerateTOTP_AllBase32Variants(t *testing.T) {
	secrets := []string{
		"JBSWY3DPEHPK3PXP",
		"jbswy3dpehpk3pxp",
		"JBSWY3DP EHPK3PXP",
	}

	for _, secret := range secrets {
		code, err := GenerateTOTP(secret, "SHA1", 6, 30)
		if err != nil {
			t.Errorf("GenerateTOTP(%q) error = %v", secret, err)
			continue
		}
		if len(code.Code) != 6 {
			t.Errorf("GenerateTOTP(%q) code length = %d, want 6", secret, len(code.Code))
		}
	}
}

func TestGenerateTOTP_ExpiresAtCalculation(t *testing.T) {
	code, err := GenerateTOTP("JBSWY3DPEHPK3PXP", "SHA1", 6, 30)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}

	if code.ExpiresAt.Unix()%30 != 0 {
		t.Errorf("ExpiresAt should be aligned to period boundary, got %d", code.ExpiresAt.Unix())
	}

	if !code.ExpiresAt.After(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
}

func TestGenerateTOTP_Digits8(t *testing.T) {
	code, err := GenerateTOTP("JBSWY3DPEHPK3PXP", "SHA1", 8, 30)
	if err != nil {
		t.Fatalf("GenerateTOTP() error = %v", err)
	}
	if len(code.Code) != 8 {
		t.Errorf("code length = %d, want 8", len(code.Code))
	}
}

func TestEncryptWithRecipients_EmptyRecipientsList(t *testing.T) {
	_, err := EncryptWithRecipients([]byte("test"))
	if !errors.Is(err, ErrNoRecipients) {
		t.Errorf("expected ErrNoRecipients, got: %v", err)
	}
}

func TestEncryptWithRecipients_NilRecipientInMiddle(t *testing.T) {
	identity1, _ := age.GenerateX25519Identity()
	identity2, _ := age.GenerateX25519Identity()

	recipients := []*age.X25519Recipient{
		identity1.Recipient(),
		nil,
		identity2.Recipient(),
	}

	_, err := EncryptWithRecipients([]byte("test"), recipients...)
	if err == nil {
		t.Fatal("expected error for nil recipient")
	}
	if !strings.Contains(err.Error(), "index 1") {
		t.Errorf("expected error to mention index 1, got: %v", err)
	}
}

func TestDecrypt_WrongIdentity(t *testing.T) {
	identity1, _ := age.GenerateX25519Identity()
	identity2, _ := age.GenerateX25519Identity()

	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, identity1.Recipient())
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	_, err = Decrypt(ciphertext, identity2)
	if err == nil {
		t.Fatal("expected error for wrong identity")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestEncrypt_EmptyPlaintext(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	_, err := Encrypt([]byte{}, identity.Recipient())
	if !errors.Is(err, ErrEmptyPlaintext) {
		t.Errorf("expected ErrEmptyPlaintext, got: %v", err)
	}
}

func TestDecrypt_EmptyCiphertext(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	_, err := Decrypt([]byte{}, identity)
	if !errors.Is(err, ErrEmptyCiphertext) {
		t.Errorf("expected ErrEmptyCiphertext, got: %v", err)
	}
}

func TestValidateRecipient_EmptyString(t *testing.T) {
	_, err := ValidateRecipient("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if err.Error() != "recipient string is empty" {
		t.Errorf("expected 'recipient string is empty', got: %v", err)
	}
}

func TestValidateRecipient_WrongPrefix(t *testing.T) {
	_, err := ValidateRecipient("age2recipient")
	if err == nil {
		t.Fatal("expected error for wrong prefix")
	}
	if !strings.Contains(err.Error(), "age1") {
		t.Errorf("expected error to mention 'age1', got: %v", err)
	}
}

func TestValidateIdentity_EmptyString(t *testing.T) {
	_, err := ValidateIdentity("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if err.Error() != "identity string is empty" {
		t.Errorf("expected 'identity string is empty', got: %v", err)
	}
}

func TestValidateIdentity_WrongPrefix(t *testing.T) {
	_, err := ValidateIdentity("AGE-SECRET-KEY-")
	if err == nil {
		t.Fatal("expected error for wrong prefix")
	}
}

func TestIsValidRecipient_InvalidStrings(t *testing.T) {
	invalid := []string{
		"",
		"invalid",
		"age2recipient",
		"AGE-SECRET-KEY-1invalid",
	}
	for _, s := range invalid {
		if IsValidRecipient(s) {
			t.Errorf("IsValidRecipient(%q) = true, want false", s)
		}
	}
}

func TestIsValidIdentity_InvalidStrings(t *testing.T) {
	invalid := []string{
		"",
		"invalid",
		"AGE-SECRET-KEY-",
		"AGE-SECRET-KEY-1invalid",
	}
	for _, s := range invalid {
		if IsValidIdentity(s) {
			t.Errorf("IsValidIdentity(%q) = true, want false", s)
		}
	}
}

func TestRecipientsToStrings_NilRecipients(t *testing.T) {
	recipients := []*age.X25519Recipient{nil, nil}
	strs := RecipientsToStrings(recipients)
	if len(strs) != 2 {
		t.Errorf("len(strs) = %d, want 2", len(strs))
	}
	for i, s := range strs {
		if s != "" {
			t.Errorf("strs[%d] = %q, want empty string for nil recipient", i, s)
		}
	}
}

func TestParseRecipients_EmptyList(t *testing.T) {
	_, err := ParseRecipients([]string{})
	if !errors.Is(err, ErrNoRecipients) {
		t.Errorf("expected ErrNoRecipients, got: %v", err)
	}
}

func TestParseRecipients_InvalidRecipient(t *testing.T) {
	_, err := ParseRecipients([]string{"not-a-valid-recipient"})
	if err == nil {
		t.Fatal("expected error for invalid recipient")
	}
	if !strings.Contains(err.Error(), "recipient at index 0") {
		t.Errorf("expected error to mention 'recipient at index 0', got: %v", err)
	}
}

func TestEncryptDecryptWithRecipients_Roundtrip(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	plaintext := []byte("multi-recipient secret")

	ciphertext, err := EncryptWithRecipients(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("EncryptWithRecipients() error = %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestEncryptDecrypt_1MB(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()

	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("1MB roundtrip mismatch")
	}
}

func TestEncryptDecrypt_10MB(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()

	plaintext := make([]byte, 10*1024*1024)
	for i := range plaintext {
		plaintext[i] = byte((i * 7) % 256)
	}

	ciphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("10MB roundtrip mismatch")
	}
}

func TestValidateTOTPParams_InvalidAlgo(t *testing.T) {
	for _, algo := range []string{"MD5", "SHA-256", "AES"} {
		err := ValidateTOTPParams(algo, 6, 30)
		if err == nil {
			t.Errorf("ValidateTOTPParams(%q) = nil, want error", algo)
		}
	}
}

func TestGenerateIdentity_NonDeterministic(t *testing.T) {
	id1, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}
	id2, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}

	if id1.String() == id2.String() {
		t.Error("GenerateIdentity() produced identical identities - not deterministic (expected)")
	}
}

func TestEncryptWithRecipients_SingleRecipient(t *testing.T) {
	identity, _ := age.GenerateX25519Identity()
	plaintext := []byte("single recipient test")

	ciphertext, err := EncryptWithRecipients(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("EncryptWithRecipients() error = %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("roundtrip mismatch")
	}
}

func TestDecrypt_NilIdentity(t *testing.T) {
	_, err := Decrypt([]byte("test"), nil)
	if !errors.Is(err, ErrNilIdentity) {
		t.Errorf("expected ErrNilIdentity, got: %v", err)
	}
}

func TestEncrypt_NilRecipient(t *testing.T) {
	_, err := Encrypt([]byte("test"), nil)
	if !errors.Is(err, ErrNilRecipient) {
		t.Errorf("expected ErrNilRecipient, got: %v", err)
	}
}
