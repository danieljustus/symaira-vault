package serverbootstrap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCertFingerprint_StableAcrossRepeatedCalls(t *testing.T) {
	dir := t.TempDir()

	fp1, err := CertFingerprint(dir)
	if err != nil {
		t.Fatalf("CertFingerprint: %v", err)
	}
	if fp1 == "" {
		t.Fatal("expected non-empty fingerprint")
	}

	fp2, err := CertFingerprint(dir)
	if err != nil {
		t.Fatalf("CertFingerprint (second call): %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("expected stable fingerprint for cached cert, got %q then %q", fp1, fp2)
	}
}

func TestCertFingerprint_ChangesWhenCertRegenerated(t *testing.T) {
	dir := t.TempDir()

	fp1, err := CertFingerprint(dir)
	if err != nil {
		t.Fatalf("CertFingerprint: %v", err)
	}

	certFile := filepath.Join(dir, autoCertFile)
	keyFile := filepath.Join(dir, autoKeyFile)
	if err := os.Remove(certFile); err != nil {
		t.Fatalf("remove cert: %v", err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatalf("remove key: %v", err)
	}

	fp2, err := CertFingerprint(dir)
	if err != nil {
		t.Fatalf("CertFingerprint (after regeneration): %v", err)
	}
	if fp1 == fp2 {
		t.Fatal("expected a new fingerprint after cert regeneration, got the same value")
	}
}

func TestCertFingerprint_EmptyVaultDir(t *testing.T) {
	if _, err := CertFingerprint(""); err == nil {
		t.Fatal("expected an error for an empty vault directory")
	}
}

func TestEnsureEnrollSecret_PersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()

	secret1, err := EnsureEnrollSecret(dir)
	if err != nil {
		t.Fatalf("EnsureEnrollSecret: %v", err)
	}
	if len(secret1) != enrollSecretSize {
		t.Fatalf("secret length = %d, want %d", len(secret1), enrollSecretSize)
	}

	secret2, err := EnsureEnrollSecret(dir)
	if err != nil {
		t.Fatalf("EnsureEnrollSecret (second call): %v", err)
	}
	if string(secret1) != string(secret2) {
		t.Fatal("expected the same secret across calls for the same vault directory")
	}
}

func TestEnsureEnrollSecret_DistinctPerVaultDir(t *testing.T) {
	secret1, err := EnsureEnrollSecret(t.TempDir())
	if err != nil {
		t.Fatalf("EnsureEnrollSecret: %v", err)
	}
	secret2, err := EnsureEnrollSecret(t.TempDir())
	if err != nil {
		t.Fatalf("EnsureEnrollSecret: %v", err)
	}
	if string(secret1) == string(secret2) {
		t.Fatal("expected distinct secrets for distinct vault directories")
	}
}

func TestEnsureEnrollSecret_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := EnsureEnrollSecret(dir); err != nil {
		t.Fatalf("EnsureEnrollSecret: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, enrollSecretFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %v, want 0600", info.Mode().Perm())
	}
}

func TestEnsureEnrollSecret_EmptyVaultDir(t *testing.T) {
	secret, err := EnsureEnrollSecret("")
	if err != nil {
		t.Fatalf("EnsureEnrollSecret: %v", err)
	}
	if secret != nil {
		t.Fatalf("expected a nil secret for an empty vault directory, got %d bytes", len(secret))
	}
}
