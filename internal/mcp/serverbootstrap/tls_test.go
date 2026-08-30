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
