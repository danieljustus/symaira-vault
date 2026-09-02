package serverbootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCertWithExpiry writes a self-signed cert+key pair with the given
// NotAfter directly to disk, bypassing EnsureTLSCert/generateSelfSignedCert
// (which always mint a fresh ~1-year-valid cert), so tests can exercise
// expiry-driven regeneration.
func writeCertWithExpiry(t *testing.T, certFile, keyFile string, notAfter time.Time) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-fixture"},
		NotBefore:             notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}

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

func TestEnsureTLSCert_RegeneratesExpiredCert(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, autoCertFile)
	keyFile := filepath.Join(dir, autoKeyFile)
	writeCertWithExpiry(t, certFile, keyFile, time.Now().Add(-24*time.Hour))

	gotCertFile, gotKeyFile, err := EnsureTLSCert(dir)
	if err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}
	if gotCertFile != certFile || gotKeyFile != keyFile {
		t.Fatalf("paths = (%q, %q), want (%q, %q)", gotCertFile, gotKeyFile, certFile, keyFile)
	}

	cert, err := loadCertificate(certFile)
	if err != nil {
		t.Fatalf("loadCertificate: %v", err)
	}
	if !cert.NotAfter.After(time.Now().Add(CertRenewalWindow)) {
		t.Fatalf("expected a freshly regenerated cert well beyond the renewal window, got NotAfter=%v", cert.NotAfter)
	}
}

func TestEnsureTLSCert_RegeneratesCertNearExpiry(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, autoCertFile)
	keyFile := filepath.Join(dir, autoKeyFile)
	writeCertWithExpiry(t, certFile, keyFile, time.Now().Add(10*24*time.Hour)) // inside the 30-day window

	if _, _, err := EnsureTLSCert(dir); err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}

	cert, err := loadCertificate(certFile)
	if err != nil {
		t.Fatalf("loadCertificate: %v", err)
	}
	if time.Until(cert.NotAfter) <= CertRenewalWindow {
		t.Fatalf("expected regeneration to push expiry beyond the renewal window, got NotAfter=%v", cert.NotAfter)
	}
}

func TestEnsureTLSCert_ReusesCertOutsideRenewalWindow(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, autoCertFile)
	keyFile := filepath.Join(dir, autoKeyFile)
	notAfter := time.Now().Add(60 * 24 * time.Hour) // outside the 30-day window
	writeCertWithExpiry(t, certFile, keyFile, notAfter)

	if _, _, err := EnsureTLSCert(dir); err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}

	cert, err := loadCertificate(certFile)
	if err != nil {
		t.Fatalf("loadCertificate: %v", err)
	}
	if diff := cert.NotAfter.Sub(notAfter); diff > time.Second || diff < -time.Second {
		t.Fatalf("cert was regenerated when it should have been reused: NotAfter = %v, want %v", cert.NotAfter, notAfter)
	}
}

func TestCertStatus_NoCert(t *testing.T) {
	dir := t.TempDir()
	exists, _, err := CertStatus(dir)
	if err != nil {
		t.Fatalf("CertStatus: %v", err)
	}
	if exists {
		t.Fatal("CertStatus reported a certificate for an empty vault directory")
	}
}

func TestCertStatus_ExistingCert(t *testing.T) {
	dir := t.TempDir()
	notAfter := time.Now().Add(60 * 24 * time.Hour)
	writeCertWithExpiry(t, filepath.Join(dir, autoCertFile), filepath.Join(dir, autoKeyFile), notAfter)

	exists, expiry, err := CertStatus(dir)
	if err != nil {
		t.Fatalf("CertStatus: %v", err)
	}
	if !exists {
		t.Fatal("CertStatus reported no certificate for a directory with one")
	}
	if diff := expiry.Sub(notAfter); diff > time.Second || diff < -time.Second {
		t.Fatalf("expiry = %v, want %v", expiry, notAfter)
	}
}

func TestCertStatus_DoesNotGenerateACert(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := CertStatus(dir); err != nil {
		t.Fatalf("CertStatus: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, autoCertFile)); !os.IsNotExist(err) {
		t.Fatal("CertStatus must not generate a certificate as a side effect")
	}
}

func TestCertStatus_EmptyVaultDir(t *testing.T) {
	exists, _, err := CertStatus("")
	if err != nil {
		t.Fatalf("CertStatus: %v", err)
	}
	if exists {
		t.Fatal("CertStatus reported a certificate for an empty vault directory string")
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
