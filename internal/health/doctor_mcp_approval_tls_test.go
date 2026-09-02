package health_test

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
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/health"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
	"github.com/danieljustus/symaira-vault/internal/pairing"
)

// writeNearExpiryCert writes a self-signed cert+key pair with the given
// NotAfter directly under vaultDir, at the exact paths EnsureTLSCert/
// CertStatus use, so this doctor-check test can exercise the near-expiry
// warning without depending on serverbootstrap's unexported test helpers.
func writeNearExpiryCert(t *testing.T, vaultDir string, notAfter time.Time) {
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
	if err := os.WriteFile(filepath.Join(vaultDir, "mcp-server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "mcp-server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
}

func runMCPApprovalTLSCheck(t *testing.T, vaultDir string) health.Result {
	t.Helper()
	results := health.RunChecks(vaultDir, health.Options{Only: []string{"mcp.approval.tls"}, NoNetwork: true})
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 result for mcp.approval.tls, got %d: %+v", len(results), results)
	}
	return results[0]
}

func TestCheckMCPApprovalTLS_NoCertYet(t *testing.T) {
	dir := t.TempDir()

	r := runMCPApprovalTLSCheck(t, dir)
	if r.Status != health.StatusOK {
		t.Fatalf("status = %v, want OK; message = %q", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "no TLS certificate generated yet") {
		t.Fatalf("message = %q, want it to mention no cert yet", r.Message)
	}
}

func TestCheckMCPApprovalTLS_HealthyCert(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := serverbootstrap.EnsureTLSCert(dir); err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}

	r := runMCPApprovalTLSCheck(t, dir)
	if r.Status != health.StatusOK {
		t.Fatalf("status = %v, want OK; message = %q", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "cert expires") {
		t.Fatalf("message = %q, want it to report the cert's expiry", r.Message)
	}
}

func TestCheckMCPApprovalTLS_ReportsDeviceCounts(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := serverbootstrap.EnsureTLSCert(dir); err != nil {
		t.Fatalf("EnsureTLSCert: %v", err)
	}

	store, err := pairing.NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	if _, err := store.Enroll("device-active", "Active Phone", ""); err != nil {
		t.Fatalf("Enroll active: %v", err)
	}
	if _, err := store.Enroll("device-revoked", "Revoked Phone", ""); err != nil {
		t.Fatalf("Enroll revoked: %v", err)
	}
	store.Revoke("device-revoked")

	r := runMCPApprovalTLSCheck(t, dir)
	if !strings.Contains(r.Message, "1 approval device(s) active") {
		t.Fatalf("message = %q, want it to report 1 active device", r.Message)
	}
	if !strings.Contains(r.Message, "1 revoked") {
		t.Fatalf("message = %q, want it to report 1 revoked device", r.Message)
	}
}

func TestCheckMCPApprovalTLS_WarnsWhenCertNearExpiry(t *testing.T) {
	dir := t.TempDir()
	writeNearExpiryCert(t, dir, time.Now().Add(10*24*time.Hour)) // inside the 30-day renewal window

	r := runMCPApprovalTLSCheck(t, dir)
	if r.Status != health.StatusWarn {
		t.Fatalf("status = %v, want Warn for a cert expiring in 10 days; message = %q", r.Status, r.Message)
	}
	if r.Hint == "" {
		t.Fatal("expected a hint explaining the automatic regeneration and re-pairing requirement")
	}
}

func TestCheckMCPApprovalTLS_WarnsWhenCertExpired(t *testing.T) {
	dir := t.TempDir()
	writeNearExpiryCert(t, dir, time.Now().Add(-24*time.Hour)) // already expired

	r := runMCPApprovalTLSCheck(t, dir)
	if r.Status != health.StatusWarn {
		t.Fatalf("status = %v, want Warn for an already-expired cert; message = %q", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "expired") {
		t.Fatalf("message = %q, want it to say the cert expired", r.Message)
	}
}
