// Package serverbootstrap provides HTTP and stdio server initialization for the MCP server.
package serverbootstrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
)

const (
	// autoCertFile is the filename for the auto-generated TLS certificate in the vault directory.
	autoCertFile = "mcp-server.crt"
	// autoKeyFile is the filename for the auto-generated TLS private key in the vault directory.
	autoKeyFile = "mcp-server.key"
	// enrollSecretFile is the filename for the random secret that proves
	// vault-directory ownership when minting an approval-device pairing
	// code (see EnsureEnrollSecret).
	enrollSecretFile = "mcp-server.enroll-secret" // #nosec G101 -- filename, not a credential
	// enrollSecretSize is the size in bytes of the generated enroll secret.
	enrollSecretSize = 32
	// CertRenewalWindow is how long before a cached certificate's expiry
	// EnsureTLSCert regenerates it, so operators have advance warning before
	// paired approval devices (and any other pinned client) stop connecting.
	CertRenewalWindow = 30 * 24 * time.Hour
)

// EnsureTLSCert returns the paths to a usable TLS certificate and key for the
// MCP HTTP server. If the vault directory already contains a cached cert+key
// pair, and that certificate is not expired or within CertRenewalWindow of
// expiring, it is reused; otherwise a new self-signed certificate is
// generated for loopback addresses (127.0.0.1, ::1, localhost). Regenerating
// invalidates every device that pinned the previous certificate's
// fingerprint (see internal/approval device enrollment) — those devices
// must be re-paired. Returns empty strings when vaultDir is empty.
func EnsureTLSCert(vaultDir string) (certFile, keyFile string, err error) {
	if vaultDir == "" {
		return "", "", nil
	}
	certFile = filepath.Join(vaultDir, autoCertFile)
	keyFile = filepath.Join(vaultDir, autoKeyFile)

	if fileExists(certFile) && fileExists(keyFile) {
		nearExpiry, checkErr := certNearExpiry(certFile, CertRenewalWindow)
		if checkErr != nil {
			return "", "", fmt.Errorf("check cached TLS certificate: %w", checkErr)
		}
		if !nearExpiry {
			return certFile, keyFile, nil
		}
		cliout.Warnf("cached MCP TLS certificate is expired or expires within %d days; regenerating — every paired approval device must be re-paired, since its pinned certificate fingerprint will no longer match", int(CertRenewalWindow.Hours()/24))
	}

	if err := generateSelfSignedCert(certFile, keyFile); err != nil {
		return "", "", fmt.Errorf("generate self-signed TLS certificate: %w", err)
	}
	return certFile, keyFile, nil
}

// certNearExpiry reports whether the certificate at certFile is already
// expired or will expire within window.
func certNearExpiry(certFile string, window time.Duration) (bool, error) {
	cert, err := loadCertificate(certFile)
	if err != nil {
		return false, err
	}
	return !time.Now().Add(window).Before(cert.NotAfter), nil
}

// loadCertificate reads and parses the PEM-encoded certificate at certFile.
func loadCertificate(certFile string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(certFile) // #nosec G304 -- certFile is EnsureTLSCert's own fixed filename under vaultDir
	if err != nil {
		return nil, fmt.Errorf("read TLS certificate: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode TLS certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse TLS certificate: %w", err)
	}
	return cert, nil
}

// generateSelfSignedCert creates a self-signed ECDSA P-256 certificate valid for
// loopback addresses and writes the PEM-encoded certificate and private key
// to the specified paths.
func generateSelfSignedCert(certFile, keyFile string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ecdsa key: %w", err)
	}
	pub := &priv.PublicKey

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "symaira-vault-mcp",
			Organization: []string{"Symaira Vault MCP Server"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if mkdirErr := os.MkdirAll(filepath.Dir(keyFile), 0o700); mkdirErr != nil {
		return fmt.Errorf("create cert directory: %w", mkdirErr)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	if err := fsutil.SafeWriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// Write certificate
	if err := fsutil.SafeWriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		_ = os.Remove(keyFile)
		return fmt.Errorf("write certificate: %w", err)
	}

	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// CertFingerprint returns the hex-encoded SHA-256 fingerprint of the MCP
// server's current leaf certificate, generating one via EnsureTLSCert first
// if none is cached yet. Callers that hand this fingerprint to a device for
// certificate pinning (see internal/approval device enrollment) must treat
// it as the entire trust story for that pairing: any mismatch on the
// receiving end must fail closed.
func CertFingerprint(vaultDir string) (string, error) {
	certFile, _, err := EnsureTLSCert(vaultDir)
	if err != nil {
		return "", fmt.Errorf("ensure TLS certificate: %w", err)
	}
	if certFile == "" {
		return "", fmt.Errorf("no TLS certificate available for vault directory")
	}
	cert, err := loadCertificate(certFile)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// CertStatus reports whether a cached MCP TLS certificate exists for
// vaultDir and, if so, its expiry time. Unlike EnsureTLSCert, it never
// generates a certificate — this is the read-only status check
// "symvault doctor" uses; callers that need a certificate to exist should
// call EnsureTLSCert instead. Returns exists=false for an empty vaultDir.
func CertStatus(vaultDir string) (exists bool, expiry time.Time, err error) {
	if vaultDir == "" {
		return false, time.Time{}, nil
	}
	certFile := filepath.Join(vaultDir, autoCertFile)
	if !fileExists(certFile) {
		return false, time.Time{}, nil
	}
	cert, err := loadCertificate(certFile)
	if err != nil {
		return true, time.Time{}, err
	}
	return true, cert.NotAfter, nil
}

// EnsureEnrollSecret returns a random secret cached at
// "<vaultDir>/mcp-server.enroll-secret" (0600, generated on first use),
// proof of possession of which stands in for proof of vault-directory
// ownership: only whoever can already read the 0600 vault directory (the
// same trust domain as the TLS private key and age identities) can read
// this file. It is used to authenticate "symvault device approval-pair"'s
// request to mint a pairing code, so a local process without vault-directory
// access cannot self-enroll as an approval device merely by reaching the
// server's loopback listener. Returns nil for an empty vaultDir.
func EnsureEnrollSecret(vaultDir string) ([]byte, error) {
	if vaultDir == "" {
		return nil, nil
	}
	path := filepath.Join(vaultDir, enrollSecretFile)
	existing, err := os.ReadFile(path) // #nosec G304 -- path is this function's own fixed filename under vaultDir
	if err == nil {
		return existing, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read enroll secret: %w", err)
	}
	secret := make([]byte, enrollSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate enroll secret: %w", err)
	}
	if err := fsutil.SafeWriteFile(path, secret, 0o600); err != nil {
		return nil, fmt.Errorf("write enroll secret: %w", err)
	}
	return secret, nil
}
