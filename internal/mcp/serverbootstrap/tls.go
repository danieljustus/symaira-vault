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
)

const (
	// autoCertFile is the filename for the auto-generated TLS certificate in the vault directory.
	autoCertFile = "mcp-server.crt"
	// autoKeyFile is the filename for the auto-generated TLS private key in the vault directory.
	autoKeyFile = "mcp-server.key"
)

// EnsureTLSCert returns the paths to a usable TLS certificate and key for the
// MCP HTTP server. If the vault directory already contains a cached cert+key
// pair they are reused; otherwise a new self-signed certificate is generated
// for loopback addresses (127.0.0.1, ::1, localhost). Returns empty strings
// when vaultDir is empty.
func EnsureTLSCert(vaultDir string) (certFile, keyFile string, err error) {
	if vaultDir == "" {
		return "", "", nil
	}
	certFile = filepath.Join(vaultDir, autoCertFile)
	keyFile = filepath.Join(vaultDir, autoKeyFile)

	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}

	if err := generateSelfSignedCert(certFile, keyFile); err != nil {
		return "", "", fmt.Errorf("generate self-signed TLS certificate: %w", err)
	}
	return certFile, keyFile, nil
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
	pemBytes, err := os.ReadFile(certFile) // #nosec G304 -- certFile is EnsureTLSCert's own fixed filename under vaultDir, same security domain
	if err != nil {
		return "", fmt.Errorf("read TLS certificate: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("decode TLS certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse TLS certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}
