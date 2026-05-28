// Package serverbootstrap provides HTTP and stdio server initialization for the MCP server.
package serverbootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

// ensureTLSCert returns the paths to a usable TLS certificate and key for the
// MCP HTTP server. If the vault directory already contains a cached cert+key
// pair they are reused; otherwise a new self-signed certificate is generated
// for loopback addresses (127.0.0.1, ::1, localhost). Returns empty strings
// when vaultDir is empty.
func ensureTLSCert(vaultDir string) (certFile, keyFile string, err error) {
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

// generateSelfSignedCert creates a self-signed Ed25519 certificate valid for
// loopback addresses and writes the PEM-encoded certificate and private key
// to the specified paths.
func generateSelfSignedCert(certFile, keyFile string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key: %w", err)
	}

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

	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
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
		os.Remove(keyFile)
		return fmt.Errorf("write certificate: %w", err)
	}

	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
