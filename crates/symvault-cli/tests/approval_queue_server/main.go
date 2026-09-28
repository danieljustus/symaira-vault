// Package main runs the production Go approval handler for Rust CLI E2E tests.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	"github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
)

type fixture struct {
	ApproveID string `json:"approve_id"`
	DenyID    string `json:"deny_id"`
	QuietID   string `json:"quiet_id"`
}

func main() {
	vault := flag.String("vault", "", "isolated test vault")
	flag.Parse()
	if *vault == "" {
		fatal("vault path is required")
	}

	serverCert, serverKey, err := serverbootstrap.EnsureTLSCert(*vault)
	if err != nil {
		fatal("create server certificate: %v", err)
	}
	secret, err := serverbootstrap.EnsureEnrollSecret(*vault)
	if err != nil {
		fatal("create ownership proof secret: %v", err)
	}
	caCert, clientCert, clientKey, err := writeClientIdentity(*vault)
	if err != nil {
		fatal("create approval client identity: %v", err)
	}

	queue := approval.NewQueue()
	approveID, err := queue.Enqueue(approval.Request{
		AgentName: "agent-e2e", Path: "notes/approve.md", Write: true, Reason: "approve fixture",
	})
	if err != nil {
		fatal("enqueue approval fixture: %v", err)
	}
	denyID, err := queue.Enqueue(approval.Request{
		AgentName: "agent-e2e", Path: "notes/deny.md", Reason: "deny fixture",
	})
	if err != nil {
		fatal("enqueue denial fixture: %v", err)
	}
	quietID, err := queue.Enqueue(approval.Request{
		AgentName: "agent-e2e", Path: "notes/quiet.md", Reason: "quiet fixture",
	})
	if err != nil {
		fatal("enqueue quiet fixture: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("listen: %v", err)
	}
	tcpAddress, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		fatal("listener returned unexpected address type %T", listener.Addr())
	}
	if err = cli.SaveRuntimePort(*vault, "127.0.0.1", tcpAddress.Port); err != nil {
		fatal("save runtime port: %v", err)
	}
	if err = cli.SaveRuntimeTLSConfig(*vault, serverCert, caCert, clientCert, clientKey, true); err != nil {
		fatal("save runtime TLS metadata: %v", err)
	}
	if err = writeJSON(filepath.Join(*vault, ".fixture.json"), fixture{approveID, denyID, quietID}); err != nil {
		fatal("write fixture: %v", err)
	}

	caPEM, err := os.ReadFile(caCert) // #nosec G304 -- generated fixed-name path in the isolated test vault.
	if err != nil {
		fatal("read approval client CA: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		fatal("parse approval client CA")
	}
	server := &http.Server{
		Handler: approval.NewLocalHTTPHandler(queue, secret, func(host string) bool { return host == "127.0.0.1" }),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
		},
		ReadHeaderTimeout: 2 * time.Second,
	}
	if err := writeFile(filepath.Join(*vault, ".ready"), nil, 0o600); err != nil {
		fatal("write readiness marker: %v", err)
	}
	if err := server.ServeTLS(listener, serverCert, serverKey); err != nil && err != http.ErrServerClosed {
		fatal("serve Go approval handler: %v", err)
	}
}

func writeClientIdentity(vault string) (caPath, certPath, keyPath string, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "approval test CA"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	clientSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", err
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject:      pkix.Name{CommonName: "dedicated approval client"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		return "", "", "", err
	}
	caPath = filepath.Join(vault, "approval-client-ca.pem")
	certPath = filepath.Join(vault, "approval-client.pem")
	keyPath = filepath.Join(vault, "approval-client.key")
	if err := writeFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return "", "", "", err
	}
	if err := writeFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o644); err != nil {
		return "", "", "", err
	}
	if err := writeFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		return "", "", "", err
	}
	return caPath, certPath, keyPath, nil
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writeFile(path, data, 0o600)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "approval queue test server: "+format+"\n", args...)
	os.Exit(1)
}
