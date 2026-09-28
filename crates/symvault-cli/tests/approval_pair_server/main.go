// Command approval_pair_server exposes the production Go enroll-code handler
// on a loopback-only ephemeral port for the Rust CLI integration test.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
	"github.com/danieljustus/symaira-vault/internal/pairing"
)

func main() {
	vault := flag.String("vault", "", "temporary vault directory")
	flag.Parse()
	if *vault == "" {
		fatal("vault directory is required")
	}

	certFile, keyFile, err := serverbootstrap.EnsureTLSCert(*vault)
	if err != nil {
		fatal("ensure TLS certificate: %v", err)
	}
	fingerprint, err := serverbootstrap.CertFingerprint(*vault)
	if err != nil {
		fatal("get TLS fingerprint: %v", err)
	}
	secret, err := serverbootstrap.EnsureEnrollSecret(*vault)
	if err != nil {
		fatal("ensure enroll secret: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal("listen: %v", err)
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		fatal("listen returned unexpected address type %T", listener.Addr())
	}
	port := address.Port
	writeJSON(filepath.Join(*vault, ".runtime-port"), map[string]any{"port": port, "bind": "0.0.0.0"})
	writeJSON(filepath.Join(*vault, ".runtime-tls-cert"), map[string]string{"certificate": certFile})
	if err := os.WriteFile(filepath.Join(*vault, ".ready"), nil, 0o600); err != nil {
		fatal("write readiness marker: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(approval.PathDeviceEnrollCode, approval.NewEnrollCodeHTTPHandler(
		pairing.NewTokenStore(), fingerprint,
		func(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() },
		secret,
	))
	server := &http.Server{
		Handler:           mux,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 2 * time.Second,
	}
	if err := server.ServeTLS(listener, certFile, keyFile); err != nil && err != http.ErrServerClosed {
		fatal("serve TLS: %v", err)
	}
}

func writeJSON(path string, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		fatal("encode %s: %v", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fatal("write %s: %v", filepath.Base(path), err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "approval_pair_server: "+format+"\n", args...)
	os.Exit(1)
}
