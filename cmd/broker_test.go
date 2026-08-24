package cmd

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// Command-layer coverage for the broker CLI wiring (issue #775): the
// standalone `broker` command (newBrokerCmd) and the `run --broker`
// env-construction path (brokerEnvForRun), including the #773
// --broker-strict / --broker-passthrough wiring.

func TestNewBrokerCmd_Flags(t *testing.T) {
	cmd := newBrokerCmd()
	for _, name := range []string{"addr", "strict", "passthrough"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("broker command missing --%s flag", name)
		}
	}
}

func TestNewRunCmd_BrokerFlags(t *testing.T) {
	cmd := newRunCmd()
	for _, name := range []string{"broker", "broker-strict", "broker-passthrough", "passthrough"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("run command missing --%s flag", name)
		}
	}
}

func TestBrokerCmd_RunE(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	cmd := newBrokerCmd()

	// Install the signal seam: capture the channel RunE waits on instead of
	// registering with the OS, and signal readiness once the listener is up
	// and the startup output has been written.
	origNotify := BrokerSignalNotify
	var sigChan chan<- os.Signal
	notifyReady := make(chan struct{})
	BrokerSignalNotify = func(c chan<- os.Signal, _ ...os.Signal) {
		sigChan = c
		close(notifyReady)
	}
	defer func() { BrokerSignalNotify = origNotify }()

	// Capture stdout while the broker runs and blocks.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	var buf bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		_, _ = buf.ReadFrom(r)
		close(readDone)
	}()
	restoreStdout := func() {
		_ = w.Close()
		os.Stdout = oldStdout
		<-readDone
	}
	defer restoreStdout()

	execDone := make(chan error, 1)
	go func() { execDone <- cmd.Execute() }()

	select {
	case <-notifyReady:
	case execErr := <-execDone:
		t.Fatalf("broker exited before the signal-wait stage: %v", execErr)
	case <-time.After(15 * time.Second):
		t.Fatal("broker never reached the signal-wait stage")
	}

	// The CA certificate was written with 0600 permissions and parses as PEM.
	caPath := filepath.Join(vaultDir, "broker-ca.pem")
	caInfo, statErr := os.Stat(caPath)
	if statErr != nil {
		t.Fatalf("stat broker-ca.pem: %v", statErr)
	}
	if perm := caInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("broker-ca.pem mode = %o, want 0600", perm)
	}
	caData, readErr := os.ReadFile(caPath)
	if readErr != nil {
		t.Fatalf("read broker-ca.pem: %v", readErr)
	}
	block, _ := pem.Decode(caData)
	if block == nil {
		t.Fatal("broker-ca.pem is not valid PEM")
	}
	if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr != nil {
		t.Errorf("broker-ca.pem does not parse as an X.509 certificate: %v", parseErr)
	}

	// Shut the broker down through the signal seam and expect a clean exit.
	sigChan <- os.Interrupt
	select {
	case execErr := <-execDone:
		if execErr != nil {
			t.Fatalf("Execute() error = %v", execErr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("broker did not shut down after signal")
	}

	restoreStdout()
	out := buf.String()
	for _, want := range []string{
		"egress broker listening on http://127.0.0.1:",
		"CA certificate written to " + caPath,
		"HTTPS_PROXY=http://127.0.0.1:",
		"HTTP_PROXY=http://127.0.0.1:",
		"SSL_CERT_FILE=" + caPath,
		"NODE_EXTRA_CA_CERTS=" + caPath,
		"REQUESTS_CA_BUNDLE=" + caPath,
		"NO_PROXY=127.0.0.1,localhost",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q; got:\n%s", want, out)
		}
	}
}

func TestBrokerEnvForRun(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	env, cleanup, err := brokerEnvForRun(v, false, nil)
	if err != nil {
		t.Fatalf("brokerEnvForRun() error = %v", err)
	}
	defer cleanup()

	caPath := filepath.Join(vaultDir, "broker-ca.pem")

	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "NO_PROXY"} {
		if env[key] == "" {
			t.Errorf("env[%q] is empty", key)
		}
	}
	if env["HTTPS_PROXY"] != env["HTTP_PROXY"] {
		t.Errorf("HTTPS_PROXY = %q, HTTP_PROXY = %q; want equal", env["HTTPS_PROXY"], env["HTTP_PROXY"])
	}
	if !strings.HasPrefix(env["HTTPS_PROXY"], "http://127.0.0.1:") {
		t.Errorf("HTTPS_PROXY = %q, want loopback proxy URL", env["HTTPS_PROXY"])
	}
	if env["SSL_CERT_FILE"] != caPath {
		t.Errorf("SSL_CERT_FILE = %q, want %q", env["SSL_CERT_FILE"], caPath)
	}
	if env["NO_PROXY"] != "127.0.0.1,localhost" {
		t.Errorf("NO_PROXY = %q, want 127.0.0.1,localhost", env["NO_PROXY"])
	}

	// The CA file exists, is 0600, and parses as a PEM certificate.
	info, statErr := os.Stat(caPath)
	if statErr != nil {
		t.Fatalf("stat CA: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("broker-ca.pem mode = %o, want 0600", perm)
	}
	caData, readErr := os.ReadFile(caPath)
	if readErr != nil {
		t.Fatalf("read CA: %v", readErr)
	}
	block, _ := pem.Decode(caData)
	if block == nil {
		t.Fatal("broker-ca.pem is not valid PEM")
	}
	if _, parseErr := x509.ParseCertificate(block.Bytes); parseErr != nil {
		t.Errorf("broker-ca.pem does not parse as an X.509 certificate: %v", parseErr)
	}

	// The cleanup function stops the listener.
	cleanup()
	// A dial that succeeds right after cleanup can be a backlog connection
	// whose TCP handshake completed before Close; require the port to stay
	// closed across a short grace period instead of failing on the first
	// stray accept.
	proxyURL, parseErr := url.Parse(env["HTTPS_PROXY"])
	if parseErr != nil {
		t.Fatalf("parse proxy URL: %v", parseErr)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", proxyURL.Host, 500*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			t.Error("proxy listener still accepting connections after cleanup()")
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestBrokerEnvForRun_StrictMode verifies the strict parameter (#773 wiring)
// reaches the broker: unmatched hosts get 403 instead of being forwarded.
func TestBrokerEnvForRun_StrictMode(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	proxyStatus := func(strict bool) int {
		t.Helper()
		env, cleanup, envErr := brokerEnvForRun(v, strict, nil)
		if envErr != nil {
			t.Fatalf("brokerEnvForRun(strict=%v) error = %v", strict, envErr)
		}
		defer cleanup()
		proxyURL, parseErr := url.Parse(env["HTTPS_PROXY"])
		if parseErr != nil {
			t.Fatalf("parse proxy URL: %v", parseErr)
		}
		client := &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		}
		resp, reqErr := client.Get("http://127.0.0.1:9/probe")
		if reqErr != nil {
			t.Fatalf("GET via proxy: %v", reqErr)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Strict: the unmatched loopback host is rejected before any upstream
	// dial, so the response is a deterministic 403.
	if got := proxyStatus(true); got != http.StatusForbidden {
		t.Errorf("strict mode status = %d, want 403", got)
	}
	// Non-strict: the unmatched host is forwarded, and the SSRF guard blocks
	// the private upstream, yielding a deterministic 502.
	if got := proxyStatus(false); got != http.StatusBadGateway {
		t.Errorf("non-strict mode status = %d, want 502", got)
	}
}

// TestBrokerEnvForRun_Passthrough verifies the passthrough parameter (#773
// wiring) routes CONNECT requests for listed hosts through the tunnel path
// (no TLS interception) instead of the intercept path.
func TestBrokerEnvForRun_Passthrough(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	env, cleanup, err := brokerEnvForRun(v, false, []string{"unmatched.invalid"})
	if err != nil {
		t.Fatalf("brokerEnvForRun() error = %v", err)
	}
	defer cleanup()

	proxyURL, parseErr := url.Parse(env["HTTPS_PROXY"])
	if parseErr != nil {
		t.Fatalf("parse proxy URL: %v", parseErr)
	}
	conn, dialErr := net.DialTimeout("tcp", proxyURL.Host, 5*time.Second)
	if dialErr != nil {
		t.Fatalf("dial proxy: %v", dialErr)
	}
	defer conn.Close()
	if _, writeErr := fmt.Fprintf(conn, "CONNECT unmatched.invalid:443 HTTP/1.1\r\nHost: unmatched.invalid:443\r\n\r\n"); writeErr != nil {
		t.Fatalf("write CONNECT: %v", writeErr)
	}
	resp, readErr := http.ReadResponse(bufio.NewReader(conn), nil)
	if readErr != nil {
		t.Fatalf("read CONNECT response: %v", readErr)
	}
	defer resp.Body.Close()
	// The tunnel dials the upstream directly and reports the failure as a
	// 502 ("cannot reach upstream"); a passthrough-listed host is never
	// offered a MITM handshake.
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("CONNECT status = %d, want 502 (passthrough tunnel cannot reach upstream)", resp.StatusCode)
	}
}

// TestCmdRun_BrokerWiring drives `run --broker` end-to-end and verifies the
// #773 flags reach the child environment through brokerEnvForRun.
func TestCmdRun_BrokerWiring(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run",
		"--broker", "--broker-strict", "--broker-passthrough", "corp.internal",
		"--", "sh", "-c", "echo PROXY=$HTTPS_PROXY; echo CERT=$SSL_CERT_FILE; echo NO=$NO_PROXY")

	caPath := filepath.Join(vaultDir, "broker-ca.pem")
	// The broker proxy URL and NO_PROXY contain an IPv4 literal, which the
	// run output redaction layer masks as credential-shaped output, so only
	// assert on the surrounding text.
	if !strings.Contains(out, "PROXY=http://") {
		t.Errorf("stdout missing proxy URL, got: %q", out)
	}
	if !strings.Contains(out, "CERT="+caPath) {
		t.Errorf("stdout missing CA path %q, got: %q", caPath, out)
	}
	if !strings.Contains(out, "NO=") || !strings.Contains(out, "localhost") {
		t.Errorf("stdout missing NO_PROXY, got: %q", out)
	}
	if _, err := os.Stat(caPath); err != nil {
		t.Errorf("broker-ca.pem not written: %v", err)
	}
}
