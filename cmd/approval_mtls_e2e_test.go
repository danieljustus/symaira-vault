package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
)

// TestApprovalCLI_MTLSRealQueue exercises the complete local approval path:
// TCP/TLS, the production local handler, approvalAPIRequest, and Cobra JSON
// commands all share one real queue. The fixture is an initialized temp vault;
// no production vault state or subprocess is involved.
func TestApprovalCLI_MTLSRealQueue(t *testing.T) {
	generatedDir := t.TempDir()
	generatedCert, generatedKey, err := serverbootstrap.EnsureTLSCert(generatedDir)
	if err != nil {
		t.Fatalf("EnsureTLSCert generated server certificate: %v", err)
	}
	if generatedCert == "" || generatedKey == "" {
		t.Fatal("EnsureTLSCert returned empty generated certificate paths")
	}

	caPEM, caPriv, caObj := writeE2ECA(t)
	serverCert, serverKey := writeE2ECert(t, caObj, caPriv, "custom-server", true)
	clientCert, clientKey := writeE2ECert(t, caObj, caPriv, "dedicated-approval-client", false)
	_, otherCAPriv, otherCAObj := writeE2ECA(t)
	otherClientCert, otherClientKey := writeE2ECert(t, otherCAObj, otherCAPriv, "wrong-client", false)
	caCert := caPEM

	vaultDir, _ := initVault(t)
	defer setupVaultFlag(t, vaultDir)()
	if err := cli.SaveRuntimePort(vaultDir, "127.0.0.1", 1); err != nil {
		t.Fatalf("seed runtime server: %v", err)
	}
	queue := approval.NewQueue()
	secret, err := serverbootstrap.EnsureEnrollSecret(vaultDir)
	if err != nil {
		t.Fatalf("EnsureEnrollSecret: %v", err)
	}

	fixtureDir := t.TempDir()
	caFile := e2eWrite(t, fixtureDir, "client-ca.pem", caCert, 0o644)
	serverCertFile := e2eWrite(t, fixtureDir, "custom-server.pem", serverCert, 0o644)
	serverKeyFile := e2eWrite(t, fixtureDir, "custom-server.key", serverKey, 0o600)
	clientCertFile := e2eWrite(t, fixtureDir, "approval-client.pem", clientCert, 0o644)
	clientKeyFile := e2eWrite(t, fixtureDir, "approval-client.key", clientKey, 0o600)
	if err := cli.SaveRuntimeTLSConfig(vaultDir, serverCertFile, caFile, clientCertFile, clientKeyFile, true); err != nil {
		t.Fatalf("SaveRuntimeTLSConfig: %v", err)
	}

	listener, port := startApprovalTLSServer(t, queue, secret, serverCertFile, serverKeyFile, caFile)
	if err := cli.SaveRuntimePort(vaultDir, "127.0.0.1", port); err != nil {
		t.Fatalf("publish actual runtime port: %v", err)
	}
	stop := func() { listener.Close() }
	defer stop()

	requestID, err := queue.Enqueue(approval.Request{AgentName: "agent-e2e", Path: "notes/todo.md", Write: true, Reason: "integration approval"})
	if err != nil {
		t.Fatalf("enqueue pending request: %v", err)
	}

	t.Run("Cobra list reads real pending queue as JSON", func(t *testing.T) {
		oldFormat := cli.OutputFormat
		cli.OutputFormat = "json"
		t.Cleanup(func() { cli.OutputFormat = oldFormat })
		var runErr error
		cmd := newApprovalListCmd()
		output := captureStdout(func() { runErr = cmd.RunE(cmd, nil) })
		if runErr != nil {
			t.Fatalf("approval list: %v", runErr)
		}
		var got approvalListOutput
		if err := json.Unmarshal([]byte(output), &got); err != nil {
			t.Fatalf("decode list JSON %q: %v", output, err)
		}
		if len(got.Requests) != 1 || got.Requests[0].ID != requestID || got.Requests[0].Status != approval.StatusPending {
			t.Fatalf("list returned %+v, want pending request %s", got.Requests, requestID)
		}
	})

	t.Run("invalid identity and server-key clone fail before transport", func(t *testing.T) {
		if err := validateApprovalClientIdentity(serverCert, e2eWrite(t, fixtureDir, "clone.pem", serverCert, 0o644), caFile); err == nil {
			t.Fatal("cloned server certificate identity was accepted")
		}
		if err := validateApprovalClientIdentity(serverCert, e2eWrite(t, fixtureDir, "invalid.pem", []byte("not a certificate"), 0o644), caFile); err == nil {
			t.Fatal("invalid client identity was accepted")
		}
		if err := cli.SaveRuntimeTLSConfig(vaultDir, serverCertFile, caFile, "", "", true); err != nil {
			t.Fatal(err)
		}
		var out approvalListOutput
		if err := approvalAPIRequest(http.MethodGet, approval.PathLocalApprovals, &out); err == nil || !strings.Contains(err.Error(), "dedicated local approval client certificate") {
			t.Fatalf("missing identity error = %v", err)
		}
		if _, err := queue.Get(requestID); err != nil {
			t.Fatalf("pre-transport failure changed queue: %v", err)
		}
		if err := cli.SaveRuntimeTLSConfig(vaultDir, serverCertFile, caFile, clientCertFile, clientKeyFile, true); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unauthenticated and wrong CA clients are rejected by TLS", func(t *testing.T) {
		pool := certPool(t, caCert)
		for name, certPEM := range map[string][]byte{
			"wrong identity": otherClientCert,
			"no identity":    nil,
		} {
			t.Run(name, func(t *testing.T) {
				cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
				if certPEM != nil {
					pair, pairErr := tls.X509KeyPair(certPEM, otherClientKey)
					if pairErr != nil {
						t.Fatal(pairErr)
					}
					cfg.Certificates = []tls.Certificate{pair}
				}
				client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: time.Second}
				resp, requestErr := client.Get("https://127.0.0.1:" + portString(port) + "/api/v1/local/approvals")
				if requestErr == nil {
					resp.Body.Close()
					t.Fatal("unauthorized TLS client unexpectedly connected")
				}
			})
		}
	})

	t.Run("Cobra decide approves and verifies queue outcome", func(t *testing.T) {
		oldFormat := cli.OutputFormat
		cli.OutputFormat = "json"
		t.Cleanup(func() { cli.OutputFormat = oldFormat })
		cmd := newApprovalDecideCmd()
		if err := cmd.Flags().Set("approve", "true"); err != nil {
			t.Fatal(err)
		}
		var runErr error
		output := captureStdout(func() { runErr = cmd.RunE(cmd, []string{requestID}) })
		if runErr != nil {
			t.Fatalf("approval decide: %v", runErr)
		}
		var got approvalOutcomeOutput
		if err := json.Unmarshal([]byte(output), &got); err != nil {
			t.Fatalf("decode decide JSON: %v", err)
		}
		if got.Outcome.ID != requestID || got.Outcome.Status != approval.StatusApproved {
			t.Fatalf("outcome = %+v", got.Outcome)
		}
		entry, err := queue.Get(requestID)
		if err != nil || entry.Status != approval.StatusApproved || entry.DecidedBy != "local-cli" {
			t.Fatalf("queue entry = %+v, err=%v", entry, err)
		}
	})

	denyID, err := queue.Enqueue(approval.Request{AgentName: "agent-e2e", Path: "notes/secret.md", Write: true, Reason: "deny integration approval"})
	if err != nil {
		t.Fatalf("enqueue deny request: %v", err)
	}
	t.Run("Cobra decide denies and verifies queue outcome", func(t *testing.T) {
		oldFormat := cli.OutputFormat
		cli.OutputFormat = "json"
		t.Cleanup(func() { cli.OutputFormat = oldFormat })
		cmd := newApprovalDecideCmd()
		if err := cmd.Flags().Set("deny", "true"); err != nil {
			t.Fatal(err)
		}
		var runErr error
		output := captureStdout(func() { runErr = cmd.RunE(cmd, []string{denyID}) })
		if runErr != nil {
			t.Fatalf("approval deny: %v", runErr)
		}
		var got approvalOutcomeOutput
		if err := json.Unmarshal([]byte(output), &got); err != nil {
			t.Fatalf("decode deny JSON: %v", err)
		}
		if got.Outcome.ID != denyID || got.Outcome.Status != approval.StatusDenied {
			t.Fatalf("outcome = %+v", got.Outcome)
		}
		entry, err := queue.Get(denyID)
		if err != nil || entry.Status != approval.StatusDenied || entry.DecidedBy != "local-cli" {
			t.Fatalf("queue entry = %+v, err=%v", entry, err)
		}
	})

	t.Run("generated server TLS serves approval API with dedicated client identity", func(t *testing.T) {
		stop()
		if err := cli.SaveRuntimeTLSConfig(vaultDir, generatedCert, caFile, clientCertFile, clientKeyFile, true); err != nil {
			t.Fatal(err)
		}
		generatedListener, generatedPort := startApprovalTLSServerAt(t, queue, secret, generatedCert, generatedKey, caFile, port)
		defer generatedListener.Close()
		if generatedPort != port {
			t.Fatalf("generated server changed port from %d to %d", port, generatedPort)
		}
		if err := cli.SaveRuntimePort(vaultDir, "127.0.0.1", generatedPort); err != nil {
			t.Fatalf("publish generated runtime port: %v", err)
		}
		var got approvalListOutput
		if err := approvalAPIRequest(http.MethodGet, approval.PathLocalApprovals, &got); err != nil {
			t.Fatalf("generated runtime snapshot request: %v", err)
		}
	})

	t.Run("runtime snapshot and CA rotation reject old identity after restart", func(t *testing.T) {
		stop()
		newCACert, newCAPriv, newCAObj := writeE2ECA(t)
		newServerCert, newServerKey := writeE2ECert(t, newCAObj, newCAPriv, "rotated-server", true)
		newClientCert, newClientKey := writeE2ECert(t, newCAObj, newCAPriv, "rotated-client", false)
		newCAFile := e2eWrite(t, fixtureDir, "rotated-ca.pem", newCACert, 0o644)
		newServerFile := e2eWrite(t, fixtureDir, "rotated-server.pem", newServerCert, 0o644)
		newServerKeyFile := e2eWrite(t, fixtureDir, "rotated-server.key", newServerKey, 0o600)
		newClientFile := e2eWrite(t, fixtureDir, "rotated-client.pem", newClientCert, 0o644)
		newClientKeyFile := e2eWrite(t, fixtureDir, "rotated-client.key", newClientKey, 0o600)
		if err := cli.SaveRuntimeTLSConfig(vaultDir, newServerFile, newCAFile, newClientFile, newClientKeyFile, true); err != nil {
			t.Fatal(err)
		}
		listener, newPort := startApprovalTLSServerAt(t, queue, secret, newServerFile, newServerKeyFile, newCAFile, port)
		defer listener.Close()
		if newPort != port {
			t.Fatalf("restart changed port from %d to %d", port, newPort)
		}
		newPool := certPool(t, newCACert)
		oldPair, pairErr := tls.X509KeyPair(clientCert, clientKey)
		if pairErr != nil {
			t.Fatalf("load old client identity: %v", pairErr)
		}
		oldClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: newPool, Certificates: []tls.Certificate{oldPair}}}, Timeout: time.Second}
		if resp, oldErr := oldClient.Get("https://127.0.0.1:" + portString(port) + "/api/v1/local/approvals"); oldErr == nil {
			resp.Body.Close()
			t.Fatal("old CA/client was accepted after rotation")
		}
		if err := cli.SaveRuntimeTLSConfig(vaultDir, newServerFile, newCAFile, newClientFile, newClientKeyFile, true); err != nil {
			t.Fatal(err)
		}
		var got approvalListOutput
		if err := approvalAPIRequest(http.MethodGet, approval.PathLocalApprovals, &got); err != nil {
			t.Fatalf("rotated runtime snapshot request: %v", err)
		}
	})
}

func certPool(t *testing.T, pemData []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		t.Fatal("append CA")
	}
	return pool
}

func portString(port int) string { return strconv.Itoa(port) }

func startApprovalTLSServer(t *testing.T, queue *approval.Queue, secret []byte, certFile, keyFile, caFile string) (net.Listener, int) {
	return startApprovalTLSServerAt(t, queue, secret, certFile, keyFile, caFile, 0)
}

func startApprovalTLSServerAt(t *testing.T, queue *approval.Queue, secret []byte, certFile, keyFile, caFile string, port int) (net.Listener, int) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: certPool(t, caPEM), ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})
	server := &http.Server{Handler: approval.NewLocalHTTPHandler(queue, secret, func(host string) bool { return host == "127.0.0.1" }), ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(tlsListener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return tlsListener, listener.Addr().(*net.TCPAddr).Port
}

func e2eWrite(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeE2ECA(t *testing.T) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "e2e CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, tmpl
}

func writeE2ECert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if server {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: usages, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
