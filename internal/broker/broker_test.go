package broker

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/audit"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

const testPassphrase = "broker-test-passphrase"

// setupVault creates a temp vault with one entry and writes a template
// override pointing at the given base URL. Returns vaultDir and identity.
func setupVault(t *testing.T, entryPath string, data map[string]any, templateName, templateBody string) (string, *age.X25519Identity) {
	t.Helper()
	dir := t.TempDir()
	identity, err := vault.InitWithPassphrase(dir, []byte(testPassphrase), configpkg.Default())
	if err != nil {
		t.Fatalf("init vault: %v", err)
	}
	entry := &vault.Entry{Data: data}
	if err := vault.WriteEntry(dir, entryPath, entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if templateName != "" {
		templatesDir := filepath.Join(dir, "templates")
		if err := os.MkdirAll(templatesDir, 0o755); err != nil {
			t.Fatalf("mkdir templates: %v", err)
		}
		if err := os.WriteFile(filepath.Join(templatesDir, templateName+".yaml"), []byte(templateBody), 0o644); err != nil {
			t.Fatalf("write template: %v", err)
		}
	}
	return dir, identity
}

// startProxy starts the broker on an ephemeral loopback port and returns the
// proxy URL and a shutdown function.
func startProxy(t *testing.T, cfg Config) (string, func()) {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}
	mu.Lock()
	lastCA = p.ca
	mu.Unlock()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: p.Handler()}
	go func() { _ = srv.Serve(ln) }()
	proxyURL := "http://" + ln.Addr().String()
	return proxyURL, func() { _ = srv.Close() }
}

// newProxyClient returns an HTTP client routed through the given proxy URL.
func newProxyClient(proxyURL string) *http.Client {
	pu, _ := url.Parse(proxyURL)
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
		},
	}
}

func bearerTemplate(baseURL string) string {
	return fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: testapi
allowed_endpoints:
  - /*
allowed_methods:
  - GET
allow_private: true
`, baseURL)
}

func TestCA_LeafForHost(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("CA PEM does not parse")
	}

	cert1, err := ca.LeafForHost("api.example.com")
	if err != nil {
		t.Fatalf("LeafForHost: %v", err)
	}
	cert2, err := ca.LeafForHost("api.example.com")
	if err != nil {
		t.Fatalf("LeafForHost (cached): %v", err)
	}
	if cert1 != cert2 {
		t.Error("LeafForHost returned different certificates for the same host (cache miss)")
	}

	other, err := ca.LeafForHost("other.example.com")
	if err != nil {
		t.Fatalf("LeafForHost (other): %v", err)
	}
	if cert1 == other {
		t.Error("LeafForHost returned the same certificate for different hosts")
	}

	leaf, err := x509.ParseCertificate(cert1.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "api.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}
	if time.Until(leaf.NotAfter) > leafTTL+time.Hour {
		t.Errorf("leaf NotAfter beyond leaf TTL: %v", leaf.NotAfter)
	}
}

func TestCA_LeafForIPHost(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())

	cert, err := ca.LeafForHost("127.0.0.1")
	if err != nil {
		t.Fatalf("LeafForHost: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("leaf IPAddresses = %v, want [127.0.0.1]", leaf.IPAddresses)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "127.0.0.1",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("IP leaf does not verify: %v", err)
	}
}

func TestProxy_PlainHTTPInjection(t *testing.T) {
	const token = "broker-token-1"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer %s", got, token)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "injected-ok")
	}))
	defer upstream.Close()

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", bearerTemplate(upstream.URL))
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/hello")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if string(body) != "injected-ok" {
		t.Errorf("body = %q, want injected-ok", body)
	}
}

func TestProxy_UnmatchedHostForwardedByDefault(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization = %q, want empty for unmatched host", auth)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "forwarded")
	}))
	defer upstream.Close()

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": "token"}, "", "")
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/nobody-home")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "forwarded" {
		t.Fatalf("status = %d body = %q, want 200 forwarded", resp.StatusCode, body)
	}
}

func TestProxy_StrictRejectsUnmatchedHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be reached in strict mode for unmatched host")
	}))
	defer upstream.Close()

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": "token"}, "", "")
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		Strict:       true,
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/blocked")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_StrictAllowsMatchedHost(t *testing.T) {
	const token = "strict-ok-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer %s", got, token)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", bearerTemplate(upstream.URL))
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		Strict:       true,
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/allowed")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestProxy_PathSubstitutionInjection(t *testing.T) {
	const botToken = "123456789:AA-broker-bot"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/bot" + botToken + "/sendMessage"
		if r.URL.Path != wantPath {
			t.Errorf("path = %q, want %q", r.URL.Path, wantPath)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "telegram-ok")
	}))
	defer upstream.Close()

	tmpl := fmt.Sprintf(`base_url: %s/bot__BOT_TOKEN__
auth_type: none
entry_ref: telegram
substitutions:
  - placeholder: __BOT_TOKEN__
    field: credential
    in: [path]
allowed_endpoints:
  - /*
allowed_methods:
  - GET
allow_private: true
`, upstream.URL)
	vaultDir, identity := setupVault(t, "telegram", map[string]any{"credential": botToken}, "telegram", tmpl)
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/bot__BOT_TOKEN__/sendMessage")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "telegram-ok" {
		t.Fatalf("status = %d body = %q, want 200 telegram-ok", resp.StatusCode, body)
	}
}

func TestProxy_ResponseSanitized(t *testing.T) {
	const token = "known-secret-value-77"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"echo": "`+token+`"}`)
	}))
	defer upstream.Close()

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", bearerTemplate(upstream.URL))
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/leak")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), token) {
		t.Fatalf("response body leaks credential: %q", body)
	}
	if !strings.Contains(string(body), "***") {
		t.Errorf("response body = %q, want redacted marker", body)
	}
}

func TestProxy_CONNECTMITM_InjectOverTLS(t *testing.T) {
	const token = "mitm-tls-token"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer %s", got, token)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "mitm-ok")
	}))
	defer upstream.Close()

	upstreamCert := upstream.Certificate()
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstreamCert)

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", bearerTemplate(upstream.URL))
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		UpstreamTLS:  &tls.Config{RootCAs: upstreamPool},
		AllowPrivate: true,
	})
	defer stop()

	body := connectAndGet(t, proxyURL, upstream.URL, "/secure", nil)
	if body != "mitm-ok" {
		t.Fatalf("body = %q, want mitm-ok", body)
	}
}

func TestProxy_CONNECT_PassthroughTunnel(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization = %q, want empty for passthrough tunnel", auth)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "tunnel-ok")
	}))
	defer upstream.Close()

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": "token"}, "", "")
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		Passthrough:  []string{"127.0.0.1"},
		AllowPrivate: true,
	})
	defer stop()

	// The tunneled TLS connection terminates at the upstream's own
	// self-signed certificate — the broker must not intercept it.
	body := connectAndGet(t, proxyURL, upstream.URL, "/raw", &tls.Config{InsecureSkipVerify: true})
	if body != "tunnel-ok" {
		t.Fatalf("body = %q, want tunnel-ok", body)
	}
}

// connectAndGet establishes a CONNECT tunnel through the proxy, performs a
// TLS handshake (verifying against the broker CA unless clientTLS overrides
// the config) and issues a GET, returning the response body.
func connectAndGet(t *testing.T, proxyURL, targetURL, path string, clientTLS *tls.Config) string {
	t.Helper()
	pu, _ := url.Parse(proxyURL)
	target, _ := url.Parse(targetURL)
	hostport := target.Host

	conn, err := net.Dial("tcp", pu.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostport, hostport)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	var tlsCfg *tls.Config
	if clientTLS != nil {
		tlsCfg = clientTLS
	} else {
		// Trust the broker's ephemeral CA.
		pool, err := brokerCAPool(t)
		if err != nil {
			t.Fatalf("broker CA pool: %v", err)
		}
		tlsCfg = &tls.Config{RootCAs: pool, ServerName: target.Hostname()}
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with broker: %v", err)
	}
	defer tlsConn.Close()

	fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, target.Host)
	tbr := bufio.NewReader(tlsConn)
	gresp, err := http.ReadResponse(tbr, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read GET response: %v", err)
	}
	body, _ := io.ReadAll(gresp.Body)
	_ = gresp.Body.Close()
	if gresp.StatusCode != 200 {
		t.Fatalf("GET status = %d body = %q", gresp.StatusCode, body)
	}
	return string(body)
}

// brokerCAPool loads the broker CA PEM written by the CLI helper into a pool.
// For in-process tests the proxy's CA is exposed; this helper re-reads the
// PEM exported via the proxy's CA() accessor path used by tests that start
// the proxy through startProxy. To keep the helper self-contained it parses
// the CA certificate from the proxy instance passed by the caller.
func brokerCAPool(t *testing.T) (*x509.CertPool, error) {
	t.Helper()
	// The pool is rebuilt from the most recently started proxy via a package
	// test hook set by startProxy.
	mu.Lock()
	ca := lastCA
	mu.Unlock()
	if ca == nil {
		return nil, fmt.Errorf("no proxy CA available")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		return nil, fmt.Errorf("invalid CA PEM")
	}
	return pool, nil
}

var (
	mu     sync.Mutex
	lastCA *CA
)

func TestProxy_AuditRecorded(t *testing.T) {
	const token = "audit-token-42"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "audited")
	}))
	defer upstream.Close()

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", bearerTemplate(upstream.URL))

	// Real audit logger writing into the vault dir.
	logger, err := audit.New("broker-test", vaultDir, identity)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()

	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AuditLog:     logger,
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/audit-me")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	_ = resp.Body.Close()
	logger.Flush()

	entries, err := audit.LoadAuditLogFiles("broker-test", vaultDir, 10)
	if err != nil {
		t.Fatalf("load audit entries: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action != "broker_request" {
			continue
		}
		found = true
		if e.OK != true {
			t.Errorf("audit entry ok = %v, want true", e.OK)
		}
		if strings.Contains(e.Path, token) || strings.Contains(e.Field, token) {
			t.Errorf("audit entry leaks credential: %+v", e)
		}
	}
	if !found {
		t.Fatal("no broker_request audit entry found")
	}
}

func TestProxy_FailedRequestAuditedAsFailure(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be reached when substitutions cannot be resolved")
	}))
	defer upstream.Close()

	tmpl := fmt.Sprintf(`base_url: %s
auth_type: none
entry_ref: testapi
substitutions:
  - placeholder: __MISSING_FIELD__
    field: missing_field
    in: [path]
allow_private: true
`, upstream.URL)

	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": "token"}, "testapi", tmpl)

	logger, err := audit.New("broker-test", vaultDir, identity)
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}
	defer logger.Close()

	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AuditLog:     logger,
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/__MISSING_FIELD__")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for unresolvable substitution", resp.StatusCode)
	}
	logger.Flush()

	entries, err := audit.LoadAuditLogFiles("broker-test", vaultDir, 10)
	if err != nil {
		t.Fatalf("load audit entries: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action != "broker_request" {
			continue
		}
		found = true
		if e.OK != false {
			t.Errorf("audit entry ok = %v, want false for failed brokered request", e.OK)
		}
	}
	if !found {
		t.Fatal("no broker_request audit entry found")
	}
}

func TestProxy_EnvExports(t *testing.T) {
	p, err := New(Config{VaultDir: t.TempDir(), Identity: nil})
	if err == nil {
		t.Fatal("New() expected error for missing identity")
	}
	_ = p
}

func TestProxy_AllowedEndpointEnforced(t *testing.T) {
	const token = "endpoint-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer %s", got, token)
		}
		if r.URL.Path != "/allowed/ok" {
			t.Errorf("disallowed path reached upstream: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "allowed")
	}))
	defer upstream.Close()

	tmpl := fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: testapi
allowed_endpoints:
  - /allowed/*
allowed_methods:
  - GET
allow_private: true
`, upstream.URL)
	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", tmpl)
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AllowPrivate: true,
	})
	defer stop()
	client := newProxyClient(proxyURL)

	// Allowed endpoint: forwarded with injected credentials.
	resp, err := client.Get(upstream.URL + "/allowed/ok")
	if err != nil {
		t.Fatalf("GET allowed endpoint: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "allowed" {
		t.Fatalf("allowed endpoint: status = %d body = %q, want 200 allowed", resp.StatusCode, body)
	}

	// Endpoint outside the allowlist: 403, upstream never reached.
	resp, err = client.Get(upstream.URL + "/other")
	if err != nil {
		t.Fatalf("GET disallowed endpoint: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("disallowed endpoint: status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_AllowedMethodEnforced(t *testing.T) {
	const token = "method-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer %s", got, token)
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method reached upstream: %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "get-ok")
	}))
	defer upstream.Close()

	tmpl := fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: testapi
allowed_endpoints:
  - /*
allowed_methods:
  - GET
allow_private: true
`, upstream.URL)
	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", tmpl)
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AllowPrivate: true,
	})
	defer stop()
	client := newProxyClient(proxyURL)

	// Allowed method: forwarded with injected credentials.
	resp, err := client.Get(upstream.URL + "/any")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "get-ok" {
		t.Fatalf("status = %d body = %q, want 200 get-ok", resp.StatusCode, body)
	}

	// Method outside the allowlist: 403, upstream never reached.
	req, _ := http.NewRequest(http.MethodDelete, upstream.URL+"/any", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("DELETE through proxy: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE status = %d, want 403", resp.StatusCode)
	}
}

func TestProxy_EmptyAllowlistsNotEnforced(t *testing.T) {
	const token = "open-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer %s", got, token)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "open-ok")
	}))
	defer upstream.Close()

	// No allowed_endpoints/allowed_methods: every path and method keeps the
	// pre-fix behavior (forwarded with injection).
	tmpl := fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: testapi
allow_private: true
`, upstream.URL)
	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", tmpl)
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AllowPrivate: true,
	})
	defer stop()

	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/anything", nil)
	resp, err := newProxyClient(proxyURL).Do(req)
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "open-ok" {
		t.Fatalf("status = %d body = %q, want 200 open-ok", resp.StatusCode, body)
	}
}

func TestProxy_DefaultHeadersApplied(t *testing.T) {
	const token = "default-header-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer %s", got, token)
		}
		if got := r.Header.Get("X-Template-Default"); got != "template-value" {
			t.Errorf("X-Template-Default = %q, want template-value", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "defaults-ok")
	}))
	defer upstream.Close()

	tmpl := fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: testapi
allowed_endpoints:
  - /*
allowed_methods:
  - GET
default_headers:
  X-Template-Default: template-value
allow_private: true
`, upstream.URL)
	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", tmpl)
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		AllowPrivate: true,
	})
	defer stop()

	resp, err := newProxyClient(proxyURL).Get(upstream.URL + "/with-defaults")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "defaults-ok" {
		t.Fatalf("status = %d body = %q, want 200 defaults-ok", resp.StatusCode, body)
	}
}

func TestProxy_CONNECTMITM_EndpointDenied(t *testing.T) {
	const token = "mitm-deny-token"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream must not be reached for a disallowed endpoint")
	}))
	defer upstream.Close()

	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate())

	tmpl := fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: testapi
allowed_endpoints:
  - /allowed/*
allowed_methods:
  - GET
allow_private: true
`, upstream.URL)
	vaultDir, identity := setupVault(t, "testapi", map[string]any{"credential": token}, "testapi", tmpl)
	proxyURL, stop := startProxy(t, Config{
		VaultDir:     vaultDir,
		Identity:     identity,
		AgentName:    "broker-test",
		UpstreamTLS:  &tls.Config{RootCAs: upstreamPool},
		AllowPrivate: true,
	})
	defer stop()

	// Origin-form request after CONNECT MITM is denied before any credential
	// could be injected upstream.
	status, body := connectAndGetStatus(t, proxyURL, upstream.URL, "/blocked")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d body = %q, want 403", status, body)
	}
}

// connectAndGetStatus establishes a CONNECT tunnel through the proxy,
// performs a TLS handshake against the broker CA and issues a GET, returning
// the response status and body (connectAndGet asserts 200 instead).
func connectAndGetStatus(t *testing.T, proxyURL, targetURL, path string) (int, string) {
	t.Helper()
	pu, _ := url.Parse(proxyURL)
	target, _ := url.Parse(targetURL)
	hostport := target.Host

	conn, err := net.Dial("tcp", pu.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostport, hostport)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}

	pool, err := brokerCAPool(t)
	if err != nil {
		t.Fatalf("broker CA pool: %v", err)
	}
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: target.Hostname()})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake with broker: %v", err)
	}
	defer tlsConn.Close()

	fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, target.Host)
	tbr := bufio.NewReader(tlsConn)
	gresp, err := http.ReadResponse(tbr, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read GET response: %v", err)
	}
	body, _ := io.ReadAll(gresp.Body)
	_ = gresp.Body.Close()
	return gresp.StatusCode, string(body)
}
