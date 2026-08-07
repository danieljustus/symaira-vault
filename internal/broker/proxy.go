package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/mcp/apitemplates"
	"github.com/danieljustus/symaira-vault/internal/mcp/masking"
	"github.com/danieljustus/symaira-vault/internal/ssrf"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	// maxBrokerResponseBytes caps the response body read for sanitization.
	maxBrokerResponseBytes = 16 << 20 // 16 MiB
	// brokerTimeout bounds each brokered upstream request.
	brokerTimeout = 60 * time.Second
	// handshakeTimeout bounds the TLS handshake with the client.
	handshakeTimeout = 30 * time.Second
)

// Config configures a broker Proxy.
type Config struct {
	// VaultDir is the vault directory: user template overrides live in
	// <vaultDir>/templates/ and credential entries are read from it.
	VaultDir string
	// Identity is the vault identity used to decrypt entries.
	Identity *age.X25519Identity
	// AgentName is recorded in audit entries.
	AgentName string
	// AuditLog receives one record per brokered request. May be nil.
	AuditLog *audit.Logger
	// Strict rejects requests to hosts without a matching template with 403
	// instead of forwarding them uninjected.
	Strict bool
	// Passthrough lists hostnames (exact or domain suffix) that are tunneled
	// without interception — the escape hatch for clients that pin
	// certificates.
	Passthrough []string
	// UpstreamTLS overrides the TLS client config used for upstream
	// connections (test hook; nil uses the system roots).
	UpstreamTLS *tls.Config
	// AllowPrivate permits private/local destinations (test-only; the CLI
	// never sets it).
	AllowPrivate bool
}

// Proxy is a loopback MITM forward proxy that attaches vault credentials to
// outbound requests server-side.
type Proxy struct {
	cfg       Config
	ca        *CA
	byHost    map[string]*apitemplates.APITemplate
	templates []*apitemplates.APITemplate
	client    *http.Client
	upstream  *net.Dialer
	passthru  []string
}

// New builds a Proxy, loading the template catalog (built-ins plus vault-local
// overrides) and minting the ephemeral CA.
func New(cfg Config) (*Proxy, error) {
	if cfg.VaultDir == "" || cfg.Identity == nil {
		return nil, fmt.Errorf("broker requires a vault dir and identity")
	}
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	templates, err := loadTemplates(cfg.VaultDir)
	if err != nil {
		return nil, err
	}
	byHost := make(map[string]*apitemplates.APITemplate, len(templates))
	for _, tmpl := range templates {
		host := templateHost(tmpl.BaseURL)
		if host != "" {
			byHost[host] = tmpl
		}
	}
	return &Proxy{
		cfg:       cfg,
		ca:        ca,
		byHost:    byHost,
		templates: templates,
		client:    ssrf.NewHTTPClientWithTLSConfig(brokerTimeout, cfg.AllowPrivate, cfg.UpstreamTLS),
		upstream:  &net.Dialer{},
		passthru:  cfg.Passthrough,
	}, nil
}

// CA returns the broker's ephemeral certificate authority.
func (p *Proxy) CA() *CA { return p.ca }

// Templates returns the resolved template catalog (for CLI introspection).
func (p *Proxy) Templates() []*apitemplates.APITemplate { return p.templates }

// Handler returns the proxy's HTTP handler (CONNECT + forward proxy).
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.handle)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.serveInner(w, r)
}

// handleConnect either tunnels the connection untouched (passthrough hosts)
// or terminates TLS with a leaf certificate and serves the inner request
// through the credential-injecting handler.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostport := r.Host
	if hostport == "" {
		http.Error(w, "missing CONNECT target", http.StatusBadRequest)
		return
	}
	host := canonicalHost(hostport)

	if p.isPassthrough(host) {
		p.tunnel(w, r, hostport)
		return
	}

	cert, err := p.ca.LeafForHost(host)
	if err != nil {
		p.audit(host, "broker_denied", false, "certificate")
		http.Error(w, "cannot intercept TLS", http.StatusInternalServerError)
		return
	}

	// Validate that the upstream is reachable through the SSRF-guarded dialer
	// before announcing interception.
	if _, dialErr := p.dialUpstream(r.Context(), hostport); dialErr != nil {
		p.audit(host, "broker_denied", false, "upstream")
		http.Error(w, "cannot reach upstream", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, _, hijackErr := hj.Hijack()
	if hijackErr != nil {
		return
	}
	if _, writeErr := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); writeErr != nil {
		_ = conn.Close()
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	inner := &http.Server{
		Handler:           http.HandlerFunc(p.serveInner),
		ErrorLog:          log.New(os.Stderr, "broker-inner: ", log.LstdFlags),
		ReadHeaderTimeout: handshakeTimeout,
		ReadTimeout:       brokerTimeout,
		WriteTimeout:      brokerTimeout,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		_ = inner.Serve(&singleConnListener{conn: tlsConn})
	}()
}

// singleConnListener adapts a single connection to net.Listener for
// http.Server.Serve, which then handles keep-alive requests over it.
// Close only stops Accept — it must not close the (still active) conn.
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, io.EOF
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// tunnel relays the client connection to the upstream untouched (no TLS
// interception) for passthrough hosts.
func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, hostport string) {
	upstream, err := p.dialUpstream(r.Context(), hostport)
	if err != nil {
		p.audit(canonicalHost(hostport), "broker_passthrough_failed", false, "upstream")
		http.Error(w, "cannot reach upstream", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	conn, _, hijackErr := hj.Hijack()
	if hijackErr != nil {
		_ = upstream.Close()
		return
	}
	if _, writeErr := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); writeErr != nil {
		_ = conn.Close()
		_ = upstream.Close()
		return
	}
	go func() {
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
}

// serveInner handles a forward-proxy request (absolute-form, plain HTTP) or a
// decrypted inner request (origin-form, after CONNECT MITM). Matched hosts get
// credential injection; unmatched hosts are forwarded (default) or rejected
// with 403 (strict mode).
func (p *Proxy) serveInner(w http.ResponseWriter, r *http.Request) {
	target, err := p.targetURL(r)
	if err != nil {
		http.Error(w, "invalid request target", http.StatusBadRequest)
		return
	}
	host := canonicalHost(r.Host)
	tmpl := p.byHost[host]

	if tmpl == nil {
		if p.cfg.Strict {
			p.audit(host, "broker_denied", false, "unmatched")
			http.Error(w, "no template for host; strict mode rejects unmatched hosts", http.StatusForbidden)
			return
		}
		p.forward(w, r, target, nil, nil)
		return
	}

	// Enforce the template's allowlists before touching the vault, mirroring
	// the MCP execute_api_request path: a request outside allowed_endpoints
	// or allowed_methods must never receive injected credentials. Empty
	// allowlists declare no constraint and are not enforced.
	if len(tmpl.AllowedEndpoints) > 0 && !endpointAllowed(r.URL.Path, tmpl.AllowedEndpoints) {
		p.audit(host, "broker_denied", false, "endpoint")
		http.Error(w, "endpoint not allowed by template", http.StatusForbidden)
		return
	}
	if len(tmpl.AllowedMethods) > 0 && !methodAllowed(r.Method, tmpl.AllowedMethods) {
		p.audit(host, "broker_denied", false, "method")
		http.Error(w, "method not allowed by template", http.StatusForbidden)
		return
	}

	entryPath, parseErr := apitemplates.EntryRefPath(tmpl.EntryRef)
	if parseErr != nil {
		p.audit(host, "broker_denied", false, "entry_ref")
		http.Error(w, "template entry_ref is invalid", http.StatusInternalServerError)
		return
	}
	entry, readErr := vaultpkg.ReadEntry(p.cfg.VaultDir, entryPath, p.cfg.Identity)
	if readErr != nil {
		p.audit(host, "broker_denied", false, "vault")
		http.Error(w, "cannot load credentials for host", http.StatusInternalServerError)
		return
	}
	p.forward(w, r, target, tmpl, entry.Data)
}

// forward sends the request upstream, applying auth injection and
// substitutions when a template matched, and sanitizes the response body.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, target string, tmpl *apitemplates.APITemplate, entryData map[string]any) {
	host := canonicalHost(r.Host)
	// Default to a failure status so error paths below (substitution
	// resolution, body read, request build, upstream failure) are audited
	// as failures; the real status overwrites this on success.
	status := http.StatusInternalServerError
	audited := false
	auditOnce := func(action string, ok bool, reason string) {
		if audited {
			return
		}
		audited = true
		p.audit(host, action, ok, reason)
	}
	defer func() {
		auditOnce("broker_request", status < 400, "forward")
	}()

	var body io.Reader
	var redactVals []string
	var values map[string]string
	if tmpl != nil && len(tmpl.Substitutions) > 0 {
		var subErr error
		values, redactVals, subErr = apitemplates.ResolveSubstitutionValues(tmpl, entryData)
		if subErr != nil {
			http.Error(w, "cannot resolve substitutions for host", http.StatusInternalServerError)
			return
		}
		target = apitemplates.ApplyURLSubstitutions(target, tmpl.Substitutions, values)
		raw, readErr := io.ReadAll(io.LimitReader(r.Body, maxBrokerResponseBytes+1))
		if readErr != nil {
			http.Error(w, "cannot read request body", http.StatusBadRequest)
			return
		}
		body = strings.NewReader(apitemplates.ApplyBodySubstitutions(string(raw), tmpl.Substitutions, values))
	} else if r.Body != nil {
		body = r.Body
	}

	outReq, buildErr := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if buildErr != nil {
		http.Error(w, "cannot build upstream request", http.StatusInternalServerError)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	if tmpl != nil {
		// Template default headers are applied before auth injection (and
		// after the client's own headers, so the template's defaults win),
		// mirroring the MCP execute_api_request header order.
		for k, v := range tmpl.DefaultHeaders {
			outReq.Header.Set(k, v)
		}
		if err := apitemplates.InjectAuth(outReq, tmpl, entryData); err != nil {
			auditOnce("broker_denied", false, "auth")
			http.Error(w, "cannot resolve auth for host", http.StatusInternalServerError)
			return
		}
		if len(tmpl.Substitutions) > 0 {
			apitemplates.ApplyHeaderSubstitutions(outReq, tmpl.Substitutions, values)
		}
	}

	resp, doErr := p.client.Do(outReq)
	if doErr != nil {
		http.Error(w, "upstream request failed: "+apitemplates.RedactValues(doErr.Error(), redactVals), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	status = resp.StatusCode

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBrokerResponseBytes+1))
	if readErr != nil {
		http.Error(w, "cannot read upstream response", http.StatusBadGateway)
		return
	}
	bodyText := string(raw)

	// Sanitize: pattern-based detection plus known credential values.
	sanitizer := masking.NewSanitizer()
	bodyText = sanitizer.Sanitize(bodyText, masking.MaskOptions{CustomMask: "***"})
	if entryData != nil {
		bodyText = redactKnownValues(bodyText, entryData)
	}

	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, bodyText)
}

// targetURL reconstructs the absolute upstream URL for origin-form (after
// CONNECT) and absolute-form (plain forward proxy) requests.
func (p *Proxy) targetURL(r *http.Request) (string, error) {
	if r.URL.IsAbs() {
		return r.URL.String(), nil
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if r.Host == "" {
		return "", fmt.Errorf("missing Host header")
	}
	u := *r.URL
	u.Scheme = scheme
	u.Host = r.Host
	return u.String(), nil
}

func (p *Proxy) dialUpstream(ctx context.Context, hostport string) (net.Conn, error) {
	return ssrf.DialAddress(ctx, p.upstream, "tcp", hostport, p.cfg.AllowPrivate, net.DefaultResolver.LookupIPAddr)
}

func (p *Proxy) isPassthrough(host string) bool {
	for _, entry := range p.passthru {
		entry = canonicalHost(entry)
		if entry == "" {
			continue
		}
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

func (p *Proxy) audit(host, action string, ok bool, reason string) {
	if p.cfg.AuditLog == nil {
		return
	}
	entry := audit.LogEntry{
		Agent:  p.cfg.AgentName,
		Action: action,
		Path:   host, // host only — paths may carry substituted credentials
		Reason: reason,
		OK:     ok,
	}
	if tmpl := p.byHost[host]; tmpl != nil && action == "broker_request" {
		entry.Field = tmpl.Name
	}
	_ = p.cfg.AuditLog.LogEntry(entry)
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		switch strings.ToLower(k) {
		case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "te":
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func redactKnownValues(text string, entryData map[string]any) string {
	for _, v := range entryData {
		if vStr, ok := v.(string); ok && vStr != "" {
			text = strings.ReplaceAll(text, vStr, "***")
		}
	}
	return text
}

// loadTemplates resolves the full catalog: embedded built-ins (with vault-local
// overrides) plus vault-local templates that are not built-in names.
func loadTemplates(vaultDir string) ([]*apitemplates.APITemplate, error) {
	var result []*apitemplates.APITemplate
	seen := make(map[string]bool)

	builtins, err := apitemplates.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("load built-in templates: %w", err)
	}
	for _, b := range builtins {
		tmpl, loadErr := apitemplates.Load(b.Name, vaultDir)
		if loadErr != nil {
			return nil, fmt.Errorf("load template %q: %w", b.Name, loadErr)
		}
		result = append(result, tmpl)
		seen[b.Name] = true
	}

	if vaultDir != "" {
		entries, readErr := os.ReadDir(filepath.Join(vaultDir, "templates"))
		if readErr == nil {
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
					continue
				}
				name := strings.TrimSuffix(entry.Name(), ".yaml")
				if seen[name] {
					continue
				}
				tmpl, loadErr := apitemplates.Load(name, vaultDir)
				if loadErr != nil {
					continue
				}
				result = append(result, tmpl)
				seen[name] = true
			}
		}
	}
	return result, nil
}

// templateHost extracts the canonical host from a template base URL.
func templateHost(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return canonicalHost(u.Host)
}

// endpointAllowed reports whether path matches any of the template's
// allowed-endpoint globs. Semantics mirror the MCP execute_api_request path
// (internal/mcp/server/tools_execute_api_request.go): standard path.Match
// plus multi-segment matching for patterns ending in /*.
func endpointAllowed(endpoint string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if endpointGlobMatch(pattern, endpoint) {
			return true
		}
	}
	return false
}

// endpointGlobMatch reports whether the endpoint matches the glob pattern.
// It uses path.Match for standard shell pattern matching, and adds
// multi-segment support for patterns ending with /* — these match any
// sub-path beneath the prefix.
func endpointGlobMatch(pattern, endpoint string) bool {
	// Try standard path.Match first (handles single-segment *).
	if matched, err := path.Match(pattern, endpoint); err == nil && matched {
		return true
	}
	// Multi-segment: patterns like /v1/* should match /v1/chat/completions.
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if prefix == "" || prefix == "/" {
			// /* matches any absolute path.
			return strings.HasPrefix(endpoint, "/")
		}
		return strings.HasPrefix(endpoint, prefix+"/")
	}
	return false
}

// methodAllowed reports whether the HTTP method is in the allowed list
// (case-insensitive), mirroring the MCP execute_api_request path.
func methodAllowed(method string, allowed []string) bool {
	for _, m := range allowed {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}
