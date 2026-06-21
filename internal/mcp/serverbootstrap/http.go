// Package serverbootstrap provides HTTP and stdio server initialization for the MCP server.
package serverbootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	auth "github.com/danieljustus/symaira-vault/internal/mcp/auth"
	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// bufferPool reduces allocations for JSON encoding on the hot path.
// Each Get returns a clean (Reset) *bytes.Buffer.
var bufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// RunHTTPServer starts the HTTP MCP server.
func RunHTTPServer(ctx context.Context, bind string, port int, v *vaultpkg.Vault, vaultDir string, version string, factory func(*vaultpkg.Vault, string, string) (*mcpserver.Server, error)) error {
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return RunHTTPServerOnListener(ctx, listener, v, vaultDir, version, factory)
}

// RunHTTPServerOnListener starts the HTTP MCP server on an already-bound listener.
// Tests and embedders can use this to bind :0 safely without a find-free-port race.
//
//nolint:gocyclo // Complex server initialization: auth, middleware, metrics, graceful shutdown
func RunHTTPServerOnListener(ctx context.Context, listener net.Listener, v *vaultpkg.Vault, vaultDir string, version string, factory func(*vaultpkg.Vault, string, string) (*mcpserver.Server, error)) error {
	bind, port := listenerAddress(listener)
	otlpEndpoint := ""
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		otlpEndpoint = v.Config.MCP.OTLPEndpoint
	}
	shutdownTracing, err := metrics.InitTracing(otlpEndpoint, "")
	if err != nil {
		return fmt.Errorf("init tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = shutdownTracing(shutdownCtx)
		cancel()
	}()

	addr := net.JoinHostPort(bind, strconv.Itoa(port))

	// Load the token registry (with legacy fallback), wire its cleanup audit
	// logging and background cleanup, and build the auth audit logger.
	ts, err := setupTokenSystem(ctx, v, vaultDir)
	if err != nil {
		return err
	}
	defer ts.Close()
	registry := ts.registry
	legacyToken := ts.legacyToken
	authAuditLog := ts.authAuditLog

	rateLimiter, stopCleanup := setupRateLimiter(ctx, v)

	handlerCache := make(map[string]*mcpserver.ProtocolHandler)
	var cacheMu sync.RWMutex

	handlerForAgent := func(agentName string) (*mcpserver.ProtocolHandler, error) {
		cacheMu.RLock()
		if h, ok := handlerCache[agentName]; ok {
			cacheMu.RUnlock()
			return h, nil
		}
		cacheMu.RUnlock()

		type result struct {
			handler *mcpserver.ProtocolHandler
			err     error
		}
		resultChan := make(chan result, 1)

		go func() {
			mcpSrv, mcpErr := factory(v, agentName, "http")
			if mcpErr != nil {
				resultChan <- result{err: mcpErr}
				return
			}
			h := mcpserver.NewProtocolHandler("symaira", "1.0.0", mcpSrv)

			cacheMu.Lock()
			if existing, ok := handlerCache[agentName]; ok {
				_ = h.Close()
				cacheMu.Unlock()
				resultChan <- result{handler: existing}
				return
			}
			handlerCache[agentName] = h
			cacheMu.Unlock()
			resultChan <- result{handler: h}
		}()

		select {
		case res := <-resultChan:
			return res.handler, res.err
		case <-time.After(10 * time.Second):
			return nil, fmt.Errorf("handler creation timeout for agent %q: creation took longer than 10s", agentName)
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"status":    "healthy",
			"port":      port,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"version":   version,
		}
		buf, ok := bufferPool.Get().(*bytes.Buffer)
		if !ok {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		buf.Reset()
		defer func() {
			buf.Reset()
			bufferPool.Put(buf)
		}()
		//nolint:errchkjson // Best-effort health response write
		_ = json.NewEncoder(buf).Encode(resp)
		_, _ = w.Write(buf.Bytes())
	})

	registerMetricsEndpoint(mux, v, bind, legacyToken, registry, authAuditLog)

	// OAuth well-known endpoints (RFC 9728, RFC 8414)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", handleOAuthProtectedResource(bind, port))
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", handleOAuthAuthorizationServer(bind, port))

	// OAuth 2.1 + PKCE endpoints (RFC 7591, RFC 6749, RFC 7636)
	// NOTE: OAuth endpoints use OriginValidation + rate limiting but NOT
	// BearerAuthMiddleware — clients don't have a token yet at this point.
	// User consent is required at the authorize step (see handleOAuthAuthorize).
	oauthStore := newOAuthCodeStore()
	clientStore, err := loadOAuthClientStore(vaultDir)
	if err != nil {
		return fmt.Errorf("load oauth client store: %w", err)
	}
	clientStore.StartCleanup(ctx, 5*time.Minute)

	oauthRegisterHandler := auth.OriginValidationMiddleware(addr, handleOAuthRegister(clientStore))
	mux.HandleFunc("POST /oauth/register", oauthRegisterHandler.ServeHTTP)

	oauthAuthorizeHandler := auth.OriginValidationMiddleware(addr, handleOAuthAuthorize(oauthStore, clientStore))
	mux.HandleFunc("GET /mcp/oauth/authorize", oauthAuthorizeHandler.ServeHTTP)

	oauthConfirmHandler := auth.OriginValidationMiddleware(addr, handleOAuthConfirm(oauthStore, clientStore, vaultDir))
	mux.HandleFunc("POST /mcp/oauth/authorize/confirm", oauthConfirmHandler.ServeHTTP)

	// Token endpoint uses the scoped token registry instead of the legacy bearer token.
	accessTokenTTL := 24 * time.Hour
	refreshTokenTTL := 720 * time.Hour
	if v != nil && v.Config != nil && v.Config.MCP != nil && v.Config.MCP.OAuth != nil {
		if v.Config.MCP.OAuth.AccessTokenTTL > 0 {
			accessTokenTTL = v.Config.MCP.OAuth.AccessTokenTTL
		}
		if v.Config.MCP.OAuth.RefreshTokenTTL > 0 {
			refreshTokenTTL = v.Config.MCP.OAuth.RefreshTokenTTL
		}
	}
	oauthTokenHandler := auth.OriginValidationMiddleware(addr, handleOAuthToken(oauthStore, registry, accessTokenTTL, refreshTokenTTL))
	mux.HandleFunc("POST /mcp/oauth/token", oauthTokenHandler.ServeHTTP)

	const maxRequestBodySize = 1 * 1024 * 1024
	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			mcpserver.WriteMCPHTTPError(w, http.StatusMethodNotAllowed, nil, transport.ErrCodeInvalidRequest, "method not allowed")
			return
		}
		if !mcpserver.IsJSONContentType(r.Header.Get("Content-Type")) {
			mcpserver.WriteMCPHTTPError(w, http.StatusUnsupportedMediaType, nil, transport.ErrCodeInvalidRequest, "Content-Type must be application/json")
			return
		}
		if !mcpserver.AcceptsMCPHTTPResponse(r.Header.Values("Accept")) {
			mcpserver.WriteMCPHTTPError(w, http.StatusNotAcceptable, nil, transport.ErrCodeInvalidRequest, "Accept must include application/json and text/event-stream")
			return
		}

		var msg transport.Message
		bodyReader := http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		if err := json.NewDecoder(bodyReader).Decode(&msg); err != nil {
			if err.Error() == "http: request body too large" {
				mcpserver.WriteMCPHTTPError(w, http.StatusRequestEntityTooLarge, nil, transport.ErrCodeParseError, "request body too large")
				return
			}
			mcpserver.WriteMCPHTTPError(w, http.StatusBadRequest, nil, transport.ErrCodeParseError, "invalid JSON")
			return
		}

		protocolVersion := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
		if protocolVersion == "" && msg.Method != "initialize" {
			protocolVersion = mcpserver.DefaultHTTPProtocolVersion
		}
		if protocolVersion != "" && !mcpserver.IsSupportedProtocolVersion(protocolVersion) {
			mcpserver.WriteMCPHTTPError(w, http.StatusBadRequest, msg.ID, transport.ErrCodeInvalidRequest, "unsupported MCP-Protocol-Version")
			return
		}

		agentName := auth.AgentFromContext(r.Context())
		handler, err := handlerForAgent(agentName)
		if err != nil {
			mcpserver.WriteMCPHTTPError(w, http.StatusForbidden, msg.ID, transport.ErrCodeInternalError, err.Error())
			return
		}

		resp, err := handler.HandleMessage(r.Context(), &msg)
		if err != nil {
			mcpserver.WriteMCPHTTPError(w, http.StatusInternalServerError, msg.ID, transport.ErrCodeInternalError, err.Error())
			return
		}
		if resp == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		buf, ok := bufferPool.Get().(*bytes.Buffer)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		buf.Reset()
		//nolint:errchkjson // Best-effort JSON response write; no recovery path if encoding fails
		_ = json.NewEncoder(buf).Encode(resp)
		_, _ = w.Write(buf.Bytes())
		buf.Reset()
		bufferPool.Put(buf)
	})
	mcpChain := auth.OriginValidationMiddleware(addr, auth.BearerAuthMiddleware(legacyToken, registry, authAuditLog, auth.AgentHeaderMiddleware(mcpHandler)))
	if rateLimiter != nil {
		mcpChain = auth.RateLimiterMiddleware(rateLimiter, mcpChain)
	}
	mux.Handle("/mcp", mcpChain)

	timeouts := resolveServerTimeouts(v)
	shutdownTimeout := timeouts.shutdown

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: timeouts.readHeader,
		ReadTimeout:       timeouts.read,
		WriteTimeout:      timeouts.write,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	tlsCert := ""
	tlsKey := ""
	tlsCAFile := ""
	mtlsEnabled := false
	allowInsecure := false
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		tlsCert = strings.TrimSpace(v.Config.MCP.TLSCertFile)
		tlsKey = strings.TrimSpace(v.Config.MCP.TLSKeyFile)
		tlsCAFile = strings.TrimSpace(v.Config.MCP.TLSClientCAFile)
		mtlsEnabled = v.Config.MCP.MTLSEnabled
		allowInsecure = v.Config.MCP.AllowInsecureBind
	}

	if !allowInsecure && (tlsCert == "" || tlsKey == "") {
		autoCert, autoKey, autoErr := ensureTLSCert(vaultDir)
		if autoErr != nil {
			cliout.Warnf("could not generate self-signed TLS certificate for MCP server: %v", autoErr)
		}
		if autoCert != "" && autoKey != "" {
			tlsCert = autoCert
			tlsKey = autoKey
		}
	}
	tlsEnabled := tlsCert != "" && tlsKey != ""

	if !tlsEnabled && !allowInsecure {
		return fmt.Errorf("refusing to serve MCP without TLS on bind %q: "+
			"set MCP.tls_cert_file + MCP.tls_key_file, or explicitly opt-in with MCP.allow_insecure_bind=true "+
			"(bearer tokens would otherwise be sent in cleartext; even on loopback, a local attacker or compromised process can sniff traffic)", bind)
	}
	if !tlsEnabled && allowInsecure {
		loopbackNote := ""
		if mcpserver.IsLoopbackBind(bind) {
			loopbackNote = " Even on loopback, a local attacker or compromised process on the same machine can sniff traffic."
		}
		cliout.Warnf(
			"MCP server is binding %q without TLS; bearer tokens travel in cleartext (MCP.allow_insecure_bind=true).%s", bind, loopbackNote)
	}

	go func() {
		<-ctx.Done()
		if stopCleanup != nil {
			stopCleanup()
		}
		if rateLimiter != nil {
			_ = rateLimiter.Close()
		}
		if registry != nil {
			_ = registry.Close()
		}
		cacheMu.Lock()
		for _, h := range handlerCache {
			_ = h.Close()
		}
		cacheMu.Unlock()
		shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	var serveErr error
	if tlsEnabled {
		if mtlsEnabled && tlsCAFile != "" {
			caCert, readErr := os.ReadFile(tlsCAFile)
			if readErr != nil {
				return fmt.Errorf("read client CA certificate: %w", readErr)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("parse client CA certificate: no valid PEM block found in %q", tlsCAFile)
			}
			cert, loadErr := tls.LoadX509KeyPair(tlsCert, tlsKey)
			if loadErr != nil {
				return fmt.Errorf("load server TLS key pair: %w", loadErr)
			}
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    caCertPool,
				MinVersion:   tls.VersionTLS12,
			}
			tlsListener := tls.NewListener(listener, tlsConfig)
			serveErr = server.Serve(tlsListener)
		} else {
			serveErr = server.ServeTLS(listener, tlsCert, tlsKey)
		}
	} else {
		serveErr = server.Serve(listener)
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}
	return nil
}

func listenerAddress(listener net.Listener) (string, int) {
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return "127.0.0.1", 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 0
	}
	return host, port
}
