// Package serverbootstrap provides HTTP and stdio server initialization for the MCP server.
package serverbootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danieljustus/symaira-vault/internal/audit"
	auth "github.com/danieljustus/symaira-vault/internal/mcp/auth"
	mcpserver "github.com/danieljustus/symaira-vault/internal/mcp/server"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/metrics"
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

	// Load token system (registry + legacy fallback)
	tokenPath := ""
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		tf := v.Config.MCP.HTTPTokenFile
		if tf != "" && tf != "auto" {
			tokenPath = tf
		}
	}
	registry, legacyToken, err := auth.LoadTokenSystem(vaultDir, tokenPath)
	if err != nil {
		return fmt.Errorf("load token system: %w", err)
	}

	// Create a dedicated audit logger for token cleanup events before
	// starting the cleanup goroutine so it can reference the logger.
	cleanupAuditLog, err := audit.New("token-cleanup", vaultDir)
	if err != nil {
		return fmt.Errorf("create token cleanup audit logger: %w", err)
	}
	defer func() { _ = cleanupAuditLog.Close() }()

	// Start background cleanup for token registry
	if registry != nil {
		registry.SetRevokedRetention(30 * 24 * time.Hour) // 30-day retention for revoked tokens
		registry.SetCleanupLogger(func(action, tokenID, label, reason string) {
			if logErr := cleanupAuditLog.LogEntry(audit.LogEntry{
				Action:  "token_cleanup",
				Agent:   "token-cleanup",
				Reason:  reason,
				TokenID: tokenID,
				OK:      true,
			}); logErr != nil {
				fmt.Fprintf(os.Stderr, "token cleanup audit log write failed: %v\n", logErr)
			}
		})
		cleanupInterval := 5 * time.Minute
		_ = registry.StartCleanup(ctx, cleanupInterval)
		// Start file watcher to reload token registry when CLI creates new tokens
		_ = registry.StartFileWatcher(ctx, 2*time.Second)
	}

	authAuditLog, err := audit.New("auth-failures", vaultDir)
	if err != nil {
		return fmt.Errorf("create auth audit logger: %w", err)
	}
	defer func() { _ = authAuditLog.Close() }()

	if registry != nil {
		result := registry.Cleanup()
		totalRemoved := result.ExpiredRemoved + result.RevokedRemoved
		if totalRemoved > 0 {
			_ = authAuditLog.LogEntry(audit.LogEntry{
				Agent:  "system",
				Action: "token_cleanup",
				Reason: fmt.Sprintf("removed %d expired, %d revoked (%d total)", result.ExpiredRemoved, result.RevokedRemoved, totalRemoved),
				OK:     true,
			})
		}
	}

	rateLimit := 60
	var trustedProxyIPs []string
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		if v.Config.MCP.RateLimit >= 0 {
			rateLimit = v.Config.MCP.RateLimit
		}
		trustedProxyIPs = v.Config.MCP.TrustedProxyIPs
	}
	var rateLimiter *auth.RateLimiter
	var stopCleanup func()
	if rateLimit > 0 {
		rateLimiter = auth.NewRateLimiter(rateLimit, time.Minute, trustedProxyIPs...)
		stopCleanup = rateLimiter.StartCleanup(ctx, 5*time.Minute)
	}

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

	readHeaderTimeout := 5 * time.Second
	readTimeout := 10 * time.Second
	writeTimeout := 10 * time.Second
	shutdownTimeout := 5 * time.Second
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		mcpCfg := v.Config.MCP
		if mcpCfg.ReadHeaderTimeout > 0 {
			readHeaderTimeout = mcpCfg.ReadHeaderTimeout
		}
		if mcpCfg.ReadTimeout > 0 {
			readTimeout = mcpCfg.ReadTimeout
		}
		if mcpCfg.WriteTimeout > 0 {
			writeTimeout = mcpCfg.WriteTimeout
		}
		if mcpCfg.ShutdownTimeout > 0 {
			shutdownTimeout = mcpCfg.ShutdownTimeout
		}
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	tlsCert := ""
	tlsKey := ""
	allowInsecure := false
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		tlsCert = strings.TrimSpace(v.Config.MCP.TLSCertFile)
		tlsKey = strings.TrimSpace(v.Config.MCP.TLSKeyFile)
		allowInsecure = v.Config.MCP.AllowInsecureBind
	}

	if !allowInsecure && (tlsCert == "" || tlsKey == "") {
		autoCert, autoKey, autoErr := ensureTLSCert(vaultDir)
		if autoErr != nil {
			fmt.Fprintf(os.Stderr,
				"WARNING: could not generate self-signed TLS certificate for MCP server: %v\n", autoErr)
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
		fmt.Fprintf(os.Stderr,
			"WARNING: MCP server is binding %q without TLS; bearer tokens travel in cleartext (MCP.allow_insecure_bind=true).%s\n", bind, loopbackNote)
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
		serveErr = server.ServeTLS(listener, tlsCert, tlsKey)
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
