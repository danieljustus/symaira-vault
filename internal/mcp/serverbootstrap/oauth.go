package serverbootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
	"github.com/danieljustus/symaira-vault/internal/mcp/server"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	oauthClientsFileVersion = 1
	oauthClientsFileName    = "mcp-oauth-clients.json"
)

// consentPageHTML is the browser-based consent page shown when the server
// runs without a TTY (e.g. as a daemon). The user proves human presence by
// entering the vault passphrase — the same secret that gates the vault root.
var consentPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Symaira Vault OAuth Authorization</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f5f5f7;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.08);
            padding: 40px;
            max-width: 480px;
            width: 100%;
        }
        .logo {
            font-size: 24px;
            font-weight: 700;
            color: #1d1d1f;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #86868b;
            font-size: 14px;
            margin-bottom: 32px;
        }
        .client-info {
            background: #f5f5f7;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
        }
        .client-info h3 {
            margin: 0 0 12px 0;
            font-size: 16px;
            color: #1d1d1f;
        }
        .client-info .detail {
            font-size: 13px;
            color: #86868b;
            margin-bottom: 4px;
            word-break: break-all;
        }
        .client-info .detail strong {
            color: #1d1d1f;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 13px;
            color: #856404;
            margin-bottom: 24px;
        }
        .warning strong {
            color: #856404;
        }
        label {
            display: block;
            font-size: 14px;
            font-weight: 500;
            color: #1d1d1f;
            margin-bottom: 8px;
        }
        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #d2d2d7;
            border-radius: 8px;
            font-size: 15px;
            margin-bottom: 8px;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus {
            outline: none;
            border-color: #0071e3;
        }
        .hint {
            font-size: 12px;
            color: #86868b;
            margin-bottom: 24px;
        }
        .actions {
            display: flex;
            gap: 12px;
        }
        button {
            flex: 1;
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }
        button[type="submit"] {
            background: #0071e3;
            color: white;
        }
        button[type="submit"]:hover {
            background: #0077ed;
        }
        button[type="submit"]:disabled {
            background: #d2d2d7;
            cursor: not-allowed;
        }
        .btn-secondary {
            background: #f5f5f7;
            color: #1d1d1f;
        }
        .btn-secondary:hover {
            background: #e8e8ed;
        }
        .error {
            background: #fff2f2;
            border: 1px solid #ffcdd2;
            border-radius: 8px;
            padding: 12px 16px;
            font-size: 13px;
            color: #c62828;
            margin-bottom: 16px;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">🔐 Symaira Vault</div>
        <div class="subtitle">OAuth Authorization Request</div>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <div class="client-info">
            <h3>{{.ClientID}}</h3>
            <div class="detail"><strong>Redirect URI:</strong> {{.RedirectURI}}</div>
            <div class="detail"><strong>Scopes:</strong> vault access</div>
        </div>
        <div class="warning">
            <strong>⚠️ Daemon Mode Detected</strong><br>
            The server is running without an interactive terminal. To authorize this client, enter your vault passphrase below.
        </div>
        <form method="POST" action="/mcp/oauth/authorize/confirm">
            <input type="hidden" name="client_id" value="{{.ClientID}}">
            <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
            <input type="hidden" name="state" value="{{.State}}">
            <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
            <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
            <label for="passphrase">Vault Passphrase</label>
            <input type="password" id="passphrase" name="passphrase" placeholder="Enter your vault passphrase" required autofocus>
            <div class="hint">Your passphrase is the same secret used to unlock the vault. It is never stored.</div>
            <div class="actions">
                <button type="submit">Authorize</button>
                <button type="button" class="btn-secondary" onclick="window.location.href='{{.RedirectURI}}?error=access_denied'">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>`

// consentPageData holds the template variables for the consent page.
type consentPageData struct {
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Error               string
}

// oauthClientStoreFile is the on-disk JSON representation of the client store.
type oauthClientStoreFile struct {
	Version int                          `json:"version"`
	Clients map[string]*registeredClient `json:"clients"`
}

// oauthClientStore persists registered OAuth client applications. It is backed
// by an on-disk JSON file when a vaultDir is provided; otherwise it operates
// purely in memory.
type oauthClientStore struct {
	mu      sync.Mutex
	clients map[string]*registeredClient
	path    string // path to the JSON persistence file, empty = in-memory only
}

type registeredClient struct {
	ClientID     string     `json:"client_id"`
	RedirectURIs []string   `json:"redirect_uris"`
	CreatedAt    time.Time  `json:"created_at"`
	TTL          *int64     `json:"ttl_seconds,omitempty"` // optional TTL in seconds
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`  // computed expiration time
}

// newOAuthClientStore creates an in-memory-only client store.
func newOAuthClientStore() *oauthClientStore {
	return &oauthClientStore{clients: make(map[string]*registeredClient)}
}

// loadOAuthClientStore creates a client store backed by a persistent JSON file
// at <vaultDir>/<oauthClientsFileName>. If vaultDir is empty, the store is
// purely in-memory. The file is loaded on creation; a missing file is not an
// error (empty store).
func loadOAuthClientStore(vaultDir string) (*oauthClientStore, error) {
	s := &oauthClientStore{clients: make(map[string]*registeredClient)}
	if vaultDir == "" {
		return s, nil
	}
	s.path = filepath.Join(vaultDir, oauthClientsFileName)
	if err := s.Load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Load reads the JSON client registry file from disk and populates the
// in-memory entries. If the file does not exist it is a no-op (empty store).
func (s *oauthClientStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.path == "" {
		return nil
	}

	data, err := os.ReadFile(s.path) //#nosec G304 -- path is set from vaultDir in loadOAuthClientStore
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read oauth client store: %w", err)
	}

	var file oauthClientStoreFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse oauth client store: %w", err)
	}

	s.clients = make(map[string]*registeredClient, len(file.Clients))
	for id, c := range file.Clients {
		if c != nil {
			s.clients[id] = c
		}
	}
	return nil
}

// Save persists the current in-memory client entries to the JSON file with
// 0o600 permissions. A no-op if the store has no associated file path.
func (s *oauthClientStore) Save() error {
	s.mu.Lock()
	file := oauthClientStoreFile{
		Version: oauthClientsFileVersion,
		Clients: make(map[string]*registeredClient, len(s.clients)),
	}
	for id, c := range s.clients {
		file.Clients[id] = c
	}
	s.mu.Unlock()

	if s.path == "" {
		return nil
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal oauth client store: %w", err)
	}

	if err := fsutil.AtomicWriteFile(s.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write oauth client store: %w", err)
	}
	return nil
}

func (s *oauthClientStore) put(c *registeredClient) {
	s.mu.Lock()
	s.clients[c.ClientID] = c
	s.mu.Unlock()

	// Best-effort persistence: log error but never fail the registration.
	if s.path != "" {
		if err := s.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to persist OAuth client store: %v\n", err)
		}
	}
}

func (s *oauthClientStore) get(clientID string) (*registeredClient, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return nil, false
	}
	// Lazy expiry check: if the client has an expiration and it's passed,
	// treat it as not found.
	if c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
		delete(s.clients, clientID)
		return nil, false
	}
	return c, true
}

// cleanupExpired removes all clients whose TTL has expired. Returns the
// count of removed entries.
func (s *oauthClientStore) cleanupExpired() int {
	s.mu.Lock()
	now := time.Now()
	var removed int
	for id, c := range s.clients {
		if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
			delete(s.clients, id)
			removed++
		}
	}
	needsSave := removed > 0 && s.path != ""
	s.mu.Unlock()

	if needsSave {
		if err := s.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to persist OAuth client store after cleanup: %v\n", err)
		}
	}
	return removed
}

// StartCleanup launches a background goroutine that periodically sweeps
// expired client entries at the given interval. It returns a stop function.
func (s *oauthClientStore) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.cleanupExpired()
			case <-ctx.Done():
				s.cleanupExpired()
				return
			}
		}
	}()
}

type oauthCodeStore struct {
	mu    sync.Mutex
	codes map[string]*pendingCode
}

type pendingCode struct {
	clientID        string
	redirectURI     string
	codeChallenge   string
	challengeMethod string
	expiresAt       time.Time
}

func newOAuthCodeStore() *oauthCodeStore {
	return &oauthCodeStore{codes: make(map[string]*pendingCode)}
}

func (s *oauthCodeStore) put(code string, p *pendingCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = p
}

func (s *oauthCodeStore) take(code string) (*pendingCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.codes[code]
	if !ok {
		return nil, false
	}
	delete(s.codes, code)
	return p, true
}

type oauthRegisterRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
}

// handleOAuthRegister implements RFC 7591 dynamic client registration.
// It stores the registered client with its allowed redirect URIs and returns
// a public client identity — no secret is issued.
func handleOAuthRegister(clientStore *oauthClientStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !server.IsJSONContentType(r.Header.Get("Content-Type")) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
			return
		}

		var req oauthRegisterRequest
		bodyReader := http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(bodyReader).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
			return
		}

		if len(req.RedirectURIs) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
			return
		}
		for _, redirectURI := range req.RedirectURIs {
			if !isAllowedRegistrationRedirectURI(redirectURI) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
				return
			}
		}

		// Generate a unique client_id instead of a hardcoded value.
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		clientID := hex.EncodeToString(b)

		clientStore.put(&registeredClient{
			ClientID:     clientID,
			RedirectURIs: req.RedirectURIs,
			CreatedAt:    time.Now(),
		})

		writeJSON(w, http.StatusCreated, map[string]any{
			"client_id":                  clientID,
			"client_id_issued_at":        time.Now().Unix(),
			"client_secret_expires_at":   0,
			"token_endpoint_auth_method": "none",
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
			"redirect_uris":              req.RedirectURIs,
		})
	}
}

// handleOAuthAuthorize handles the authorization code request (RFC 6749 §4.1.1).
// It validates the client_id and redirect_uri against the registered client,
// requires explicit user consent via TTY, and only then issues a short-lived
// authorization code bound to the client_id.
// When no TTY is available (daemon mode), it renders a browser-based consent
// page where the user proves human presence by entering the vault passphrase.
func handleOAuthAuthorize(store *oauthCodeStore, clientStore *oauthClientStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		codeChallenge := q.Get("code_challenge")
		challengeMethod := q.Get("code_challenge_method")
		clientID := q.Get("client_id")

		if q.Get("response_type") != "code" || redirectURI == "" || codeChallenge == "" || clientID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "response_type=code, client_id, redirect_uri and code_challenge are required",
			})
			return
		}
		if challengeMethod != "S256" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "only S256 code_challenge_method is supported",
			})
			return
		}

		// Validate client_id against registered clients.
		client, ok := clientStore.get(clientID)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="symaira",error="invalid_client",error_description="unknown client_id; register via POST /oauth/register first"`)
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_client",
				"error_description": "unknown client_id; register via POST /oauth/register first",
			})
			return
		}

		// Validate redirect_uri against the registered allowlist.
		if !isAllowedRedirectURI(redirectURI, client.RedirectURIs) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_redirect_uri",
				"error_description": "redirect_uri does not match registered redirect URIs",
			})
			return
		}

		// Require explicit user consent via TTY prompt.
		// Without this, any local process can silently mint tokens (see #21).
		result := server.RequestApproval(server.ApprovalRequest{
			Operation: "OAuth Authorization Request",
			Details:   fmt.Sprintf("Client %q requests vault access\n  Redirect URI: %s", clientID, redirectURI),
			Timeout:   60 * time.Second,
		})
		if !result.Approved {
			if result.Error != nil && strings.Contains(result.Error.Error(), "no TTY available") {
				// Daemon mode: render browser-based consent page with passphrase challenge.
				renderConsentPage(w, consentPageData{
					ClientID:            clientID,
					RedirectURI:         redirectURI,
					State:               state,
					CodeChallenge:       codeChallenge,
					CodeChallengeMethod: challengeMethod,
				})
				return
			}
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":             "access_denied",
				"error_description": "Authorization denied by user",
			})
			return
		}

		issueAuthCode(w, r, store, clientID, redirectURI, state, codeChallenge, challengeMethod)
	}
}

// renderConsentPage renders the HTML consent page for daemon-mode OAuth approval.
func renderConsentPage(w http.ResponseWriter, data consentPageData) {
	tmpl, err := template.New("consent").Parse(consentPageHTML)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "failed to render consent page",
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = tmpl.Execute(w, data)
}

// issueAuthCode generates an authorization code, stores it, and redirects.
func issueAuthCode(w http.ResponseWriter, r *http.Request, store *oauthCodeStore, clientID, redirectURI, state, codeChallenge, challengeMethod string) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	code := hex.EncodeToString(b)

	store.put(code, &pendingCode{
		clientID:        clientID,
		redirectURI:     redirectURI,
		codeChallenge:   codeChallenge,
		challengeMethod: challengeMethod,
		expiresAt:       time.Now().Add(5 * time.Minute),
	})

	u, err := url.Parse(redirectURI)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	params := u.Query()
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	u.RawQuery = params.Encode()
	// #nosec G710 -- client-supplied redirect URI is validated against client registry before reaching here
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleOAuthConfirm handles the POST from the browser-based consent page.
// It verifies the vault passphrase and, on success, issues an authorization code.
func handleOAuthConfirm(store *oauthCodeStore, clientStore *oauthClientStore, vaultDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "invalid_request"})
			return
		}

		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}

		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		state := r.FormValue("state")
		codeChallenge := r.FormValue("code_challenge")
		challengeMethod := r.FormValue("code_challenge_method")
		passphrase := r.FormValue("passphrase")

		// Re-validate client_id.
		client, ok := clientStore.get(clientID)
		if !ok {
			renderConsentPage(w, consentPageData{
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				State:               state,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: challengeMethod,
				Error:               "Invalid client ID. Please register the client first.",
			})
			return
		}

		// Re-validate redirect_uri.
		if !isAllowedRedirectURI(redirectURI, client.RedirectURIs) {
			renderConsentPage(w, consentPageData{
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				State:               state,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: challengeMethod,
				Error:               "Invalid redirect URI.",
			})
			return
		}

		// Verify passphrase by attempting to open the vault.
		if vaultDir == "" || passphrase == "" {
			renderConsentPage(w, consentPageData{
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				State:               state,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: challengeMethod,
				Error:               "Passphrase is required.",
			})
			return
		}

		_, err := vaultpkg.OpenWithPassphrase(vaultDir, []byte(passphrase))
		if err != nil {
			renderConsentPage(w, consentPageData{
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				State:               state,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: challengeMethod,
				Error:               "Incorrect passphrase. Please try again.",
			})
			return
		}

		// Passphrase verified — issue the authorization code.
		issueAuthCode(w, r, store, clientID, redirectURI, state, codeChallenge, challengeMethod)
	}
}

// handleOAuthToken implements the authorization code grant (RFC 6749 §4.1.3)
// with PKCE verification (RFC 7636) and refresh token support (RFC 6749 §6).
// On success it mints a fresh scoped MCP token via the TokenRegistry instead
// of returning the global legacy bearer token.
func handleOAuthToken(store *oauthCodeStore, registry *auth.TokenRegistry, accessTokenTTL, refreshTokenTTL time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}

		if registry == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}

		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			pending, ok := store.take(r.FormValue("code"))
			if !ok || time.Now().After(pending.expiresAt) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
				return
			}
			if !verifyS256(r.FormValue("code_verifier"), pending.codeChallenge) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
				return
			}

			label := fmt.Sprintf("oauth-%s", pending.clientID[:8])
			tok, rawToken, rawRefresh, err := registry.CreateWithRefresh(
				label, []string{"*"}, "oauth", accessTokenTTL, refreshTokenTTL,
			)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
				return
			}

			expiresIn := 0
			if tok.ExpiresAt != nil {
				expiresIn = int(time.Until(*tok.ExpiresAt).Seconds())
			}

			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  rawToken,
				"token_type":    "Bearer",
				"expires_in":    expiresIn,
				"refresh_token": rawRefresh,
			})

		case "refresh_token":
			rawRefresh := r.FormValue("refresh_token")
			if rawRefresh == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "refresh_token is required"})
				return
			}

			newTok, rawAccess, rawRefresh, err := registry.RotateViaRefreshToken(rawRefresh)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "invalid or expired refresh token"})
				return
			}

			expiresIn := 0
			if newTok.ExpiresAt != nil {
				expiresIn = int(time.Until(*newTok.ExpiresAt).Seconds())
			}

			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":  rawAccess,
				"token_type":    "Bearer",
				"expires_in":    expiresIn,
				"refresh_token": rawRefresh,
			})

		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		}
	}
}

func verifyS256(codeVerifier, codeChallenge string) bool {
	if codeVerifier == "" || codeChallenge == "" {
		return false
	}
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// isAllowedRedirectURI checks whether redirectURI exactly matches one of the
// allowed URIs (trailing-slash normalization applied).
func isAllowedRedirectURI(redirectURI string, allowedURIs []string) bool {
	normalized := strings.TrimSuffix(redirectURI, "/")
	for _, allowed := range allowedURIs {
		if strings.TrimSuffix(allowed, "/") == normalized {
			return true
		}
	}
	return false
}

func isAllowedRegistrationRedirectURI(redirectURI string) bool {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" {
		return false
	}
	if u.User != nil || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "http", "https":
		host := u.Hostname()
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	default:
		return strings.HasPrefix(u.Scheme, "symvault") || strings.HasPrefix(u.Scheme, "symaira")
	}
}
