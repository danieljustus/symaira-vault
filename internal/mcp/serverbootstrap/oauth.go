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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/danieljustus/OpenPass/internal/fileutil"
	"github.com/danieljustus/OpenPass/internal/mcp"
)

const (
	oauthClientsFileVersion = 1
	oauthClientsFileName    = "mcp-oauth-clients.json"
)

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
	TTL          *int64     `json:"ttl_seconds,omitempty"`   // optional TTL in seconds
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`    // computed expiration time
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

	if err := fileutil.AtomicWriteFile(s.path, append(data, '\n'), 0o600); err != nil {
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
		if !mcp.IsJSONContentType(r.Header.Get("Content-Type")) {
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
			w.Header().Set("WWW-Authenticate", `Bearer realm="openpass",error="invalid_client",error_description="unknown client_id; register via POST /oauth/register first"`)
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
		result := mcp.RequestApproval(mcp.ApprovalRequest{
			Operation: "OAuth Authorization Request",
			Details:   fmt.Sprintf("Client %q requests vault access\n  Redirect URI: %s", clientID, redirectURI),
			Timeout:   60 * time.Second,
		})
		if !result.Approved {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":             "access_denied",
				"error_description": "Authorization denied by user",
			})
			return
		}

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
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
}

// handleOAuthToken implements the authorization code grant (RFC 6749 §4.1.3)
// with PKCE verification (RFC 7636) and refresh token support (RFC 6749 §6).
// On success it mints a fresh scoped MCP token via the TokenRegistry instead
// of returning the global legacy bearer token.
func handleOAuthToken(store *oauthCodeStore, registry *mcp.TokenRegistry, accessTokenTTL, refreshTokenTTL time.Duration) http.HandlerFunc {
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
