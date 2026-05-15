package serverbootstrap

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/danieljustus/OpenPass/internal/mcp"
)

// oauthClientStore persists registered OAuth client applications in memory.
type oauthClientStore struct {
	mu      sync.Mutex
	clients map[string]*registeredClient
}

type registeredClient struct {
	ClientID     string    `json:"client_id"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

func newOAuthClientStore() *oauthClientStore {
	return &oauthClientStore{clients: make(map[string]*registeredClient)}
}

func (s *oauthClientStore) put(c *registeredClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ClientID] = c
}

func (s *oauthClientStore) get(clientID string) (*registeredClient, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	return c, ok
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
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "unauthorized_client",
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
