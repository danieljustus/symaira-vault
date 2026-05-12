package serverbootstrap

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/danieljustus/OpenPass/internal/mcp"
)

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

type oauthRegisterRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
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

// handleOAuthRegister implements RFC 7591 dynamic client registration.
// Parses the JSON request body to extract redirect_uris, validates them,
// and returns a public client identity — no secret is issued.
func handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	if !mcp.IsJSONContentType(r.Header.Get("Content-Type")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
		return
	}

	var req oauthRegisterRequest
	bodyReader := http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(bodyReader).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
		return
	}

	if len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  "openpass-mcp-client",
		"client_id_issued_at":        time.Now().Unix(),
		"client_secret_expires_at":   0,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"redirect_uris":              req.RedirectURIs,
	})
}

// handleOAuthAuthorize handles the authorization code request (RFC 6749 §4.1.1).
// Since the MCP server is local and the vault is already unlocked, we auto-approve
// and immediately redirect back with a short-lived authorization code.
func handleOAuthAuthorize(store *oauthCodeStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		codeChallenge := q.Get("code_challenge")
		challengeMethod := q.Get("code_challenge_method")
		clientID := q.Get("client_id")

		if q.Get("response_type") != "code" || redirectURI == "" || codeChallenge == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "response_type=code, redirect_uri and code_challenge are required",
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
// with PKCE verification (RFC 7636). On success it returns the vault bearer
// token so the MCP client can authenticate subsequent requests normally.
func handleOAuthToken(store *oauthCodeStore, bearerToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		if r.FormValue("grant_type") != "authorization_code" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
			return
		}

		pending, ok := store.take(r.FormValue("code"))
		if !ok || time.Now().After(pending.expiresAt) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		if !verifyS256(r.FormValue("code_verifier"), pending.codeChallenge) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": bearerToken,
			"token_type":   "Bearer",
			"expires_in":   0,
		})
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
