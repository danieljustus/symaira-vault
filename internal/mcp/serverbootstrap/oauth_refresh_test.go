package serverbootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/mcp"
)

type mockResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (m *mockResponseWriter) Header() http.Header         { return m.header }
func (m *mockResponseWriter) Write(b []byte) (int, error)  { return m.body.Write(b) }
func (m *mockResponseWriter) WriteHeader(s int)            { m.status = s }

func challengeForVerifier(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestOAuthRefreshToken_FullFlow(t *testing.T) {
	dir := t.TempDir()
	regPath := dir + "/tokens.json"
	reg := mcp.NewTokenRegistry(regPath)

	accessTTL := 10 * time.Minute
	refreshTTL := 30 * time.Minute

	store := newOAuthCodeStore()
	handler := handleOAuthToken(store, reg, accessTTL, refreshTTL)

	code := "test-auth-code-123"
	store.put(code, &pendingCode{
		clientID:        "test-client",
		redirectURI:     "http://localhost:9999/callback",
		codeChallenge:   challengeForVerifier("test-verifier"),
		challengeMethod: "S256",
		expiresAt:       time.Now().Add(5 * time.Minute),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {"test-verifier"},
	}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusOK {
		t.Fatalf("token exchange status = %d, want %d; body=%s", w.status, http.StatusOK, w.body.String())
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(w.body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResp["access_token"] == nil {
		t.Fatal("access_token missing")
	}
	if tokenResp["refresh_token"] == nil {
		t.Fatal("refresh_token missing")
	}

	rawAccess := tokenResp["access_token"].(string)
	rawRefresh := tokenResp["refresh_token"].(string)

	w2 := &mockResponseWriter{header: http.Header{}}
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawRefresh},
	}
	req2, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(w2, req2)

	if w2.status != http.StatusOK {
		t.Fatalf("refresh token exchange status = %d, want %d; body=%s", w2.status, http.StatusOK, w2.body.String())
	}

	var refreshResp map[string]any
	if err := json.Unmarshal(w2.body.Bytes(), &refreshResp); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if refreshResp["access_token"] == nil {
		t.Fatal("new access_token missing after refresh")
	}
	if refreshResp["refresh_token"] == nil {
		t.Fatal("new refresh_token missing after refresh")
	}

	newAccess := refreshResp["access_token"].(string)
	newRefresh := refreshResp["refresh_token"].(string)

	if newAccess == rawAccess {
		t.Error("access token was not rotated")
	}
	if newRefresh == rawRefresh {
		t.Error("refresh token was not rotated")
	}

	oldHash := sha256HexRaw(rawAccess)
	_, ok := reg.Get(oldHash)
	if ok {
		t.Error("old access token should be revoked after refresh")
	}

	w3 := &mockResponseWriter{header: http.Header{}}
	form3 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawRefresh},
	}
	req3, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form3.Encode()))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(w3, req3)
	if w3.status != http.StatusBadRequest {
		t.Errorf("old refresh token status = %d, want %d", w3.status, http.StatusBadRequest)
	}

	var errResp map[string]any
	if err := json.Unmarshal(w3.body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", errResp["error"])
	}

	w4 := &mockResponseWriter{header: http.Header{}}
	form4 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {newRefresh},
	}
	req4, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form4.Encode()))
	req4.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(w4, req4)
	if w4.status != http.StatusOK {
		t.Fatalf("new refresh token status = %d, want %d", w4.status, http.StatusOK)
	}
}

func TestOAuthRefreshToken_ExpiredRefreshDenied(t *testing.T) {
	dir := t.TempDir()
	regPath := dir + "/tokens.json"
	reg := mcp.NewTokenRegistry(regPath)

	accessTTL := 1 * time.Hour
	refreshTTL := 1 * time.Millisecond

	store := newOAuthCodeStore()
	handler := handleOAuthToken(store, reg, accessTTL, refreshTTL)

	code := "test-code-expired"
	store.put(code, &pendingCode{
		clientID:        "test-client",
		redirectURI:     "http://localhost:9999/callback",
		codeChallenge:   challengeForVerifier("v"),
		challengeMethod: "S256",
		expiresAt:       time.Now().Add(5 * time.Minute),
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {"v"},
	}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := &mockResponseWriter{header: http.Header{}}
	handler.ServeHTTP(w, req)

	if w.status != http.StatusOK {
		t.Fatalf("token exchange status = %d, want %d", w.status, http.StatusOK)
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(w.body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	rawRefresh := tokenResp["refresh_token"].(string)

	time.Sleep(2 * time.Millisecond)

	w2 := &mockResponseWriter{header: http.Header{}}
	form2 := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawRefresh},
	}
	req2, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(w2, req2)

	if w2.status != http.StatusBadRequest {
		t.Fatalf("expired refresh token status = %d, want %d; body=%s", w2.status, http.StatusBadRequest, w2.body.String())
	}

	var errResp map[string]any
	if err := json.Unmarshal(w2.body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp["error"] != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", errResp["error"])
	}
}

func TestOAuthRefreshToken_RegisterResponseIncludesRefresh(t *testing.T) {
	clientStore := newOAuthClientStore()
	handler := handleOAuthRegister(clientStore)

	reqBody := `{"redirect_uris": ["http://localhost:3000/callback"]}`
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusCreated {
		t.Fatalf("register status = %d, want %d", w.status, http.StatusCreated)
	}

	var regResp map[string]any
	if err := json.Unmarshal(w.body.Bytes(), &regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}

	grantTypes, ok := regResp["grant_types"].([]any)
	if !ok {
		t.Fatal("grant_types missing from registration response")
	}

	hasRefresh := false
	hasAuthCode := false
	for _, gt := range grantTypes {
		switch gt {
		case "authorization_code":
			hasAuthCode = true
		case "refresh_token":
			hasRefresh = true
		}
	}
	if !hasAuthCode {
		t.Error("authorization_code missing from grant_types")
	}
	if !hasRefresh {
		t.Error("refresh_token missing from grant_types")
	}
}

func TestOAuthRefreshToken_WellKnownIncludesRefresh(t *testing.T) {
	handler := handleOAuthAuthorizationServer("127.0.0.1", 9999)

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	var body map[string]any
	if err := json.Unmarshal(w.body.Bytes(), &body); err != nil {
		t.Fatalf("decode well-known response: %v", err)
	}

	grantTypes, ok := body["grant_types_supported"].([]any)
	if !ok {
		t.Fatal("grant_types_supported missing")
	}

	hasRefresh := false
	for _, gt := range grantTypes {
		if gt == "refresh_token" {
			hasRefresh = true
			break
		}
	}
	if !hasRefresh {
		t.Error("refresh_token missing from grant_types_supported")
	}
}

func TestOAuthRefreshToken_UnsupportedGrantType(t *testing.T) {
	reg := mcp.NewTokenRegistry("")
	handler := handleOAuthToken(nil, reg, 24*time.Hour, 720*time.Hour)

	form := url.Values{"grant_type": {"unsupported"}}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.status, http.StatusBadRequest)
	}

	var errResp map[string]any
	if err := json.Unmarshal(w.body.Bytes(), &errResp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if errResp["error"] != "unsupported_grant_type" {
		t.Errorf("error = %q, want unsupported_grant_type", errResp["error"])
	}
}

func TestOAuthRefreshToken_MissingRefreshToken(t *testing.T) {
	reg := mcp.NewTokenRegistry("")
	handler := handleOAuthToken(nil, reg, 24*time.Hour, 720*time.Hour)

	form := url.Values{"grant_type": {"refresh_token"}}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.status, http.StatusBadRequest)
	}
}

func sha256HexRaw(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
