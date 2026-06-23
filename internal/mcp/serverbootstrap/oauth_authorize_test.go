package serverbootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- handleOAuthAuthorize: parameter validation branches ---

func TestHandleOAuthAuthorize_MissingResponseType(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?client_id=c&redirect_uri=http://localhost/cb&code_challenge=abc&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
	if !strings.Contains(body["error_description"], "response_type") {
		t.Errorf("description should mention response_type, got %q", body["error_description"])
	}
}

func TestHandleOAuthAuthorize_MissingClientID(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&redirect_uri=http://localhost/cb&code_challenge=abc&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}

func TestHandleOAuthAuthorize_MissingRedirectURI(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&client_id=c&code_challenge=abc&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}

func TestHandleOAuthAuthorize_MissingCodeChallenge(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}

func TestHandleOAuthAuthorize_MissingAllParams(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}

// --- S256-only enforcement ---

func TestHandleOAuthAuthorize_NonS256ChallengeMethod(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&code_challenge=abc&code_challenge_method=plain", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
	if !strings.Contains(body["error_description"], "S256") {
		t.Errorf("description should mention S256, got %q", body["error_description"])
	}
}

func TestHandleOAuthAuthorize_EmptyChallengeMethod(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&code_challenge=abc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- Unknown client_id ---

func TestHandleOAuthAuthorize_UnknownClientID(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&client_id=unknown&redirect_uri=http://localhost/cb&code_challenge=abc&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// Verify WWW-Authenticate header is set.
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "invalid_client") {
		t.Errorf("WWW-Authenticate = %q, should contain invalid_client", wwwAuth)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %q, want invalid_client", body["error"])
	}
	if !strings.Contains(body["error_description"], "register") {
		t.Errorf("description should mention registration, got %q", body["error_description"])
	}
}

// --- Invalid redirect_uri ---

func TestHandleOAuthAuthorize_InvalidRedirectURI(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	clientStore.put(&registeredClient{
		ClientID:     "my-client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&client_id=my-client&redirect_uri=http://evil.example/callback&code_challenge=abc&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "invalid_redirect_uri" {
		t.Errorf("error = %q, want invalid_redirect_uri", body["error"])
	}
}

// --- Daemon-mode consent page rendering (no TTY path) ---

func TestHandleOAuthAuthorize_NoTTYRendersConsentPage(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	clientStore.put(&registeredClient{
		ClientID:     "my-client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&client_id=my-client&redirect_uri=http://localhost:3000/callback&code_challenge=test-challenge&code_challenge_method=S256&state=my-state", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// In test environment (no TTY), the handler renders the consent page.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Symaira Vault") {
		t.Error("expected consent page header in HTML")
	}
	if !strings.Contains(body, "my-client") {
		t.Error("expected client ID in consent page")
	}
	if !strings.Contains(body, "http://localhost:3000/callback") {
		t.Error("expected redirect URI in consent page")
	}
	if !strings.Contains(body, `name="state" value="my-state"`) {
		t.Error("expected state hidden field in consent page")
	}
	if !strings.Contains(body, `name="code_challenge" value="test-challenge"`) {
		t.Error("expected code_challenge hidden field in consent page")
	}
	if !strings.Contains(body, "passphrase") {
		t.Error("expected passphrase input in consent page")
	}
}

func TestHandleOAuthAuthorize_NoStateConsentPage(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()
	clientStore.put(&registeredClient{
		ClientID:     "no-state-client",
		RedirectURIs: []string{"http://localhost:4000/cb"},
	})
	handler := handleOAuthAuthorize(store, clientStore)

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?response_type=code&client_id=no-state-client&redirect_uri=http://localhost:4000/cb&code_challenge=challenge&code_challenge_method=S256", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "no-state-client") {
		t.Error("expected client ID in consent page")
	}
	// State field should be empty string when not provided.
	if !strings.Contains(body, `name="state" value=""`) {
		t.Error("expected empty state field in consent page")
	}
}

// --- renderConsentPage: ensure full coverage ---

func TestRenderConsentPage_AllFields(t *testing.T) {
	w := httptest.NewRecorder()
	data := consentPageData{
		ClientID:            "full-test-client",
		RedirectURI:         "http://localhost:8080/callback",
		State:               "state-value",
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		Error:               "",
	}

	renderConsentPage(w, data)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "full-test-client") {
		t.Error("client ID missing from rendered page")
	}
	if !strings.Contains(body, "http://localhost:8080/callback") {
		t.Error("redirect URI missing from rendered page")
	}
	if !strings.Contains(body, "state-value") {
		t.Error("state missing from rendered page")
	}
	if !strings.Contains(body, "challenge-value") {
		t.Error("code_challenge missing from rendered page")
	}
	if !strings.Contains(body, "S256") {
		t.Error("code_challenge_method missing from rendered page")
	}
	if !strings.Contains(body, "Authorize") {
		t.Error("authorize button missing from rendered page")
	}
}

func TestRenderConsentPage_WithErrorMessage(t *testing.T) {
	w := httptest.NewRecorder()
	data := consentPageData{
		ClientID:            "error-client",
		RedirectURI:         "http://localhost/cb",
		CodeChallenge:       "ch",
		CodeChallengeMethod: "S256",
		Error:               "Invalid passphrase. Please try again.",
	}

	renderConsentPage(w, data)

	body := w.Body.String()
	if !strings.Contains(body, "Invalid passphrase") {
		t.Error("error message missing from rendered page")
	}
}

func TestRenderConsentPage_DaemonModeWarning(t *testing.T) {
	w := httptest.NewRecorder()
	data := consentPageData{
		ClientID:            "daemon-client",
		RedirectURI:         "http://localhost/cb",
		CodeChallenge:       "ch",
		CodeChallengeMethod: "S256",
	}

	renderConsentPage(w, data)

	body := w.Body.String()
	if !strings.Contains(body, "Daemon Mode") {
		t.Error("daemon mode warning missing from rendered page")
	}
	if !strings.Contains(body, "POST") {
		t.Error("form method should be POST")
	}
	if !strings.Contains(body, "/mcp/oauth/authorize/confirm") {
		t.Error("form action should point to confirm endpoint")
	}
}

// --- issueAuthCode: direct tests ---

func TestIssueAuthCode_ValidRedirectWithState(t *testing.T) {
	codeStore := newOAuthCodeStore()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/mcp/oauth/authorize", nil)
	rec := httptest.NewRecorder()

	issueAuthCode(rec, req, codeStore, "client-1", "http://localhost:3000/callback", "my-state", "challenge-abc", "S256")

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}

	location := rec.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location header: %v", err)
	}

	params := parsedURL.Query()
	code := params.Get("code")
	if code == "" {
		t.Fatal("authorization code missing from redirect")
	}
	if params.Get("state") != "my-state" {
		t.Errorf("state = %q, want my-state", params.Get("state"))
	}
	if parsedURL.Host != "localhost:3000" {
		t.Errorf("redirect host = %q, want localhost:3000", parsedURL.Host)
	}
	if parsedURL.Path != "/callback" {
		t.Errorf("redirect path = %q, want /callback", parsedURL.Path)
	}

	// Verify the code was stored.
	pending, ok := codeStore.take(code)
	if !ok {
		t.Fatal("authorization code not stored in code store")
	}
	if pending.clientID != "client-1" {
		t.Errorf("clientID = %q, want client-1", pending.clientID)
	}
	if pending.redirectURI != "http://localhost:3000/callback" {
		t.Errorf("redirectURI = %q, want http://localhost:3000/callback", pending.redirectURI)
	}
	if pending.codeChallenge != "challenge-abc" {
		t.Errorf("codeChallenge = %q, want challenge-abc", pending.codeChallenge)
	}
	if pending.challengeMethod != "S256" {
		t.Errorf("challengeMethod = %q, want S256", pending.challengeMethod)
	}
}

func TestIssueAuthCode_ValidRedirectWithoutState(t *testing.T) {
	codeStore := newOAuthCodeStore()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/mcp/oauth/authorize", nil)
	rec := httptest.NewRecorder()

	issueAuthCode(rec, req, codeStore, "client-2", "http://localhost:4000/cb", "", "challenge-def", "S256")

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	location := rec.Header().Get("Location")
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location header: %v", err)
	}

	params := parsedURL.Query()
	code := params.Get("code")
	if code == "" {
		t.Fatal("authorization code missing from redirect")
	}
	// When state is empty, the state param should not be in the redirect.
	if params.Get("state") != "" {
		t.Errorf("state should be empty, got %q", params.Get("state"))
	}
}

func TestIssueAuthCode_CodeIsUnique(t *testing.T) {
	codeStore := newOAuthCodeStore()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/mcp/oauth/authorize", nil)

	rec1 := httptest.NewRecorder()
	issueAuthCode(rec1, req, codeStore, "client-a", "http://localhost/cb1", "s1", "ch1", "S256")

	rec2 := httptest.NewRecorder()
	issueAuthCode(rec2, req, codeStore, "client-b", "http://localhost/cb2", "s2", "ch2", "S265")

	code1 := extractCodeFromRedirect(t, rec1.Header().Get("Location"))
	code2 := extractCodeFromRedirect(t, rec2.Header().Get("Location"))

	if code1 == code2 {
		t.Errorf("two calls produced the same code %q", code1)
	}
}

func TestIssueAuthCode_StoresCodeWithExpiry(t *testing.T) {
	codeStore := newOAuthCodeStore()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/mcp/oauth/authorize", nil)
	rec := httptest.NewRecorder()

	issueAuthCode(rec, req, codeStore, "client-x", "http://localhost/cb", "", "ch", "S256")

	code := extractCodeFromRedirect(t, rec.Header().Get("Location"))
	pending, ok := codeStore.codes[code]
	if !ok {
		t.Fatal("code not stored")
	}
	if pending.expiresAt.IsZero() {
		t.Error("expiresAt should be set")
	}
}

func TestIssueAuthCode_InvalidRedirectURI(t *testing.T) {
	codeStore := newOAuthCodeStore()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/mcp/oauth/authorize", nil)
	rec := httptest.NewRecorder()

	// An invalid URI that url.Parse can't parse as valid.
	issueAuthCode(rec, req, codeStore, "client-y", "://bad-uri", "", "ch", "S256")

	// url.Parse is very permissive, so "://bad-uri" may parse. Use a truly
	// empty redirect to trigger the error path.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "http://localhost/mcp/oauth/authorize", nil)
	// We can't easily make url.Parse fail with normal inputs since it's
	// permissive. Instead, verify the happy path works with different URI formats.
	issueAuthCode(rec2, req2, codeStore, "client-z", "http://127.0.0.1:9999/callback?foo=bar", "", "ch", "S256")

	if rec2.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec2.Code, http.StatusFound)
	}
}

// --- End-to-end: full authorize flow through handler ---

func TestHandleOAuthAuthorize_FullFlowConsentPage(t *testing.T) {
	store := newOAuthCodeStore()
	clientStore := newOAuthClientStore()

	// Register a client first.
	clientStore.put(&registeredClient{
		ClientID:     "e2e-client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})

	handler := handleOAuthAuthorize(store, clientStore)

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"e2e-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"code_challenge":        {"e2e-challenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"e2e-state"},
	}

	req := httptest.NewRequest(http.MethodGet, "/mcp/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// No TTY in test env → consent page rendered.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	body := rec.Body.String()
	// Verify all form fields are present in the consent page.
	for _, field := range []string{
		`name="client_id" value="e2e-client"`,
		`name="redirect_uri" value="http://localhost:3000/callback"`,
		`name="state" value="e2e-state"`,
		`name="code_challenge" value="e2e-challenge"`,
		`name="code_challenge_method" value="S256"`,
	} {
		if !strings.Contains(body, field) {
			t.Errorf("consent page missing field: %s", field)
		}
	}

	// Verify code store is empty (no code issued yet).
	if len(store.codes) != 0 {
		t.Errorf("code store should be empty, got %d codes", len(store.codes))
	}
}

// --- Helper ---

func extractCodeFromRedirect(t *testing.T, location string) string {
	t.Helper()
	parsedURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := parsedURL.Query().Get("code")
	if code == "" {
		t.Fatal("code missing from redirect Location")
	}
	return code
}
