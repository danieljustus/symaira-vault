package serverbootstrap

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRenderConsentPage(t *testing.T) {
	w := &mockResponseWriter{header: http.Header{}}
	data := consentPageData{
		ClientID:            "test-client",
		RedirectURI:         "http://localhost:3000/callback",
		State:               "test-state",
		CodeChallenge:       "test-challenge",
		CodeChallengeMethod: "S256",
	}

	renderConsentPage(w, data)

	if w.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.status, http.StatusOK)
	}

	contentType := w.header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", contentType)
	}

	body := w.body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("expected HTML response, got non-HTML")
	}
	if !strings.Contains(body, "test-client") {
		t.Error("expected client ID in HTML")
	}
	if !strings.Contains(body, "http://localhost:3000/callback") {
		t.Error("expected redirect URI in HTML")
	}
	if !strings.Contains(body, `name="state" value="test-state"`) {
		t.Error("expected state in hidden form field")
	}
	if !strings.Contains(body, "passphrase") {
		t.Error("expected passphrase input field")
	}
}

func TestRenderConsentPage_WithError(t *testing.T) {
	w := &mockResponseWriter{header: http.Header{}}
	data := consentPageData{
		ClientID:            "test-client",
		RedirectURI:         "http://localhost:3000/callback",
		State:               "test-state",
		CodeChallenge:       "test-challenge",
		CodeChallengeMethod: "S256",
		Error:               "Incorrect passphrase",
	}

	renderConsentPage(w, data)

	body := w.body.String()
	if !strings.Contains(body, "Incorrect passphrase") {
		t.Errorf("expected error message in HTML, got: %s", body)
	}
}

func TestOAuthConfirm_InvalidPassphraseShowsError(t *testing.T) {
	clientStore := newOAuthClientStore()
	clientStore.put(&registeredClient{
		ClientID:     "test-client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})

	store := newOAuthCodeStore()
	handler := handleOAuthConfirm(store, clientStore, t.TempDir())

	form := url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"test-state"},
		"passphrase":            {"wrong-passphrase"},
	}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.status, http.StatusOK)
	}

	body := w.body.String()
	if !strings.Contains(body, "Incorrect passphrase") {
		t.Errorf("expected error message about incorrect passphrase, got: %s", body)
	}
}

func TestOAuthConfirm_MissingPassphraseShowsError(t *testing.T) {
	clientStore := newOAuthClientStore()
	clientStore.put(&registeredClient{
		ClientID:     "test-client",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})

	store := newOAuthCodeStore()
	handler := handleOAuthConfirm(store, clientStore, t.TempDir())

	form := url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"test-state"},
	}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.status, http.StatusOK)
	}

	body := w.body.String()
	if !strings.Contains(body, "Passphrase is required") {
		t.Errorf("expected error message about missing passphrase, got: %s", body)
	}
}

func TestOAuthConfirm_InvalidClientShowsError(t *testing.T) {
	store := newOAuthCodeStore()
	handler := handleOAuthConfirm(store, newOAuthClientStore(), "")

	form := url.Values{
		"client_id":             {"unknown-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
		"state":                 {"test-state"},
		"passphrase":            {"some-pass"},
	}
	req, _ := http.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.status, http.StatusOK)
	}

	body := w.body.String()
	if !strings.Contains(body, "Invalid client ID") {
		t.Errorf("expected error message about invalid client, got: %s", body)
	}
}

func TestOAuthConfirm_GetNotAllowed(t *testing.T) {
	store := newOAuthCodeStore()
	handler := handleOAuthConfirm(store, newOAuthClientStore(), "")

	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	w := &mockResponseWriter{header: http.Header{}}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", w.status, http.StatusMethodNotAllowed)
	}
}
