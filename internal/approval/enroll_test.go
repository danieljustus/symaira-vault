package approval

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/pairing"
)

func alwaysLoopback(string) bool { return true }
func neverLoopback(string) bool  { return false }

var testEnrollSecret = []byte("test-enroll-secret-32-bytes-long")

// setValidEnrollProof attaches a proof computed against testEnrollSecret for
// the current time, as a real "symvault device approval-pair" caller would.
func setValidEnrollProof(req *http.Request) {
	now := time.Now().UTC()
	req.Header.Set(HeaderEnrollTimestamp, now.Format(time.RFC3339))
	req.Header.Set(HeaderEnrollProof, EnrollProof(testEnrollSecret, now))
}

func TestEnrollCodeHTTPHandler_RejectsNonLoopback(t *testing.T) {
	codes := pairing.NewTokenStore()
	h := NewEnrollCodeHTTPHandler(codes, "fp-1", neverLoopback, testEnrollSecret)

	req := httptest.NewRequest(http.MethodPost, PathDeviceEnrollCode, nil)
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestEnrollCodeHTTPHandler_RejectsWithoutProof(t *testing.T) {
	codes := pairing.NewTokenStore()
	h := NewEnrollCodeHTTPHandler(codes, "fp-1", alwaysLoopback, testEnrollSecret)

	req := httptest.NewRequest(http.MethodPost, PathDeviceEnrollCode, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (unproven request from loopback must still be rejected)", rec.Code)
	}
}

func TestEnrollCodeHTTPHandler_RejectsWrongProof(t *testing.T) {
	codes := pairing.NewTokenStore()
	h := NewEnrollCodeHTTPHandler(codes, "fp-1", alwaysLoopback, testEnrollSecret)

	req := httptest.NewRequest(http.MethodPost, PathDeviceEnrollCode, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	now := time.Now().UTC()
	req.Header.Set(HeaderEnrollTimestamp, now.Format(time.RFC3339))
	req.Header.Set(HeaderEnrollProof, EnrollProof([]byte("wrong-secret"), now))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestEnrollCodeHTTPHandler_RejectsStaleProof(t *testing.T) {
	codes := pairing.NewTokenStore()
	h := NewEnrollCodeHTTPHandler(codes, "fp-1", alwaysLoopback, testEnrollSecret)

	req := httptest.NewRequest(http.MethodPost, PathDeviceEnrollCode, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	stale := time.Now().UTC().Add(-time.Hour)
	req.Header.Set(HeaderEnrollTimestamp, stale.Format(time.RFC3339))
	req.Header.Set(HeaderEnrollProof, EnrollProof(testEnrollSecret, stale))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a proof outside the freshness window", rec.Code)
	}
}

func TestEnrollCodeHTTPHandler_RejectsWithoutFingerprint(t *testing.T) {
	codes := pairing.NewTokenStore()
	h := NewEnrollCodeHTTPHandler(codes, "", alwaysLoopback, testEnrollSecret)

	req := httptest.NewRequest(http.MethodPost, PathDeviceEnrollCode, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	setValidEnrollProof(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestEnrollCodeHTTPHandler_RejectsNonPost(t *testing.T) {
	codes := pairing.NewTokenStore()
	h := NewEnrollCodeHTTPHandler(codes, "fp-1", alwaysLoopback, testEnrollSecret)

	req := httptest.NewRequest(http.MethodGet, PathDeviceEnrollCode, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestEnrollCodeHTTPHandler_MintsCode(t *testing.T) {
	codes := pairing.NewTokenStore()
	h := NewEnrollCodeHTTPHandler(codes, "fp-1", alwaysLoopback, testEnrollSecret)

	req := httptest.NewRequest(http.MethodPost, PathDeviceEnrollCode, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	setValidEnrollProof(req)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code        string `json:"code"`
		Fingerprint string `json:"fingerprint"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Code == "" {
		t.Fatal("expected a non-empty code")
	}
	if resp.Fingerprint != "fp-1" {
		t.Fatalf("fingerprint = %q, want fp-1", resp.Fingerprint)
	}
	if resp.ExpiresAt == "" {
		t.Fatal("expected a non-empty expires_at")
	}

	// The minted code must actually validate against the same store.
	if _, ok := codes.Validate(resp.Code); !ok {
		t.Fatal("minted code did not validate")
	}
}

func TestEnrollHTTPHandler_RejectsMalformedBody(t *testing.T) {
	codes := pairing.NewTokenStore()
	sessions, err := pairing.NewDeviceSessionStore("")
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	h := NewEnrollHTTPHandler(codes, sessions)

	req := httptest.NewRequest(http.MethodPost, PathDeviceEnroll, bytes.NewBufferString("not json"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestEnrollHTTPHandler_RejectsMissingCode(t *testing.T) {
	codes := pairing.NewTokenStore()
	sessions, err := pairing.NewDeviceSessionStore("")
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	h := NewEnrollHTTPHandler(codes, sessions)

	body, _ := json.Marshal(map[string]string{"device_name": "iPhone"})
	req := httptest.NewRequest(http.MethodPost, PathDeviceEnroll, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestEnrollHTTPHandler_RejectsInvalidCode(t *testing.T) {
	codes := pairing.NewTokenStore()
	sessions, err := pairing.NewDeviceSessionStore("")
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	h := NewEnrollHTTPHandler(codes, sessions)

	body, _ := json.Marshal(map[string]string{"code": "bogus-code", "device_name": "iPhone"})
	req := httptest.NewRequest(http.MethodPost, PathDeviceEnroll, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestEnrollHTTPHandler_Success(t *testing.T) {
	codes := pairing.NewTokenStore()
	sessions, err := pairing.NewDeviceSessionStore("")
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	h := NewEnrollHTTPHandler(codes, sessions)

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := codes.Store(token, ""); err != nil {
		t.Fatalf("Store: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"code": token.String(), "device_name": "Daniel's iPhone"})
	req := httptest.NewRequest(http.MethodPost, PathDeviceEnroll, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token    string `json:"token"`
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Token == "" || resp.DeviceID == "" {
		t.Fatalf("expected non-empty token and device_id, got %+v", resp)
	}

	deviceID, ok := sessions.Validate(resp.Token)
	if !ok || deviceID != resp.DeviceID {
		t.Fatalf("issued token did not validate: deviceID=%q ok=%v", deviceID, ok)
	}
}

func TestEnrollHTTPHandler_RevocationTakesEffectAcrossStoreInstances(t *testing.T) {
	dir := t.TempDir()
	codes := pairing.NewTokenStore()
	sessions, err := pairing.NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	h := NewEnrollHTTPHandler(codes, sessions)

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := codes.Store(token, ""); err != nil {
		t.Fatalf("Store: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"code": token.String(), "device_name": "Daniel's iPhone"})
	req := httptest.NewRequest(http.MethodPost, PathDeviceEnroll, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token    string `json:"token"`
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Sanity: the server's own long-lived store instance accepts the token
	// immediately after enrolment, as "symvault serve" would.
	if deviceID, ok := sessions.Validate(resp.Token); !ok || deviceID != resp.DeviceID {
		t.Fatalf("issued token did not validate before revoke: deviceID=%q ok=%v", deviceID, ok)
	}

	// A second, independent store instance is exactly what
	// "symvault device approval-revoke" opens: its own process, its own
	// DeviceSessionStore, pointed at the same vault directory.
	revoker, err := pairing.NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore (revoker): %v", err)
	}
	revoker.Revoke(resp.DeviceID)

	// The server's original, still-running store instance must reject the
	// token without needing a restart.
	if deviceID, ok := sessions.Validate(resp.Token); ok {
		t.Fatalf("revoked token still validated: deviceID=%q", deviceID)
	}

	// The revocation on disk must survive the server's own store persisting
	// state again (e.g. a cleanup tick), rather than being clobbered back to
	// unrevoked by the server's stale in-memory copy.
	sessions.CleanupExpired()
	onDisk, err := pairing.NewDeviceSessionStore(dir)
	if err != nil {
		t.Fatalf("NewDeviceSessionStore (reload): %v", err)
	}
	found := false
	for _, s := range onDisk.List() {
		if s.DeviceID == resp.DeviceID {
			found = true
			if !s.Revoked {
				t.Fatalf("device %q not revoked on disk after cleanup tick", resp.DeviceID)
			}
		}
	}
	if !found {
		t.Fatalf("device %q not found on disk after cleanup tick", resp.DeviceID)
	}
}

func TestEnrollHTTPHandler_CodeIsSingleUse(t *testing.T) {
	codes := pairing.NewTokenStore()
	sessions, err := pairing.NewDeviceSessionStore("")
	if err != nil {
		t.Fatalf("NewDeviceSessionStore: %v", err)
	}
	h := NewEnrollHTTPHandler(codes, sessions)

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := codes.Store(token, ""); err != nil {
		t.Fatalf("Store: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"code": token.String(), "device_name": "iPhone"})

	req1 := httptest.NewRequest(http.MethodPost, PathDeviceEnroll, bytes.NewReader(body))
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first enroll status = %d, want 200", rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, PathDeviceEnroll, bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("second enroll (reused code) status = %d, want 401", rec2.Code)
	}
}
