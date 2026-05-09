package pairing

import (
	"testing"
	"time"
)

func TestNewTokenStore(t *testing.T) {
	ts := NewTokenStore()
	if ts == nil {
		t.Fatal("NewTokenStore returned nil")
	}
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	if len(token) != 6 {
		t.Errorf("expected 6-digit token, got %q (len=%d)", token, len(token))
	}
	for _, ch := range token {
		if ch < '0' || ch > '9' {
			t.Errorf("expected digits only, got %q", token)
			break
		}
	}
}

func TestTokenStore_StoreAndValidate(t *testing.T) {
	ts := NewTokenStore()
	token := "123456"
	pubKey := "test-public-key"

	if err := ts.Store(token, pubKey); err != nil {
		t.Fatalf("Store error: %v", err)
	}

	got, ok := ts.Validate(token)
	if !ok {
		t.Fatal("Validate returned false for valid token")
	}
	if got != pubKey {
		t.Errorf("Validate returned %q, want %q", got, pubKey)
	}
}

func TestTokenStore_Validate_SingleUse(t *testing.T) {
	ts := NewTokenStore()
	_ = ts.Store("000000", "key")

	_, ok := ts.Validate("000000")
	if !ok {
		t.Fatal("first Validate should succeed")
	}
	_, ok = ts.Validate("000000")
	if ok {
		t.Fatal("second Validate should fail (single-use)")
	}
}

func TestTokenStore_Validate_NotFound(t *testing.T) {
	ts := NewTokenStore()
	_, ok := ts.Validate("999999")
	if ok {
		t.Error("expected false for unknown token")
	}
}

func TestTokenStore_CleanupExpired(t *testing.T) {
	ts := NewTokenStore()
	_ = ts.Store("111111", "key1")

	// Manually expire the token.
	ts.mu.Lock()
	entry := ts.tokens["111111"]
	entry.expiresAt = time.Now().Add(-time.Minute)
	ts.tokens["111111"] = entry
	ts.mu.Unlock()

	ts.CleanupExpired()

	ts.mu.RLock()
	_, exists := ts.tokens["111111"]
	ts.mu.RUnlock()

	if exists {
		t.Error("expected expired token to be cleaned up")
	}
}
