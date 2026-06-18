package pairing

import (
	"strings"
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

	raw := string(token)
	// base32 hex encoding of 20 bytes without padding: ceil(20*8/5) = 32 chars
	if len(raw) != 32 {
		t.Errorf("expected 32-char token, got %q (len=%d)", raw, len(raw))
	}

	// Should only contain base32 hex chars (0-9, A-V)
	for _, ch := range raw {
		if !((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'V')) {
			t.Errorf("unexpected character %q in token %q", ch, raw)
			break
		}
	}
}

func TestGenerateToken_Entropy(t *testing.T) {
	// Generate multiple tokens and verify they're all unique (practical entropy check).
	const count = 100
	seen := make(map[string]bool, count)
	lastRaw := ""
	for i := 0; i < count; i++ {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken error at iteration %d: %v", i, err)
		}
		lastRaw = string(token)
		if seen[lastRaw] {
			t.Fatalf("duplicate token generated at iteration %d: %q", i, lastRaw)
		}
		seen[lastRaw] = true
	}

	// 20 random bytes = 160 bits, encoded as 32 base32 chars at 5 bits/char.
	if len(lastRaw)*5 < 100 {
		t.Errorf("token has %d bits of entropy, want >= 100", len(lastRaw)*5)
	}
}

func TestToken_Display(t *testing.T) {
	tests := []struct {
		input Token
		want  string
	}{
		{Token("ABCDEFGHIJKLMNOPQRST"), "ABCD-EFGH-IJKL-MNOP-QRST"},
		{Token("ABCD"), "ABCD"},
		{Token("ABCDEFGH"), "ABCD-EFGH"},
		{Token(""), ""},
		{Token("A"), "A"},
	}

	for _, tt := range tests {
		got := tt.input.Display()
		if got != tt.want {
			t.Errorf("Token(%q).Display() = %q, want %q", string(tt.input), got, tt.want)
		}
	}
}

func TestToken_String(t *testing.T) {
	token := Token("ABCD1234")
	if token.String() != "ABCD1234" {
		t.Errorf("Token.String() = %q, want %q", token.String(), "ABCD1234")
	}
}

func TestTokenStore_StoreAndValidate(t *testing.T) {
	ts := NewTokenStore()
	token := Token("TOKEN1234TEST")
	pubKey := "test-public-key"

	if err := ts.Store(token, pubKey); err != nil {
		t.Fatalf("Store error: %v", err)
	}

	got, ok := ts.Validate(string(token))
	if !ok {
		t.Fatal("Validate returned false for valid token")
	}
	if got != pubKey {
		t.Errorf("Validate returned %q, want %q", got, pubKey)
	}
}

func TestTokenStore_Validate_SingleUse(t *testing.T) {
	ts := NewTokenStore()
	_ = ts.Store(Token("SINGLEUSE"), "key")

	_, ok := ts.Validate("SINGLEUSE")
	if !ok {
		t.Fatal("first Validate should succeed")
	}
	_, ok = ts.Validate("SINGLEUSE")
	if ok {
		t.Fatal("second Validate should fail (single-use)")
	}
}

func TestTokenStore_Validate_NotFound(t *testing.T) {
	ts := NewTokenStore()
	_, ok := ts.Validate("NONEXISTENT")
	if ok {
		t.Error("expected false for unknown token")
	}
}

func TestTokenStore_CleanupExpired(t *testing.T) {
	ts := NewTokenStore()
	_ = ts.Store(Token("EXPIREDTOKEN"), "key1")

	// Manually expire the token.
	ts.mu.Lock()
	entry := ts.tokens["EXPIREDTOKEN"]
	entry.expiresAt = time.Now().Add(-time.Minute)
	ts.tokens["EXPIREDTOKEN"] = entry
	ts.mu.Unlock()

	ts.CleanupExpired()

	ts.mu.RLock()
	_, exists := ts.tokens["EXPIREDTOKEN"]
	ts.mu.RUnlock()

	if exists {
		t.Error("expected expired token to be cleaned up")
	}
}

func TestTokenStore_GlobalCooldown(t *testing.T) {
	ts := NewTokenStore()
	token := Token("COOLDOWN")
	pubKey := "cooldown-key"

	if err := ts.Store(token, pubKey); err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// 5 failed attempts with different wrong tokens trigger the global
	// cooldown. Previously the per-guess tracking never reached the limit
	// (each wrong token was a different key), making brute-force possible.
	for i := 0; i < 5; i++ {
		badToken := string(token) + "_wrong"
		_, ok := ts.Validate(badToken)
		if ok {
			t.Fatalf("Validate(%q) should fail", badToken)
		}
	}

	// The real token is temporarily rejected due to global cooldown.
	got, ok := ts.Validate(string(token))
	if ok {
		t.Fatal("Validate should fail — global cooldown active after 5 failures")
	}
	if got != "" {
		t.Errorf("Validate returned %q, want empty", got)
	}

	// Verify cooldown state is set.
	ts.mu.Lock()
	if ts.failedCount < maxFailedAttempts {
		t.Error("failedCount should be >= maxFailedAttempts")
	}
	if ts.cooldownUntil.IsZero() {
		t.Error("cooldownUntil should be set")
	}
	ts.mu.Unlock()
}

func TestTokenStore_FailedAttemptsBurnSameToken(t *testing.T) {
	ts := NewTokenStore()
	token := Token("SELFBURN")
	pubKey := "self-burn-key"

	if err := ts.Store(token, pubKey); err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Same token string attempted 5 times with wrong value won't match
	// because the store uses the exact token string as the key.
	// Instead, expire the token and then try 5 times.
	ts.mu.Lock()
	entry := ts.tokens["SELFBURN"]
	entry.expiresAt = time.Now().Add(-time.Hour)
	ts.tokens["SELFBURN"] = entry
	ts.mu.Unlock()

	for i := 0; i < 5; i++ {
		_, ok := ts.Validate("SELFBURN")
		if ok {
			t.Fatalf("iteration %d: Validate should fail for expired token", i)
		}
	}

	// After 5 failed global attempts, cooldown should trigger.
	ts.mu.Lock()
	_, tokenExists := ts.tokens["SELFBURN"]
	inCooldown := ts.failedCount >= maxFailedAttempts && time.Now().Before(ts.cooldownUntil)
	ts.mu.Unlock()

	if tokenExists {
		t.Error("expected token to be deleted after 5 failed attempts")
	}
	if !inCooldown {
		t.Error("expected cooldown to be active after 5 failed attempts")
	}
}

func TestTokenStore_FailedAttempts_ExactMatchSingleUse(t *testing.T) {
	ts := NewTokenStore()
	token := Token("EXACTMATCH")
	pubKey := "exact-match-key"

	if err := ts.Store(token, pubKey); err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Exact match succeeds immediately (single-use token consumed).
	got, ok := ts.Validate("EXACTMATCH")
	if !ok {
		t.Fatal("Validate should succeed for exact match")
	}
	if got != pubKey {
		t.Errorf("Validate returned %q, want %q", got, pubKey)
	}

	// Second attempt should fail (single-use).
	_, ok = ts.Validate("EXACTMATCH")
	if ok {
		t.Fatal("second Validate should fail (single-use)")
	}
}

func TestTokenStore_TTL(t *testing.T) {
	if TokenTTL > 5*time.Minute {
		t.Errorf("TokenTTL = %v, want <= 5 minutes", TokenTTL)
	}
}

func TestTokenStore_ConcurrentAccess(t *testing.T) {
	ts := NewTokenStore()
	token := Token("CONCURRENT")
	pubKey := "concurrent-key"

	if err := ts.Store(token, pubKey); err != nil {
		t.Fatalf("Store error: %v", err)
	}

	// Launch multiple goroutines trying to validate the same token.
	// Only one should succeed.
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, ok := ts.Validate("CONCURRENT")
			done <- ok
		}()
	}

	successCount := 0
	for i := 0; i < 10; i++ {
		if <-done {
			successCount++
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful validation, got %d", successCount)
	}
}

func TestGenerateToken_DisplayFormat(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}

	display := token.Display()
	// Display should contain dashes separating 4-char groups.
	parts := strings.Split(display, "-")
	for _, part := range parts {
		if len(part) > 4 || len(part) == 0 {
			t.Errorf("Display part %q has invalid length (want 1-4 chars)", part)
		}
	}
	// The last group may be shorter (remainder), but the displayed token
	// should reconstruct to the same raw string.
	reconstructed := strings.Join(parts, "")
	if reconstructed != string(token) {
		t.Errorf("Display reconstruction mismatch: %q vs %q", reconstructed, string(token))
	}
}

func TestValidatePairingToken_Valid(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken error: %v", err)
	}
	if err := ValidatePairingToken(string(token)); err != nil {
		t.Errorf("ValidatePairingToken(%q) = %v, want nil", string(token), err)
	}
}

func TestValidatePairingToken_Empty(t *testing.T) {
	if err := ValidatePairingToken(""); err == nil {
		t.Error("expected error for empty token")
	}
}

func TestValidatePairingToken_PathSeparator(t *testing.T) {
	for _, tok := range []string{"../../../etc/passwd", "abc/def", `abc\def`} {
		if err := ValidatePairingToken(tok); err == nil {
			t.Errorf("expected error for token %q", tok)
		}
	}
}

func TestValidatePairingToken_NullByte(t *testing.T) {
	if err := ValidatePairingToken("abc\x00def"); err == nil {
		t.Error("expected error for null byte in token")
	}
}

func TestValidatePairingToken_ControlChars(t *testing.T) {
	if err := ValidatePairingToken("abc\x01def"); err == nil {
		t.Error("expected error for control character in token")
	}
}

func TestValidatePairingToken_InvalidChars(t *testing.T) {
	for _, tok := range []string{"abc def", "abc:def", "abc=def", "abc+def"} {
		if err := ValidatePairingToken(tok); err == nil {
			t.Errorf("expected error for token %q", tok)
		}
	}
}

func TestValidatePairingToken_LowercaseValid(t *testing.T) {
	if err := ValidatePairingToken("abcdef012345"); err != nil {
		t.Errorf("lowercase base32 hex should be valid, got %v", err)
	}
}

func TestValidatePairingToken_TooLong(t *testing.T) {
	long := strings.Repeat("A", 65)
	if err := ValidatePairingToken(long); err == nil {
		t.Error("expected error for token > 64 chars")
	}
}

func TestValidatePairingToken_GenerateTokenAlwaysValid(t *testing.T) {
	for i := 0; i < 50; i++ {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("iteration %d: GenerateToken error: %v", i, err)
		}
		if err := ValidatePairingToken(string(token)); err != nil {
			t.Errorf("iteration %d: generated token %q rejected: %v", i, string(token), err)
		}
	}
}
