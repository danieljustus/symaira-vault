// Package pairing provides device pairing token generation and management.
package pairing

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
)

// TokenTTL is the time-to-live for pairing tokens. Exported for testing.
var TokenTTL = 5 * time.Minute

// Token represents a high-entropy pairing token.
type Token string

// String returns the raw token string.
func (t Token) String() string { return string(t) }

// Display formats the token as human-readable blocks (e.g., "ABCD-EFGH-IJKL-MNOP-QRST").
func (t Token) Display() string {
	s := string(t)
	parts := make([]string, 0, len(s)/4+1)
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return strings.Join(parts, "-")
}

type tokenEntry struct {
	publicKey string
	expiresAt time.Time
}

// TokenStore holds pairing tokens in memory with automatic expiry
// and failed-attempt rate limiting.
type TokenStore struct {
	mu            sync.RWMutex
	tokens        map[string]tokenEntry
	failedCount   int
	cooldownUntil time.Time
}

const maxFailedAttempts = 5

// failedAttemptCooldown is how long all attempts are rejected after
// maxFailedAttempts global failures.
var failedAttemptCooldown = 30 * time.Second

// NewTokenStore creates a new in-memory token store.
func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]tokenEntry),
	}
}

// GenerateToken creates a high-entropy token using crypto/rand.
// Generates 20 random bytes encoded as base32 (no padding) → ~32 characters
// with approximately 160 bits of entropy.
func GenerateToken() (Token, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	// base32 hex encoding is URL-safe, case-insensitive, and readable.
	token := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return Token(token), nil
}

var errInvalidTokenFormat = fmt.Errorf("invalid pairing token format")

// ValidatePairingToken checks that a token string is safe to use in
// file-path construction. It rejects tokens containing path separators,
// null bytes, control characters, or characters outside the base32-hex
// alphabet that GenerateToken produces.
func ValidatePairingToken(token string) error {
	if token == "" {
		return errInvalidTokenFormat
	}
	if len(token) > 64 {
		return errInvalidTokenFormat
	}
	for _, ch := range token {
		switch {
		case ch == '/' || ch == '\\':
			return errInvalidTokenFormat
		case ch == 0:
			return errInvalidTokenFormat
		case unicode.IsControl(ch):
			return errInvalidTokenFormat
		case (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'V') || (ch >= 'a' && ch <= 'v'):
		default:
			return errInvalidTokenFormat
		}
	}
	return nil
}

// Store saves a token with its associated public key and sets expiry.
func (ts *TokenStore) Store(token Token, publicKey string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.tokens[string(token)] = tokenEntry{
		publicKey: publicKey,
		expiresAt: time.Now().Add(TokenTTL),
	}
	return nil
}

// Validate checks a token and returns the associated public key if valid.
// Tokens are single-use: successful validation removes the token.
// After maxFailedAttempts global failures, a cooldown is triggered during
// which all attempts are rejected (defense-in-depth, see #25).
// Returns (publicKey, true) on success, ("", false) if token is invalid, expired,
// or a cooldown is active.
func (ts *TokenStore) Validate(token string) (string, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Global cooldown: after maxFailedAttempts, reject all attempts until
	// the cooldown expires. This prevents brute-force by per-guess keying.
	if ts.failedCount >= maxFailedAttempts && time.Now().Before(ts.cooldownUntil) {
		return "", false
	}

	if ts.failedCount >= maxFailedAttempts && time.Now().After(ts.cooldownUntil) {
		ts.failedCount = 0
	}

	entry, ok := ts.tokens[token]
	if !ok {
		// Token not found — track the failed attempt globally.
		ts.failedCount++
		if ts.failedCount >= maxFailedAttempts {
			ts.cooldownUntil = time.Now().Add(failedAttemptCooldown)
		}
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		// Expired token — count as failed attempt and clean up.
		ts.failedCount++
		delete(ts.tokens, token)
		if ts.failedCount >= maxFailedAttempts {
			ts.cooldownUntil = time.Now().Add(failedAttemptCooldown)
		}
		return "", false
	}

	// Token is valid — single-use, delete immediately.
	publicKey := entry.publicKey
	delete(ts.tokens, token)
	ts.failedCount = 0
	ts.cooldownUntil = time.Time{}
	return publicKey, true
}

// CleanupExpired removes all expired tokens and resets the failed-attempt
// counter once the cooldown has expired.
func (ts *TokenStore) CleanupExpired() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	for token, entry := range ts.tokens {
		if now.After(entry.expiresAt) {
			delete(ts.tokens, token)
		}
	}

	// Reset failed count if cooldown has expired.
	if ts.failedCount >= maxFailedAttempts && now.After(ts.cooldownUntil) {
		ts.failedCount = 0
	}
}
