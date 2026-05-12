// Package pairing provides device pairing token generation and management.
package pairing

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"sync"
	"time"
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
	mu             sync.RWMutex
	tokens         map[string]tokenEntry
	failedAttempts map[string]int
}

// NewTokenStore creates a new in-memory token store.
func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens:         make(map[string]tokenEntry),
		failedAttempts: make(map[string]int),
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
// After 5 failed attempts for a given token, it is burned (deleted from the store).
// Returns (publicKey, true) on success, ("", false) if token is invalid, expired, or burned.
func (ts *TokenStore) Validate(token string) (string, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry, ok := ts.tokens[token]
	if !ok {
		// Token not found — track the failed attempt.
		ts.failedAttempts[token]++
		if ts.failedAttempts[token] >= 5 {
			// Burn: remove tracking data (token was never in store or already deleted).
			delete(ts.failedAttempts, token)
		}
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		// Expired token — count as failed attempt and clean up.
		ts.failedAttempts[token]++
		delete(ts.tokens, token)
		if ts.failedAttempts[token] >= 5 {
			delete(ts.failedAttempts, token)
		}
		return "", false
	}

	// Token is valid — single-use, delete immediately.
	publicKey := entry.publicKey
	delete(ts.tokens, token)
	delete(ts.failedAttempts, token)
	return publicKey, true
}

// CleanupExpired removes all expired tokens and stale failed-attempt tracking
// from the store.
func (ts *TokenStore) CleanupExpired() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	for token, entry := range ts.tokens {
		if now.After(entry.expiresAt) {
			delete(ts.tokens, token)
			delete(ts.failedAttempts, token)
		}
	}
}
