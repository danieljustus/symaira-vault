// Package pairing provides device pairing token generation and management.
package pairing

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"
)

const tokenTTL = 15 * time.Minute

type tokenEntry struct {
	publicKey string
	expiresAt time.Time
}

// TokenStore holds pairing tokens in memory with automatic expiry.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]tokenEntry
}

// NewTokenStore creates a new in-memory token store.
func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]tokenEntry),
	}
}

// GenerateToken creates a 6-digit numeric token using crypto/rand.
func GenerateToken() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// Store saves a token with its associated public key and sets expiry.
func (ts *TokenStore) Store(token, publicKey string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.tokens[token] = tokenEntry{
		publicKey: publicKey,
		expiresAt: time.Now().Add(tokenTTL),
	}
	return nil
}

// Validate checks a token and returns the associated public key if valid.
// Tokens are single-use: successful validation removes the token.
// Returns (publicKey, true) on success, ("", false) if token is invalid or expired.
func (ts *TokenStore) Validate(token string) (string, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry, ok := ts.tokens[token]
	if !ok {
		return "", false
	}

	if time.Now().After(entry.expiresAt) {
		delete(ts.tokens, token)
		return "", false
	}

	publicKey := entry.publicKey
	delete(ts.tokens, token)
	return publicKey, true
}

// CleanupExpired removes all expired tokens from the store.
func (ts *TokenStore) CleanupExpired() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	for token, entry := range ts.tokens {
		if now.After(entry.expiresAt) {
			delete(ts.tokens, token)
		}
	}
}
