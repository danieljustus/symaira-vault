// Package pairing provides device pairing token generation and management.
//
// # Transport-independent pairing handshake
//
// The pairing exchange is deliberately separated from any transport. The
// exchange consists of two JSON artifacts that any channel can carry — a git
// remote, a synced folder (iCloud Drive), or a QR / manual copy exchange:
//
//  1. The existing device writes <token>.json (PairingFile) containing its
//     public key and shares the file with the joining device.
//  2. The joining device reads the file, generates its own keypair, and
//     writes <token>-response.json (JoinResponse) containing its public key
//     back to the same channel. In the git flow this artifact is written as
//     <token>-joined.json inside the vault; the two names are aliases for
//     the same response format so both transports interoperate.
//  3. The existing device runs `device accept <token>`, which reads either
//     name, re-encrypts all entries for the new recipient, and removes the
//     artifacts.
//
// Nothing in this package performs I/O on a transport: callers decide how
// the files travel. See cmd/device.go for the git-based wiring and ADR 0006
// (D1) for the mobile rationale.
package pairing

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
)

// PairingFile is the invitation artifact written by the existing device
// (`device pair`). Any transport that can deliver this file to the joining
// device is sufficient; no git remote is required.
type PairingFile struct {
	Token     string    `json:"token"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

// JoinResponse is the response artifact written by the joining device
// after it has read the PairingFile and generated its own identity.
// On the git transport it is stored as `<token>-joined.json`; other
// transports may use `<token>-response.json`. Both names are accepted by
// `device accept`.
type JoinResponse struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

// ResponseFilenames returns the canonical filenames under which the join
// response may be found for a token, in lookup order.
func ResponseFilenames(token string) []string {
	return []string{token + "-joined.json", token + "-response.json"}
}

// MarshalPairingFile serializes a PairingFile for exchange over any channel.
func MarshalPairingFile(pf PairingFile) ([]byte, error) {
	b, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal pairing file: %w", err)
	}
	return b, nil
}

// ParsePairingFile parses an invitation artifact received over any channel.
func ParsePairingFile(data []byte) (PairingFile, error) {
	var pf PairingFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return PairingFile{}, fmt.Errorf("parse pairing file: %w", err)
	}
	return pf, nil
}

// ParseJoinResponse parses a response artifact received over any channel.
func ParseJoinResponse(data []byte) (JoinResponse, error) {
	var jr JoinResponse
	if err := json.Unmarshal(data, &jr); err != nil {
		return JoinResponse{}, fmt.Errorf("parse join response: %w", err)
	}
	return jr, nil
}

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
