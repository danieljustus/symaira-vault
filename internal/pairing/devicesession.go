// Package pairing provides device pairing and device-session token management.
//
// DeviceSessionStore is a long-lived, multi-use, per-device revocable token
// store persisted to disk. It is populated by device enrolment (device accept)
// and survives server restarts.
package pairing

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
)

const (
	// DefaultSessionTTL is the default TTL for enrolled device sessions.
	DefaultSessionTTL = 90 * 24 * time.Hour // 90 days
	// MaxSessionFailedAttempts is the number of failed validation attempts
	// allowed per device before a cooldown is applied.
	MaxSessionFailedAttempts = 5
	// SessionFailedAttemptCooldown is how long a device's attempts are
	// rejected after MaxSessionFailedAttempts failures.
	SessionFailedAttemptCooldown = 30 * time.Second
)

// DeviceSession represents an enrolled device session token. The bearer
// token itself is never persisted — only its SHA-256 hash, keyed identically
// to internal/mcp/auth's scoped-token registry, plus Prefix (the first few
// characters of the raw token) for display in "approval-list".
type DeviceSession struct {
	Prefix    string    `json:"prefix"`
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name,omitempty"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// deviceFailure tracks failed validation attempts for a single device.
type deviceFailure struct {
	Count         int
	CooldownUntil time.Time
}

// DeviceSessionStore holds long-lived device session tokens on disk.
// It is safe for concurrent use.
type DeviceSessionStore struct {
	path     string
	mu       sync.RWMutex
	sessions map[string]*DeviceSession // sha256Hex(token) -> session
	failures map[string]deviceFailure  // deviceID -> failure state
	mtime    time.Time                 // mtime of path as of the last load/save
}

// NewDeviceSessionStore loads the device session store from vaultDir.
// It creates the file if it does not exist. The store file lives at
// <vaultDir>/.symvault/device-sessions.json.
func NewDeviceSessionStore(vaultDir string) (*DeviceSessionStore, error) {
	if vaultDir == "" {
		return &DeviceSessionStore{
			sessions: make(map[string]*DeviceSession),
			failures: make(map[string]deviceFailure),
		}, nil
	}
	path := filepath.Join(vaultDir, config.DefaultVaultSubdir, "device-sessions.json")
	s := &DeviceSessionStore{
		path:     path,
		sessions: make(map[string]*DeviceSession),
		failures: make(map[string]deviceFailure),
	}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("load device session store: %w", err)
	}
	return s, nil
}

// Enroll creates a new long-lived session token for deviceID with the given
// human-readable name and publicKey. The raw token is returned to the caller
// and never persisted — only its hash (see hashToken) is stored.
func (s *DeviceSessionStore) Enroll(deviceID, name, publicKey string) (string, error) {
	token, err := GenerateSessionToken()
	if err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	rawToken := token.String()
	hash := hashToken(rawToken)
	now := time.Now().UTC()
	session := &DeviceSession{
		Prefix:    tokenPrefix(rawToken),
		DeviceID:  deviceID,
		Name:      name,
		PublicKey: publicKey,
		CreatedAt: now,
		ExpiresAt: now.Add(DefaultSessionTTL),
	}
	s.mu.Lock()
	s.sessions[hash] = session
	s.mu.Unlock()
	if err := s.save(); err != nil {
		delete(s.sessions, hash)
		return "", fmt.Errorf("persist device session: %w", err)
	}
	return rawToken, nil
}

// List returns a snapshot of every session in the store, including revoked
// and expired ones, for display in a device-management UI. Callers that only
// want live sessions should filter on Revoked and ExpiresAt themselves.
func (s *DeviceSessionStore) List() []DeviceSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DeviceSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		out = append(out, *session)
	}
	return out
}

// Validate checks a session token and returns the deviceID if the session
// is valid (not revoked, not expired, device not in cooldown).
// Successful validation resets the device's failure counter.
func (s *DeviceSessionStore) Validate(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mergeRevocationsFromDisk()

	session, ok := s.sessions[hashToken(token)]
	if !ok {
		return "", false
	}
	if session.Revoked {
		return "", false
	}
	if time.Now().After(session.ExpiresAt) {
		return "", false
	}

	f, hasFailures := s.failures[session.DeviceID]
	if hasFailures && time.Now().Before(f.CooldownUntil) {
		return "", false
	}
	if hasFailures && time.Now().After(f.CooldownUntil) {
		delete(s.failures, session.DeviceID)
	}

	s.failures[session.DeviceID] = deviceFailure{}
	return session.DeviceID, true
}

// RecordFailure records a validation failure for the device associated with
// the token. If the token is unknown, no failure is recorded (unknown-token
// brute-force is bounded by the store's file-read path and the validator's
// caller).
func (s *DeviceSessionStore) RecordFailure(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mergeRevocationsFromDisk()

	session, ok := s.sessions[hashToken(token)]
	if !ok {
		return
	}
	f := s.failures[session.DeviceID]
	f.Count++
	if f.Count >= MaxSessionFailedAttempts {
		f.CooldownUntil = time.Now().Add(SessionFailedAttemptCooldown)
	}
	s.failures[session.DeviceID] = f
	_ = s.save()
}

// Revoke revokes all sessions for deviceID.
func (s *DeviceSessionStore) Revoke(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	changed := s.mergeRevocationsFromDisk()
	for _, session := range s.sessions {
		if session.DeviceID == deviceID && !session.Revoked {
			session.Revoked = true
			changed = true
		}
	}
	if changed {
		_ = s.save()
	}
}

// RevokeAll revokes every session in the store.
func (s *DeviceSessionStore) RevokeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mergeRevocationsFromDisk()
	for _, session := range s.sessions {
		if !session.Revoked {
			session.Revoked = true
		}
	}
	_ = s.save()
}

// CleanupExpired removes expired sessions and resets stale device failure
// counters.
func (s *DeviceSessionStore) CleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	changed := s.mergeRevocationsFromDisk()

	now := time.Now()
	for token, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, token)
			changed = true
		}
	}
	for deviceID, f := range s.failures {
		if f.Count >= MaxSessionFailedAttempts && now.After(f.CooldownUntil) {
			delete(s.failures, deviceID)
			changed = true
		}
	}
	if changed {
		_ = s.save()
	}
}

// Save persists the store to disk.
func (s *DeviceSessionStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save()
}

// StartCleanup runs a periodic cleanup bound to ctx. It returns a stop
// function.
func (s *DeviceSessionStore) StartCleanup(ctx context.Context, interval time.Duration) func() {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.CleanupExpired()
			case <-stopCh:
				s.CleanupExpired()
				return
			case <-ctx.Done():
				s.CleanupExpired()
				return
			}
		}
	}()
	return func() {
		close(stopCh)
		<-doneCh
	}
}

func (s *DeviceSessionStore) load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.save()
		}
		return err
	}
	var raw map[string]*DeviceSession
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse device sessions: %w", err)
	}

	// Migrate legacy entries keyed by the raw bearer token (from before
	// tokens were hashed at rest) to hash-keyed entries. A legacy key is the
	// base32 session token itself, which never looks like a SHA-256 hex
	// digest.
	migrated := false
	sessions := make(map[string]*DeviceSession, len(raw))
	for key, session := range raw {
		if session == nil {
			continue
		}
		if looksLikeSHA256Hex(key) {
			sessions[key] = session
			continue
		}
		if session.Prefix == "" {
			session.Prefix = tokenPrefix(key)
		}
		sessions[hashToken(key)] = session
		migrated = true
	}
	s.sessions = sessions
	if info, statErr := os.Stat(s.path); statErr == nil {
		s.mtime = info.ModTime()
	}
	if migrated {
		return s.save()
	}
	return nil
}

func (s *DeviceSessionStore) save() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.sessions, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if info, statErr := os.Stat(s.path); statErr == nil {
		s.mtime = info.ModTime()
	}
	return nil
}

// mergeRevocationsFromDisk re-reads the on-disk store when it is newer than
// the last load/save this instance observed, and applies any revocation
// found there onto the in-memory copy. Revocation only ever moves from false
// to true here, so a concurrent writer (typically the "approval-revoke" CLI,
// which opens its own store instance against the same file) can never have
// its revocation silently undone by this instance's next save. Callers must
// hold s.mu for writing. Returns whether any in-memory session was newly
// marked revoked.
func (s *DeviceSessionStore) mergeRevocationsFromDisk() bool {
	if s.path == "" {
		return false
	}
	info, err := os.Stat(s.path)
	if err != nil || !info.ModTime().After(s.mtime) {
		return false
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return false
	}
	var onDisk map[string]*DeviceSession
	if err := json.Unmarshal(data, &onDisk); err != nil {
		return false
	}
	changed := false
	for token, diskSession := range onDisk {
		if diskSession == nil || !diskSession.Revoked {
			continue
		}
		if mem, ok := s.sessions[token]; ok && !mem.Revoked {
			mem.Revoked = true
			changed = true
		}
	}
	s.mtime = info.ModTime()
	return changed
}

// GenerateSessionToken creates a high-entropy session token.
func GenerateSessionToken() (Token, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return Token(token), nil
}

// tokenPrefixLen is how many characters of the raw token are kept as the
// display-only Prefix, matching internal/mcp/auth.TokenData's Prefix
// convention (see TokenRegistry.Create).
const tokenPrefixLen = 4

// hashToken returns the storage key for rawToken: the same SHA-256 hex
// scheme internal/mcp/auth's scoped-token registry stores its own bearer
// tokens under, so a leaked backup or vault-dir read yields no usable
// credential — only whoever presents the matching raw token again can be
// looked up.
func hashToken(rawToken string) string {
	return auth.SHA256Hex(rawToken)
}

// tokenPrefix returns the short, non-secret display prefix stored alongside
// a hashed session so "approval-list" can show which device is which
// without ever persisting the usable token.
func tokenPrefix(rawToken string) string {
	if len(rawToken) <= tokenPrefixLen {
		return rawToken
	}
	return rawToken[:tokenPrefixLen]
}

// looksLikeSHA256Hex reports whether s has the shape of a lowercase
// hex-encoded SHA-256 digest (64 hex characters), used to distinguish
// already-hashed storage keys from legacy keys that are still the raw
// base32 session token itself (see (*DeviceSessionStore).load).
func looksLikeSHA256Hex(s string) bool {
	if len(s) != hex.EncodedLen(sha256DigestSize) {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// sha256DigestSize is the size in bytes of a SHA-256 digest.
const sha256DigestSize = 32
