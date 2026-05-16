package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/danieljustus/OpenPass/internal/fileutil"
)

// randReader is the rand.Reader used for token generation, swappable for tests.
var randReader = rand.Reader

// TokenRegistryFile is the on-disk JSON representation of the token registry.
type TokenRegistryFile struct {
	Version int                           `json:"version"`
	Tokens  map[string]TokenRegistryEntry `json:"tokens"`
}

// TokenRegistryEntry is a single entry in the on-disk token registry.
type TokenRegistryEntry struct {
	ID               string     `json:"id"`
	Label            string     `json:"label,omitempty"`
	Hash             string     `json:"hash"`
	Prefix           string     `json:"prefix"`
	AllowedTools     []string   `json:"allowed_tools"`
	AgentName        string     `json:"agent_name,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	Revoked          bool       `json:"revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RefreshTokenHash string     `json:"refresh_token_hash,omitempty"`
	RefreshExpiresAt *time.Time `json:"refresh_expires_at,omitempty"`
}

// ScopedToken is the in-memory representation of a scoped token with its
// associated metadata. It is safe for concurrent access.
type ScopedToken struct {
	ID               string     `json:"id"`
	Label            string     `json:"label,omitempty"`
	Hash             string     `json:"hash"`
	Prefix           string     `json:"prefix"`
	AllowedTools     []string   `json:"allowed_tools"`
	AgentName        string     `json:"agent_name,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	Revoked          bool       `json:"revoked"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RefreshTokenHash string     `json:"refresh_token_hash,omitempty"`
	RefreshExpiresAt *time.Time `json:"refresh_expires_at,omitempty"`

	mu sync.Mutex
}

// IsExpired returns true if the token has a defined expiration time that has
// already passed. Revoked tokens are not considered expired — they are simply
// invalidated through the Revoked flag.
func (t *ScopedToken) IsExpired() bool {
	if t == nil {
		return true
	}
	if t.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.ExpiresAt)
}

// IsRefreshExpired returns true if the refresh token has a defined expiration
// that has already passed. A nil RefreshExpiresAt means no expiration.
func (t *ScopedToken) IsRefreshExpired() bool {
	if t == nil {
		return true
	}
	if t.RefreshExpiresAt == nil {
		return false
	}
	return time.Now().After(*t.RefreshExpiresAt)
}

// IsToolAllowed returns true when the given tool name is permitted by this
// token. A wildcard "*" in the AllowedTools list grants access to every tool.
func (t *ScopedToken) IsToolAllowed(toolName string) bool {
	if t == nil {
		return false
	}
	for _, allowed := range t.AllowedTools {
		if allowed == "*" {
			return true
		}
		if allowed == toolName {
			return true
		}
	}
	return false
}

// UpdateLastUsed sets the LastUsedAt timestamp to the current time.
func (t *ScopedToken) UpdateLastUsed() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.LastUsedAt = &now
}

// toEntry converts the ScopedToken to a TokenRegistryEntry suitable for
// on-disk persistence.
func (t *ScopedToken) toEntry() TokenRegistryEntry {
	if t == nil {
		return TokenRegistryEntry{}
	}
	return TokenRegistryEntry{
		ID:               t.ID,
		Label:            t.Label,
		Hash:             t.Hash,
		Prefix:           t.Prefix,
		AllowedTools:     t.AllowedTools,
		AgentName:        t.AgentName,
		CreatedAt:        t.CreatedAt,
		ExpiresAt:        t.ExpiresAt,
		LastUsedAt:       t.LastUsedAt,
		Revoked:          t.Revoked,
		RevokedAt:        t.RevokedAt,
		RefreshTokenHash: t.RefreshTokenHash,
		RefreshExpiresAt: t.RefreshExpiresAt,
	}
}

// entryToScopedToken converts an on-disk entry to in-memory ScopedToken.
func entryToScopedToken(e TokenRegistryEntry) *ScopedToken {
	allowed := e.AllowedTools
	if allowed == nil {
		allowed = []string{}
	}
	return &ScopedToken{
		ID:               e.ID,
		Label:            e.Label,
		Hash:             e.Hash,
		Prefix:           e.Prefix,
		AllowedTools:     allowed,
		AgentName:        e.AgentName,
		CreatedAt:        e.CreatedAt,
		ExpiresAt:        e.ExpiresAt,
		LastUsedAt:       e.LastUsedAt,
		Revoked:          e.Revoked,
		RevokedAt:        e.RevokedAt,
		RefreshTokenHash: e.RefreshTokenHash,
		RefreshExpiresAt: e.RefreshExpiresAt,
	}
}

// TokenRegistry provides thread-safe management of scoped MCP tokens backed
// by an on-disk JSON file.
type TokenRegistry struct {
	path        string
	mu          sync.RWMutex
	entries     map[string]*ScopedToken // keyed by token hash
	stopFn      func()                  // stops the background cleanup goroutine
	watchStopFn func()                  // stops the file watcher goroutine
}

// NewTokenRegistry creates a TokenRegistry that loads/saves from the given
// file path. The caller must call Load() to populate the registry from disk.
func NewTokenRegistry(path string) *TokenRegistry {
	return &TokenRegistry{
		path:    path,
		entries: make(map[string]*ScopedToken),
	}
}

// Load reads the JSON registry file from disk and populates the in-memory
// entries. If the file does not exist it is a no-op (empty registry).
func (r *TokenRegistry) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := os.ReadFile(r.path) //#nosec G304 -- path comes from NewTokenRegistry which is controlled
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read token registry: %w", err)
	}

	var file TokenRegistryFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse token registry: %w", err)
	}

	r.entries = make(map[string]*ScopedToken, len(file.Tokens))
	for _, entry := range file.Tokens {
		t := entryToScopedToken(entry)
		if t.Hash != "" {
			r.entries[t.Hash] = t
		}
	}
	return nil
}

// Save persists the current in-memory entries to the JSON registry file with
// 0o600 permissions.
func (r *TokenRegistry) Save() error {
	r.mu.Lock()
	file := TokenRegistryFile{
		Version: 2,
		Tokens:  make(map[string]TokenRegistryEntry, len(r.entries)),
	}
	for _, t := range r.entries {
		file.Tokens[t.ID] = t.toEntry()
	}
	r.mu.Unlock()

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token registry: %w", err)
	}

	if err := fileutil.AtomicWriteFile(r.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write token registry: %w", err)
	}
	return nil
}

// Create generates a new scoped token, stores its hash in the registry, and
// persists to disk. It returns the token metadata and the cleartext raw token
// string. The caller is responsible for presenting the raw token to the user
// — it is never stored on disk.
func (r *TokenRegistry) Create(label string, allowedTools []string, agentName string, ttl time.Duration) (*ScopedToken, string, error) {
	buf := make([]byte, 32)
	if _, err := randReader.Read(buf); err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}
	rawToken := hex.EncodeToString(buf)

	id := generateTokenID()
	hash := sha256Hex(rawToken)
	prefix := rawToken[:4]

	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().UTC().Add(ttl)
		expiresAt = &t
	}

	if allowedTools == nil {
		allowedTools = []string{}
	}

	createdAt := time.Now().UTC()
	t := &ScopedToken{
		ID:           id,
		Label:        label,
		Hash:         hash,
		Prefix:       prefix,
		AllowedTools: allowedTools,
		AgentName:    agentName,
		CreatedAt:    createdAt,
		ExpiresAt:    expiresAt,
	}

	r.mu.Lock()
	r.entries[hash] = t
	r.mu.Unlock()

	if err := r.Save(); err != nil {
		r.mu.Lock()
		delete(r.entries, hash)
		r.mu.Unlock()
		return nil, "", err
	}

	return t, rawToken, nil
}

// Get looks up a scoped token by its SHA-256 hash. It performs a lazy
// expiry check: expired tokens are removed from the registry and treated as
// not found. Revoked tokens are also treated as not found.
func (r *TokenRegistry) Get(hash string) (*ScopedToken, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	t, ok := r.entries[hash]
	if !ok || t == nil {
		return nil, false
	}
	if t.Revoked {
		return nil, false
	}
	if t.IsExpired() {
		delete(r.entries, hash)
		return nil, false
	}
	t.UpdateLastUsed()
	return t, true
}

// Revoke marks a token as revoked by its ID. Returns true if a matching
// (non-revoked) token was found.
func (r *TokenRegistry) Revoke(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, t := range r.entries {
		if t.ID == id && !t.Revoked {
			now := time.Now().UTC()
			t.Revoked = true
			t.RevokedAt = &now
			return true
		}
	}
	return false
}

// getByRefreshTokenHash looks up a token by its refresh token hash. Returns
// nil if not found, revoked, or expired.
func (r *TokenRegistry) getByRefreshTokenHash(refreshHash string) *ScopedToken {
	for _, t := range r.entries {
		if t.RefreshTokenHash == refreshHash && !t.Revoked && !t.IsExpired() {
			return t
		}
	}
	return nil
}

// CreateWithRefresh generates a new access+refresh token pair, stores both
// hashes in the registry, and persists to disk. It returns the token metadata,
// the cleartext access token, and the cleartext refresh token.
func (r *TokenRegistry) CreateWithRefresh(label string, allowedTools []string, agentName string, accessTTL, refreshTTL time.Duration) (*ScopedToken, string, string, error) {
	accessBuf := make([]byte, 32)
	if _, err := randReader.Read(accessBuf); err != nil {
		return nil, "", "", fmt.Errorf("generate access token: %w", err)
	}
	rawAccess := hex.EncodeToString(accessBuf)

	refreshBuf := make([]byte, 32)
	if _, err := randReader.Read(refreshBuf); err != nil {
		return nil, "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	rawRefresh := hex.EncodeToString(refreshBuf)

	id := generateTokenID()
	accessHash := sha256Hex(rawAccess)
	refreshHash := sha256Hex(rawRefresh)
	prefix := rawAccess[:4]

	var expiresAt *time.Time
	if accessTTL > 0 {
		t := time.Now().UTC().Add(accessTTL)
		expiresAt = &t
	}
	var refreshExpiresAt *time.Time
	if refreshTTL > 0 {
		t := time.Now().UTC().Add(refreshTTL)
		refreshExpiresAt = &t
	}

	if allowedTools == nil {
		allowedTools = []string{}
	}

	createdAt := time.Now().UTC()
	t := &ScopedToken{
		ID:               id,
		Label:            label,
		Hash:             accessHash,
		Prefix:           prefix,
		AllowedTools:     allowedTools,
		AgentName:        agentName,
		CreatedAt:        createdAt,
		ExpiresAt:        expiresAt,
		RefreshTokenHash: refreshHash,
		RefreshExpiresAt: refreshExpiresAt,
	}

	r.mu.Lock()
	r.entries[accessHash] = t
	r.mu.Unlock()

	if err := r.Save(); err != nil {
		r.mu.Lock()
		delete(r.entries, accessHash)
		r.mu.Unlock()
		return nil, "", "", err
	}

	return t, rawAccess, rawRefresh, nil
}

// RotateViaRefreshToken revokes the old access token associated with the given
// refresh token and creates a new access+refresh token pair. The old refresh
// token is also invalidated (single-use pattern). Returns the new token
// metadata, raw access token, and raw refresh token.
func (r *TokenRegistry) RotateViaRefreshToken(rawRefreshToken string) (*ScopedToken, string, string, error) {
	refreshHash := sha256Hex(rawRefreshToken)

	r.mu.Lock()

	oldEntry := r.getByRefreshTokenHash(refreshHash)
	if oldEntry == nil {
		r.mu.Unlock()
		return nil, "", "", fmt.Errorf("invalid refresh token")
	}

	if oldEntry.IsRefreshExpired() {
		r.mu.Unlock()
		return nil, "", "", fmt.Errorf("invalid refresh token: expired")
	}

	oldEntry.Revoked = true
	now := time.Now().UTC()
	oldEntry.RevokedAt = &now

	r.mu.Unlock()

	var accessTTL, refreshTTL time.Duration
	if oldEntry.ExpiresAt != nil {
		accessTTL = time.Until(*oldEntry.ExpiresAt)
		if accessTTL < 0 {
			accessTTL = 0
		}
	}
	if oldEntry.RefreshExpiresAt != nil {
		refreshTTL = time.Until(*oldEntry.RefreshExpiresAt)
		if refreshTTL < 0 {
			refreshTTL = 0
		}
	}

	newTok, rawAccess, rawRefresh, err := r.CreateWithRefresh(
		oldEntry.Label,
		oldEntry.AllowedTools,
		oldEntry.AgentName,
		accessTTL,
		refreshTTL,
	)
	if err != nil {
		return nil, "", "", fmt.Errorf("rotate via refresh: %w", err)
	}

	return newTok, rawAccess, rawRefresh, nil
}

// List returns a snapshot of all tokens currently in the registry. Expired
// tokens are excluded and removed; revoked tokens are included for the audit
// trail.
func (r *TokenRegistry) List() []*ScopedToken {
	r.mu.Lock()
	defer r.mu.Unlock()

	for hash, t := range r.entries {
		if t.IsExpired() {
			delete(r.entries, hash)
		}
	}

	result := make([]*ScopedToken, 0, len(r.entries))
	for _, t := range r.entries {
		result = append(result, t)
	}
	return result
}

// StartCleanup launches a background goroutine that periodically calls
// cleanupOnce at the given interval. It returns a stop function that cancels
// the goroutine and a final cleanup run.
func (r *TokenRegistry) StartCleanup(ctx context.Context, interval time.Duration) func() {
	stopCh := make(chan struct{})
	r.stopFn = func() { close(stopCh) }

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.cleanupOnce()
			case <-stopCh:
				r.cleanupOnce()
				return
			case <-ctx.Done():
				r.cleanupOnce()
				return
			}
		}
	}()
	return r.stopFn
}

// cleanupOnce performs a single sweep that removes expired tokens.
func (r *TokenRegistry) cleanupOnce() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for hash, t := range r.entries {
		if t.IsExpired() {
			delete(r.entries, hash)
		}
	}
}

// StartFileWatcher begins polling the registry file's modification time at the
// given interval and reloads the registry whenever the file changes. It returns
// a stop function. The goroutine terminates when ctx is canceled or the stop
// function is called.
func (r *TokenRegistry) StartFileWatcher(ctx context.Context, interval time.Duration) func() {
	stopCh := make(chan struct{})

	var lastModTime time.Time
	fi, err := os.Stat(r.path)
	if err == nil {
		lastModTime = fi.ModTime()
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fi, err := os.Stat(r.path)
				if err != nil {
					continue
				}
				mt := fi.ModTime()
				if mt.After(lastModTime) {
					lastModTime = mt
					if err := r.Load(); err != nil {
						fmt.Fprintf(os.Stderr, "error reloading token registry from %s: %v\n", r.path, err)
					}
				}
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	stopFn := func() { close(stopCh) }
	r.mu.Lock()
	r.watchStopFn = stopFn
	r.mu.Unlock()
	return stopFn
}

// Close shuts down the background cleanup and file watcher goroutines if they
// are running.
func (r *TokenRegistry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopFn != nil {
		r.stopFn()
		r.stopFn = nil
	}
	if r.watchStopFn != nil {
		r.watchStopFn()
		r.watchStopFn = nil
	}
	return nil
}

// generateTokenID creates a human-readable token identifier in the format
// tok-<YYYYMMDD>-<8 random hex chars>.
func generateTokenID() string {
	buf := make([]byte, 4)
	n, err := randReader.Read(buf)
	if err != nil {
		// Fallback: use nanoseconds to still produce a unique-ish ID.
		return fmt.Sprintf("tok-%s-fallback%x", time.Now().UTC().Format("20060102"), time.Now().UnixNano())
	}
	_ = n
	return fmt.Sprintf("tok-%s-%x", time.Now().UTC().Format("20060102"), buf)
}

// GenerateTokenID is the exported alias for generateTokenID.
func GenerateTokenID() string {
	return generateTokenID()
}

// sha256Hex returns the lowercase hex-encoded SHA-256 digest of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TokenRegistryFilePath returns the path to the scoped-token registry file for
// the given vault directory.
func TokenRegistryFilePath(vaultDir string) string {
	return filepath.Join(vaultDir, "mcp-tokens.json")
}

// LoadTokenSystem tries to load the scoped token registry from
// <vaultDir>/mcp-tokens.json. If that file does not exist it falls back to the
// legacy single-token file and transparently seeds a new registry with one
// wildcard-allowing entry. An optional customLegacyPath can be provided to
// override the default <vaultDir>/mcp-token location. The returned string is
// the raw legacy token (empty when the new registry is used).
func LoadTokenSystem(vaultDir string, customLegacyPath ...string) (*TokenRegistry, string, error) {
	regPath := TokenRegistryFilePath(vaultDir)
	reg := NewTokenRegistry(regPath)

	if err := reg.Load(); err != nil {
		return nil, "", err
	}

	// If the registry already has entries, return it (new mode).
	if len(reg.entries) > 0 {
		return reg, "", nil
	}

	legacyPath := TokenFilePath(vaultDir)
	if len(customLegacyPath) > 0 && customLegacyPath[0] != "" {
		legacyPath = customLegacyPath[0]
	}

	legacyToken, err := LoadOrCreateToken(legacyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load legacy token: %w", err)
	}

	// If the legacy token was loaded from an existing file (not just
	// generated), seed the registry so we can migrate transparently.
	legacyData, readErr := os.ReadFile(legacyPath) //#nosec G304
	if readErr == nil && strings.TrimSpace(string(legacyData)) != "" {
		hash := sha256Hex(legacyToken)
		prefix := legacyToken[:4]
		if _, exists := reg.Get(hash); !exists {
			id := generateTokenID()
			entry := &ScopedToken{
				ID:           id,
				Label:        "legacy (auto-migrated, unscoped)",
				Hash:         hash,
				Prefix:       prefix,
				AllowedTools: []string{"*"},
				AgentName:    "legacy",
				CreatedAt:    time.Now().UTC(),
			}
			reg.mu.Lock()
			reg.entries[hash] = entry
			reg.mu.Unlock()

			// Save-then-delete: never destroy the old credential before the
			// new one is committed. On save failure the legacy file is kept
			// so the next restart can retry.
			if saveErr := reg.Save(); saveErr == nil {
				// Loud, one-time warning: the legacy token was migrated with
				// wildcard tool scope. Operators should rotate it via
				// `openpass mcp token create` with an explicit allow-list and
				// then revoke the legacy entry.
				fmt.Fprintf(os.Stderr,
					"WARNING: legacy MCP token migrated to scoped registry with wildcard (*) tool access (id=%s).\n"+
						"         To restrict scope, run: openpass mcp token create --label <name> --tools <list>\n"+
						"         Then revoke the legacy token: openpass mcp token revoke %s\n",
					id, id)
				if rmErr := fileutil.SafeRemove(legacyPath); rmErr != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to remove legacy token file %s after migration: %v\n", legacyPath, rmErr)
				}
			}
		}
	}
	return reg, legacyToken, nil
}

// LoadOrCreateToken reads a token from path, or generates a new one if the
// file is missing or empty. If OPENPASS_MCP_TOKEN is set in the environment
// (and no file token exists), the environment value is returned.
func LoadOrCreateToken(path string) (string, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- path comes from TokenFilePath() which uses filepath.Join on vaultDir
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			if envToken := os.Getenv("OPENPASS_MCP_TOKEN"); envToken != "" {
				fmt.Fprintf(os.Stderr, "Warning: OPENPASS_MCP_TOKEN is set but file token exists at %s; using file token\n", path)
			}
			return token, nil
		}
	}

	if envToken := os.Getenv("OPENPASS_MCP_TOKEN"); envToken != "" {
		return envToken, nil
	}

	buf := make([]byte, 32)
	if _, err := randReader.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(buf)

	if err := fileutil.AtomicWriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write token file: %w", err)
	}

	return token, nil
}

// RotateToken generates a new token and writes it to the token file.
// This invalidates the previous token - any MCP clients using the old token
// will need to be updated with the new token.
func RotateToken(path string) (string, error) {
	buf := make([]byte, 32)
	if _, err := randReader.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(buf)

	if err := fileutil.AtomicWriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("write token file: %w", err)
	}

	return token, nil
}

// TokenFilePath returns the default token file path for a vault directory.
func TokenFilePath(vaultDir string) string {
	return filepath.Join(vaultDir, "mcp-token")
}
