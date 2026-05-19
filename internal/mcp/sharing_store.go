package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"

	openpasscrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/fileutil"
)

const shareStoreVersion = 1

// shareStoreFile is the on-disk JSON representation of the share store.
type shareStoreFile struct {
	Version int          `json:"version"`
	Grants  []ShareGrant `json:"grants"`
}

// ShareStore provides thread-safe management of secret share grants backed
// by an on-disk JSON file.
type ShareStore struct {
	path       string
	mu         sync.RWMutex
	grants     map[string]*ShareGrant // keyed by grant ID
	version    int
	signingKey []byte
	stopFn     func()
}

// NewShareStore creates a ShareStore that loads/saves from the given file
// path. The caller must call Load() to populate the store from disk.
func NewShareStore(path string) *ShareStore {
	return &ShareStore{
		path:    path,
		grants:  make(map[string]*ShareGrant),
		version: shareStoreVersion,
	}
}

// SetSigningKey sets the HMAC signing key used to generate and verify
// cryptographically bound grant IDs. If the key is nil, grants will use
// random hex IDs instead of HMAC-based IDs (backward compatibility mode).
func (s *ShareStore) SetSigningKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signingKey = key
}

// InitSigningKey loads or creates the grant signing key from the OS keyring
// (with memory fallback). This should be called once after creating the store.
// Returns the loaded key, or nil if the keyring is unavailable (the store will
// fall back to non-HMAC IDs without error).
// The identity parameter is used by the fallback keystore for encrypting
// keys at rest and is ignored on OS keyring platforms.
func (s *ShareStore) InitSigningKey(vaultDir string, identity *age.X25519Identity) ([]byte, error) {
	key, err := LoadOrCreateGrantSigningKey(vaultDir, identity)
	if err != nil {
		return nil, err
	}
	s.SetSigningKey(key)
	return key, nil
}

// randomGrantID generates a random hex string for use as a grant ID when no
// signing key is configured (backward compatibility mode for existing tests
// and legacy grants).
func randomGrantID() string {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		// Cryptographic randomness is expected to always succeed on modern systems.
		// Fall back to a timestamp-based ID if it somehow fails.
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// Load reads the JSON share store file from disk and populates the in-memory
// grants. If the file does not exist it is a no-op (empty store).
func (s *ShareStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path) //#nosec G304 -- path comes from NewShareStore which is controlled
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read share store: %w", err)
	}

	var file shareStoreFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse share store: %w", err)
	}

	s.grants = make(map[string]*ShareGrant, len(file.Grants))
	for i := range file.Grants {
		g := &file.Grants[i]
		if g.ID != "" {
			s.grants[g.ID] = g
		}
	}
	return nil
}

// Save persists the current in-memory grants to the JSON store file with
// 0o600 permissions.
func (s *ShareStore) Save() error {
	s.mu.Lock()
	file := shareStoreFile{
		Version: shareStoreVersion,
		Grants:  make([]ShareGrant, 0, len(s.grants)),
	}
	for _, g := range s.grants {
		file.Grants = append(file.Grants, *g)
	}
	s.mu.Unlock()

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal share store: %w", err)
	}

	if err := fileutil.AtomicWriteFile(s.path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write share store: %w", err)
	}
	return nil
}

// Create creates a new share grant in pending status and persists to disk.
// If TTL > 0, the grant's ExpiresAt is set relative to creation time.
// Returns the created grant.
//
// If a signing key has been set via SetSigningKey or InitSigningKey, the
// grant ID is a cryptographically bound HMAC-SHA256 hash of the grant fields
// plus a random nonce. Otherwise a random hex ID is used (legacy mode).
func (s *ShareStore) Create(fromAgent, toAgent, secretPath, secretField string, ttl time.Duration) (*ShareGrant, error) {
	createdAt := time.Now().UTC()

	var expiresAt *time.Time
	if ttl > 0 {
		t := createdAt.Add(ttl)
		expiresAt = &t
	}

	g := &ShareGrant{
		FromAgent:   fromAgent,
		ToAgent:     toAgent,
		SecretPath:  secretPath,
		SecretField: secretField,
		Status:      SharePending,
		CreatedAt:   createdAt,
		ExpiresAt:   expiresAt,
		TTL:         ttl,
	}

	s.mu.RLock()
	key := s.signingKey
	s.mu.RUnlock()

	if len(key) > 0 {
		grantID, err := newHMACGrantID(g, key)
		if err != nil {
			return nil, fmt.Errorf("generate hmac grant id: %w", err)
		}
		g.ID = grantID
	} else {
		g.ID = randomGrantID()
	}

	s.mu.Lock()
	s.grants[g.ID] = g
	s.mu.Unlock()

	if err := s.Save(); err != nil {
		s.mu.Lock()
		delete(s.grants, g.ID)
		s.mu.Unlock()
		return nil, err
	}

	return g, nil
}

// newHMACGrantID creates an HMAC-bound grant ID from the grant's fields.
func newHMACGrantID(g *ShareGrant, key []byte) (string, error) {
	fields := openpasscrypto.GrantIDFields{
		FromAgent:   g.FromAgent,
		ToAgent:     g.ToAgent,
		SecretPath:  g.SecretPath,
		SecretField: g.SecretField,
		CreatedAt:   g.CreatedAt,
	}

	grantID, err := openpasscrypto.GenerateGrantID(fields, key)
	if err != nil {
		return "", err
	}

	// Store the nonce on the grant for reference.
	nonce, parseErr := openpasscrypto.ParseNonceFromID(grantID)
	if parseErr == nil {
		g.Nonce = nonce
	}

	return grantID, nil
}

// Get retrieves a grant by its ID. Returns the grant and true if found.
func (s *ShareStore) Get(id string) (*ShareGrant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	g, ok := s.grants[id]
	if !ok || g == nil {
		return nil, false
	}
	return g, true
}

// Approve marks a pending grant as approved. If the grant has a TTL > 0,
// ExpiresAt is set relative to the approval time. approvedBy records who
// approved the grant.
func (s *ShareStore) Approve(id string, approvedBy string) error {
	s.mu.Lock()
	g, ok := s.grants[id]
	if !ok || g == nil {
		s.mu.Unlock()
		return fmt.Errorf("share grant %s not found", id)
	}
	if g.Status != SharePending {
		s.mu.Unlock()
		return fmt.Errorf("share grant %s is not pending (status: %s)", id, g.Status)
	}

	now := time.Now().UTC()
	g.Status = ShareApproved
	g.ApprovedAt = &now
	g.ApprovedBy = approvedBy
	if g.TTL > 0 {
		exp := now.Add(g.TTL)
		g.ExpiresAt = &exp
	}
	s.mu.Unlock()

	return s.Save()
}

// Revoke marks a grant as revoked. Only pending or approved grants can be
// revoked; already revoked grants return an error.
func (s *ShareStore) Revoke(id string) error {
	s.mu.Lock()
	g, ok := s.grants[id]
	if !ok || g == nil {
		s.mu.Unlock()
		return fmt.Errorf("share grant %s not found", id)
	}
	if g.Status == ShareRevoked || g.Status == ShareRejected {
		s.mu.Unlock()
		return fmt.Errorf("share grant %s cannot be revoked (status: %s)", id, g.Status)
	}

	now := time.Now().UTC()
	g.Status = ShareRevoked
	g.RevokedAt = &now
	s.mu.Unlock()

	return s.Save()
}

// Reject marks a pending grant as rejected.
func (s *ShareStore) Reject(id string) error {
	s.mu.Lock()
	g, ok := s.grants[id]
	if !ok || g == nil {
		s.mu.Unlock()
		return fmt.Errorf("share grant %s not found", id)
	}
	if g.Status != SharePending {
		s.mu.Unlock()
		return fmt.Errorf("share grant %s is not pending (status: %s)", id, g.Status)
	}

	g.Status = ShareRejected
	s.mu.Unlock()

	return s.Save()
}

// List returns all grants, optionally filtered by the first provided
// ShareFilter. When no filter is supplied, all grants are returned.
func (s *ShareStore) List(filters ...ShareFilter) []*ShareGrant {
	s.mu.RLock()
	result := make([]*ShareGrant, 0, len(s.grants))
	for _, g := range s.grants {
		result = append(result, g)
	}
	s.mu.RUnlock()

	if len(filters) == 0 {
		return result
	}

	filter := filters[0]
	filtered := make([]*ShareGrant, 0, len(result))
	for _, g := range result {
		if filter.Status != nil && g.Status != *filter.Status {
			continue
		}
		if filter.FromAgent != "" && g.FromAgent != filter.FromAgent {
			continue
		}
		if filter.ToAgent != "" && g.ToAgent != filter.ToAgent {
			continue
		}
		if filter.SecretPath != "" && g.SecretPath != filter.SecretPath {
			continue
		}
		filtered = append(filtered, g)
	}
	return filtered
}

// ListForAgent returns all grants where the given agent name appears as
// either the FromAgent or the ToAgent.
func (s *ShareStore) ListForAgent(agentName string) []*ShareGrant {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ShareGrant, 0)
	for _, g := range s.grants {
		if g.FromAgent == agentName || g.ToAgent == agentName {
			result = append(result, g)
		}
	}
	return result
}

// CheckAccess verifies whether toAgent has an approved, non-expired share
// grant for the given secretPath. Returns the matching grant if found.
//
// For grants with HMAC-format IDs (nonce:hmac), the HMAC is verified before
// returning the grant. If verification fails (tampered/forged grant), the
// grant is treated as invalid and a security event is logged. Legacy UUID
// grants are returned without HMAC verification.
func (s *ShareStore) CheckAccess(toAgent, secretPath string) (*ShareGrant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, g := range s.grants {
		if g.ToAgent == toAgent && g.SecretPath == secretPath && g.Status == ShareApproved && !g.IsExpired() {
			// Verify HMAC for cryptographically bound grants.
			if openpasscrypto.IsHMACFormat(g.ID) {
				if len(s.signingKey) == 0 {
					slog.Warn("cannot verify HMAC grant: signing key not configured",
						"grant_id", g.ID, "to_agent", toAgent)
					continue
				}
				if !verifyGrantHMAC(g, s.signingKey) {
					slog.Warn("security: grant HMAC verification failed (possible forgery)",
						"grant_id", g.ID, "to_agent", toAgent, "from_agent", g.FromAgent,
						"secret_path", g.SecretPath)
					continue
				}
			}
			return g, true
		}
	}
	return nil, false
}

// verifyGrantHMAC returns true if the grant's HMAC ID is valid for its
// current fields using the given key.
func verifyGrantHMAC(g *ShareGrant, key []byte) bool {
	fields := openpasscrypto.GrantIDFields{
		FromAgent:   g.FromAgent,
		ToAgent:     g.ToAgent,
		SecretPath:  g.SecretPath,
		SecretField: g.SecretField,
		CreatedAt:   g.CreatedAt,
	}
	valid, err := openpasscrypto.VerifyGrantID(g.ID, fields, key)
	if err != nil {
		return false
	}
	return valid
}

// CleanupExpired iterates all grants and removes those whose ExpiresAt has
// passed. Returns the number of grants removed. Removal is in-memory only;
// the next Save persists the change.
func (s *ShareStore) CleanupExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed int
	for id, g := range s.grants {
		if g.IsExpired() {
			delete(s.grants, id)
			removed++
		}
	}
	return removed
}

// StartCleanup launches a background goroutine that periodically calls
// CleanupExpired at the given interval. It returns a function that stops the
// goroutine and performs a final cleanup run.
func (s *ShareStore) StartCleanup(ctx context.Context, interval time.Duration) func() {
	stopCh := make(chan struct{})
	s.mu.Lock()
	s.stopFn = func() { close(stopCh) }
	s.mu.Unlock()

	go func() {
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
	return s.stopFn
}

// Close shuts down the background cleanup goroutine if one is running.
func (s *ShareStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopFn != nil {
		s.stopFn()
		s.stopFn = nil
	}
	return nil
}

// ShareStoreFilePath returns the default path for the share store JSON file
// inside a vault directory.
func ShareStoreFilePath(vaultDir string) string {
	return filepath.Join(vaultDir, "mcp-shares.json")
}
