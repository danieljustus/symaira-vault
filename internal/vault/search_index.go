package vault

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
)

// EncryptedIndex provides a persistent encrypted search index that maps entry
// paths to the string values from their decrypted data. The index ciphertext is
// stored both in memory and on disk (at vaultDir/.search-index) so it survives
// process restarts. It is encrypted with a key derived from the vault identity
// and decrypted only during search operations, preventing plaintext index data
// from leaking during memory dumps or swap.
//
// When searching, the index is decrypted once and the query is matched as a
// substring against all stored values. This preserves the existing substring
// matching semantics while only requiring a single decrypt per search (vs
// decrypting every non-path-matching entry).
//
// The index is:
//   - Built lazily on first search after vault unlock
//   - Saved to disk after building so it persists across restarts
//   - Loaded from disk on first search if available and valid
//   - Invalidated on any write operation (clears both memory and disk)
//   - Rebuilt automatically on the next search
//   - Encrypted with a key derived from the vault identity
type EncryptedIndex struct {
	mu         sync.RWMutex
	ciphertext []byte            // encrypted serialized index
	vaultDir   string            // vault directory the index covers
	idHash     [sha256.Size]byte // sha256 of identity for change detection
}

func indexFilePath(vaultDir string) string {
	return filepath.Join(vaultDir, ".search-index")
}

// indexDoc stores raw string values per entry path for substring matching.
// The needle is matched as a substring (case-insensitive) against all stored
// values when performing a search.
type indexDoc struct {
	// Values maps entry path → lowercased string values from its data.
	Values map[string][]string `json:"v"`
	// EntryCount is the number of entries in the vault when the index was built.
	// Used for stale detection — if the count differs, the index is rebuilt.
	EntryCount int `json:"c,omitempty"`
}

var globalIndex EncryptedIndex

// Build constructs the encrypted search index by scanning all entries in the
// vault and collecting their string field values. The resulting path→values
// mapping is serialized to JSON and encrypted with the vault identity key.
func (idx *EncryptedIndex) Build(vaultDir string, identity *age.X25519Identity) error {
	// Invalidate the list cache to ensure we see entries written after the
	// last list — writes create files in subdirectories which do not update
	// the parent entries/ directory mtime, so the mtime-based cache check
	// would miss them.
	InvalidateListCache(vaultDir)

	paths, err := List(vaultDir, "")
	if err != nil {
		return err
	}

	doc := indexDoc{
		Values:     make(map[string][]string, len(paths)),
		EntryCount: len(paths),
	}

	for _, entryPath := range paths {
		entry, readErr := ReadEntry(vaultDir, entryPath, identity)
		if readErr != nil {
			continue
		}

		var values []string
		collectStringValues(&values, entry.Data)
		if len(values) > 0 {
			doc.Values[entryPath] = values
		}
	}

	plaintext, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	defer vaultcrypto.Wipe(plaintext)

	key := deriveIndexKey(identity)
	defer vaultcrypto.Wipe(key)

	ciphertext, err := vaultcrypto.EncryptWithKey(plaintext, key)
	if err != nil {
		return err
	}

	idHash := sha256.Sum256([]byte(identity.String()))

	idx.mu.Lock()
	idx.ciphertext = ciphertext
	idx.vaultDir = vaultDir
	idx.idHash = idHash
	idx.mu.Unlock()

	_ = idx.saveToDisk(vaultDir)
	return nil
}

// MatchEntries decrypts the index and checks which of the given entry paths
// contain the needle as a substring in any of their stored values. Returns
// the subset of paths that match.
//
// The needle is matched as a case-insensitive substring against all stored
// values (preserving the existing Find behavior).
//
// Returns nil, nil if the index is not built or on any error (caller falls
// back to the original decrypt-everything approach).
func (idx *EncryptedIndex) MatchEntries(vaultDir string, identity *age.X25519Identity, candidates []string, needle string) (map[string]struct{}, error) {
	if len(candidates) == 0 || needle == "" {
		return nil, nil
	}

	idx.mu.RLock()
	ct := idx.ciphertext
	idHash := idx.idHash
	idx.mu.RUnlock()

	if ct == nil {
		return nil, nil
	}

	currentHash := sha256.Sum256([]byte(identity.String()))
	if currentHash != idHash {
		return nil, errors.New("identity changed")
	}

	key := deriveIndexKey(identity)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(ct, key)
	if err != nil {
		return nil, err
	}
	defer vaultcrypto.Wipe(plaintext)

	var doc indexDoc
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		return nil, err
	}

	needleLower := strings.ToLower(needle)
	matching := make(map[string]struct{}, len(candidates))

	for _, path := range candidates {
		values, ok := doc.Values[path]
		if !ok {
			continue
		}
		for _, val := range values {
			if strings.Contains(val, needleLower) {
				matching[path] = struct{}{}
				break
			}
		}
	}

	return matching, nil
}

// IsBuilt returns true if the index has been built (ciphertext exists).
func (idx *EncryptedIndex) IsBuilt() bool {
	idx.mu.RLock()
	built := idx.ciphertext != nil
	idx.mu.RUnlock()
	return built
}

// Invalidate clears the encrypted index from memory and deletes the on-disk
// copy, forcing a rebuild on the next MatchEntries call.
func (idx *EncryptedIndex) Invalidate() {
	idx.mu.Lock()
	vaultDir := idx.vaultDir
	idx.ciphertext = nil
	idx.vaultDir = ""
	idx.idHash = [sha256.Size]byte{}
	idx.mu.Unlock()

	if vaultDir != "" {
		_ = os.Remove(indexFilePath(vaultDir))
	}
}

// UpdateEntry incrementally updates a single entry in the encrypted index.
// It decrypts the existing index, re-indexes the given path, and re-encrypts.
// If the index is not built, this is a no-op (the index will be built lazily).
func (idx *EncryptedIndex) UpdateEntry(vaultDir, path string, identity *age.X25519Identity) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if idx.ciphertext == nil {
		return nil
	}

	key := deriveIndexKey(identity)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(idx.ciphertext, key)
	if err != nil {
		// Corrupt index — clear and let it rebuild lazily
		idx.ciphertext = nil
		idx.vaultDir = ""
		idx.idHash = [sha256.Size]byte{}
		return nil
	}
	defer vaultcrypto.Wipe(plaintext)

	var doc indexDoc
	if err = json.Unmarshal(plaintext, &doc); err != nil {
		idx.ciphertext = nil
		idx.vaultDir = ""
		idx.idHash = [sha256.Size]byte{}
		return nil
	}

	if doc.Values == nil {
		doc.Values = make(map[string][]string)
	}

	entry, readErr := ReadEntry(vaultDir, path, identity)
	if readErr != nil {
		delete(doc.Values, path)
	} else {
		var values []string
		collectStringValues(&values, entry.Data)
		if len(values) > 0 {
			doc.Values[path] = values
		} else {
			delete(doc.Values, path)
		}
	}

	newPlaintext, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	defer vaultcrypto.Wipe(newPlaintext)

	newCiphertext, err := vaultcrypto.EncryptWithKey(newPlaintext, key)
	if err != nil {
		return err
	}

	idx.ciphertext = newCiphertext
	idx.vaultDir = vaultDir
	idx.idHash = sha256.Sum256([]byte(identity.String()))
	return nil
}

// RemoveEntry removes a single path from the encrypted index.
// If the index is not built, this is a no-op.
func (idx *EncryptedIndex) RemoveEntry(path string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if idx.ciphertext == nil {
		return
	}

	identity := currentSearchIdentity()
	if identity == nil {
		idx.ciphertext = nil
		return
	}

	key := deriveIndexKey(identity)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(idx.ciphertext, key)
	if err != nil {
		idx.ciphertext = nil
		return
	}
	defer vaultcrypto.Wipe(plaintext)

	var doc indexDoc
	if err = json.Unmarshal(plaintext, &doc); err != nil {
		idx.ciphertext = nil
		return
	}

	delete(doc.Values, path)

	newPlaintext, err := json.Marshal(doc)
	if err != nil {
		idx.ciphertext = nil
		return
	}
	defer vaultcrypto.Wipe(newPlaintext)

	newCiphertext, err := vaultcrypto.EncryptWithKey(newPlaintext, key)
	if err != nil {
		idx.ciphertext = nil
		return
	}

	idx.ciphertext = newCiphertext
}

func (idx *EncryptedIndex) saveToDisk(vaultDir string) error {
	idx.mu.RLock()
	ct := idx.ciphertext
	idx.mu.RUnlock()

	if ct == nil {
		return nil
	}

	indexPath := indexFilePath(vaultDir)
	return os.WriteFile(indexPath, ct, 0600)
}

func (idx *EncryptedIndex) loadFromDisk(vaultDir string, identity *age.X25519Identity) error {
	indexPath := indexFilePath(vaultDir)
	ct, err := os.ReadFile(indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	key := deriveIndexKey(identity)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(ct, key)
	if err != nil {
		_ = os.Remove(indexPath)
		return err
	}
	defer vaultcrypto.Wipe(plaintext)

	var doc indexDoc
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		_ = os.Remove(indexPath)
		return err
	}

	paths, listErr := List(vaultDir, "")
	if listErr != nil {
		_ = os.Remove(indexPath)
		return listErr
	}
	if doc.EntryCount > 0 && doc.EntryCount != len(paths) {
		_ = os.Remove(indexPath)
		return errors.New("stale index")
	}

	idHash := sha256.Sum256([]byte(identity.String()))

	idx.mu.Lock()
	idx.ciphertext = ct
	idx.vaultDir = vaultDir
	idx.idHash = idHash
	idx.mu.Unlock()

	return nil
}

// InvalidateSearchIndex clears the global in-memory encrypted search index and
// invalidates the list cache. Called after write operations so both caches are
// rebuilt on the next search.
func InvalidateSearchIndex() {
	globalIndex.Invalidate()
	// Also invalidate the list cache because writes create files in subdirectories
	// which do not update the parent entries/ directory mtime. Without this, a
	// subsequent List call would return stale paths, and the index would be built
	// from incomplete data.
	InvalidateListCache("")
}

// collectStringValues recursively extracts lowercase string values from entry
// data and appends them to the provided slice.
func collectStringValues(dst *[]string, data any) {
	switch v := data.(type) {
	case string:
		if v != "" {
			*dst = append(*dst, strings.ToLower(v))
		}
	case map[string]any:
		for _, val := range v {
			collectStringValues(dst, val)
		}
	case []any:
		for _, item := range v {
			collectStringValues(dst, item)
		}
	}
}

// deriveIndexKey derives a 32-byte symmetric encryption key from the vault
// identity using SHA-256 of the identity string.
func deriveIndexKey(identity *age.X25519Identity) []byte {
	h := sha256.Sum256([]byte(identity.String()))
	return h[:]
}
