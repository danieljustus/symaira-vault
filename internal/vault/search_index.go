package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"

	"filippo.io/age"
	"golang.org/x/crypto/hkdf"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
)

// ErrIndexBuildEmpty is returned by Build when the vault contains entries
// but none of them could be decrypted with the supplied identity. This
// typically signals a wrong identity, vault-wide corruption, or a read
// error that affected every entry. Callers should fall back to a full
// decrypt pass over the candidate paths.
var ErrIndexBuildEmpty = errors.New("search index build produced no entries")

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
//   - Updated incrementally on single-entry add/update/delete: UpdateEntry and
//     RemoveEntry re-index just that path and re-persist the ciphertext, so a
//     write no longer discards the whole index
//   - Fully invalidated only by bulk/structural operations (recipient changes,
//     migrations, manifest rebuild) via InvalidateSearchIndex, then rebuilt on
//     the next search
//   - Encrypted with a key derived from the vault identity
type EncryptedIndex struct {
	mu         sync.RWMutex
	ciphertext []byte            // encrypted serialized index
	salt       []byte            // 16-byte HKDF salt (nil for legacy)
	vaultDir   string            // vault directory the index covers
	idHash     [sha256.Size]byte // sha256 of identity recipient for change detection
}

func indexFilePath(vaultDir string) string {
	return filepath.Join(vaultDir, ".search-index")
}

// canonicalVaultDir returns a canonical form of vaultDir for index-ownership
// comparison. It resolves symlinks when possible and otherwise falls back to a
// lexical clean, so two references to the same vault compare equal while two
// distinct vaults stay distinct.
func canonicalVaultDir(vaultDir string) string {
	if resolved, err := filepath.EvalSymlinks(vaultDir); err == nil {
		return resolved
	}
	return filepath.Clean(vaultDir)
}

// indexDoc stores raw string values per entry path for substring matching.
// The needle is matched as a substring (case-insensitive) against all stored
// values when performing a search.
//
// A TokenIndex provides O(1) pre-filtering: each unique token extracted from
// string values maps to the set of entry paths containing that token. During
// search, an exact token lookup avoids scanning all values. Substring fallback
// handles partial matches (e.g., "ali" matching "alice").
type indexDoc struct {
	// Values maps entry path → lowercased string values from its data.
	Values map[string][]string `json:"v"`
	// TokenIndex maps token → entry paths containing that token.
	// Tokens are lowercased and split on whitespace/punctuation boundaries.
	TokenIndex map[string]map[string]struct{} `json:"ti,omitempty"`
	// EntryCount is the number of entries in the vault when the index was built.
	// Used for stale detection — if the count differs, the index is rebuilt.
	EntryCount int `json:"c,omitempty"`
	// Salt is the random salt for HKDF-based index key derivation.
	// Empty for legacy indices (pre-v0.4.1) that used raw SHA-256 keying.
	Salt []byte `json:"s,omitempty"`
}

var globalIndex EncryptedIndex

// Build constructs the encrypted search index by scanning all entries in the
// vault and collecting their string field values. The resulting path→values
// mapping is serialized to JSON and encrypted with the vault identity key.
//
// If the vault contains entries but none of them could be decrypted with the
// provided identity (for example, the wrong identity was supplied, or every
// entry on disk is corrupt), the build is treated as a failure and an error
// is returned. The resulting in-memory state and on-disk file are not
// updated. Callers can detect this and fall back to a full decrypt pass
// over the candidates.
func (idx *EncryptedIndex) Build(vaultDir string, identity *age.X25519Identity) error {
	// Invalidate the list cache to ensure we see entries written after the
	// last list — writes create files in subdirectories which do not update
	// the parent entries/ directory mtime, so the mtime-based cache check
	// would miss them.
	listCacheFor(vaultDir).Invalidate()

	paths, err := List(vaultDir, "", identity)
	if err != nil {
		return err
	}

	doc := indexDoc{
		Values:     make(map[string][]string, len(paths)),
		TokenIndex: make(map[string]map[string]struct{}),
		EntryCount: len(paths),
	}

	salt := make([]byte, indexSaltLen)
	if _, randErr := rand.Read(salt); randErr != nil {
		return randErr
	}
	doc.Salt = salt

	type indexJob struct {
		i    int
		path string
	}
	type indexResult struct {
		i      int
		path   string
		values []string
	}

	jobs := make(chan indexJob, len(paths))
	results := make(chan indexResult, len(paths))

	maxWorkers := SearchWorkerCount(0)
	if len(paths) < maxWorkers {
		maxWorkers = len(paths)
	}

	var pseudoKey []byte
	cfg, cfgErr := loadVaultConfig(vaultDir)
	if cfgErr == nil && identity != nil && isPseudonymizeEnabled(cfg) {
		pseudoKey = derivePseudonymizationKey(identity)
	}

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				entry, readErr := readEntryInner(vaultDir, job.path, identity, pseudoKey)
				if readErr != nil {
					results <- indexResult{i: job.i, path: job.path}
					continue
				}

				var values []string
				collectStringValues(&values, entry.Data)
				sort.Strings(values)
				results <- indexResult{i: job.i, path: job.path, values: values}
			}
		}()
	}

	for i, entryPath := range paths {
		jobs <- indexJob{i: i, path: entryPath}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]indexResult, len(paths))
	for result := range results {
		collected[result.i] = result
	}

	for _, result := range collected {
		if len(result.values) == 0 {
			continue
		}

		doc.Values[result.path] = result.values
		for _, val := range result.values {
			for _, token := range tokenize(val) {
				if doc.TokenIndex[token] == nil {
					doc.TokenIndex[token] = make(map[string]struct{})
				}
				doc.TokenIndex[token][result.path] = struct{}{}
			}
		}
	}

	// Refuse to commit an index that covers zero entries when the vault
	// actually has entries. This is the signature of a wrong identity, a
	// vault-wide corruption, or any other condition where the index would
	// silently look empty. Returning an error lets callers fall back to
	// the full decrypt path (or surface the problem to the user) instead
	// of producing misleading "no matches" results.
	if len(paths) > 0 && len(doc.Values) == 0 {
		return ErrIndexBuildEmpty
	}

	plaintext, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	defer vaultcrypto.Wipe(plaintext)

	key := deriveIndexKey(identity, salt)
	defer vaultcrypto.Wipe(key)

	ciphertext, err := vaultcrypto.EncryptWithKey(plaintext, key)
	if err != nil {
		return err
	}

	idHash := sha256.Sum256([]byte(identity.Recipient().String()))

	idx.mu.Lock()
	idx.ciphertext = ciphertext
	idx.salt = salt
	idx.vaultDir = vaultDir
	idx.idHash = idHash
	idx.mu.Unlock()

	_ = idx.saveToDisk(vaultDir)
	return nil
}

// BuildMemoryOnly builds the in-memory index without persisting to disk.
// This is used by WarmSearchIndex to eliminate cold-start latency without
// risking stale on-disk state from background goroutine races.
func (idx *EncryptedIndex) BuildMemoryOnly(vaultDir string, identity *age.X25519Identity) error {
	listCacheFor(vaultDir).Invalidate()

	paths, err := List(vaultDir, "", identity)
	if err != nil {
		return err
	}

	doc := indexDoc{
		Values:     make(map[string][]string, len(paths)),
		TokenIndex: make(map[string]map[string]struct{}),
		EntryCount: len(paths),
	}

	salt := make([]byte, indexSaltLen)
	if _, randErr := rand.Read(salt); randErr != nil {
		return randErr
	}
	doc.Salt = salt

	type indexJob struct {
		i    int
		path string
	}
	type indexResult struct {
		i      int
		path   string
		values []string
	}

	jobs := make(chan indexJob, len(paths))
	results := make(chan indexResult, len(paths))

	maxWorkers := SearchWorkerCount(0)
	if len(paths) < maxWorkers {
		maxWorkers = len(paths)
	}

	var pseudoKey []byte
	cfg, cfgErr := loadVaultConfig(vaultDir)
	if cfgErr == nil && identity != nil && isPseudonymizeEnabled(cfg) {
		pseudoKey = derivePseudonymizationKey(identity)
	}

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				entry, readErr := readEntryInner(vaultDir, job.path, identity, pseudoKey)
				if readErr != nil {
					results <- indexResult{i: job.i, path: job.path}
					continue
				}

				var values []string
				collectStringValues(&values, entry.Data)
				sort.Strings(values)
				results <- indexResult{i: job.i, path: job.path, values: values}
			}
		}()
	}

	for i, entryPath := range paths {
		jobs <- indexJob{i: i, path: entryPath}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]indexResult, len(paths))
	for result := range results {
		collected[result.i] = result
	}

	for _, result := range collected {
		if len(result.values) == 0 {
			continue
		}

		doc.Values[result.path] = result.values
		for _, val := range result.values {
			for _, token := range tokenize(val) {
				if doc.TokenIndex[token] == nil {
					doc.TokenIndex[token] = make(map[string]struct{})
				}
				doc.TokenIndex[token][result.path] = struct{}{}
			}
		}
	}

	if len(paths) > 0 && len(doc.Values) == 0 {
		return ErrIndexBuildEmpty
	}

	plaintext, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	defer vaultcrypto.Wipe(plaintext)

	key := deriveIndexKey(identity, salt)
	defer vaultcrypto.Wipe(key)

	ciphertext, err := vaultcrypto.EncryptWithKey(plaintext, key)
	if err != nil {
		return err
	}

	idHash := sha256.Sum256([]byte(identity.Recipient().String()))

	idx.mu.Lock()
	idx.ciphertext = ciphertext
	idx.salt = salt
	idx.vaultDir = vaultDir
	idx.idHash = idHash
	idx.mu.Unlock()

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
	storedSalt := idx.salt
	storedDir := idx.vaultDir
	idx.mu.RUnlock()

	if ct == nil {
		return nil, nil
	}

	currentHash := sha256.Sum256([]byte(identity.Recipient().String()))
	if currentHash != idHash {
		return nil, errors.New("identity changed")
	}
	// The index is a single shared slot. Reject a lookup against a different
	// vault directory even when the identity matches — otherwise a second vault
	// opened with the same identity would filter its candidates against the
	// first vault's index and return incomplete or incorrect results.
	if canonicalVaultDir(storedDir) != canonicalVaultDir(vaultDir) {
		return nil, errors.New("vault directory changed")
	}

	key := deriveIndexKey(identity, storedSalt)
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

	// Fast path: O(1) token lookup — if the search needle is a whole token
	// (no whitespace, single word), check the token index directly. This
	// avoids scanning all values in the common case of exact-term searches.
	if isSingleToken(needle) && doc.TokenIndex != nil {
		if paths, ok := doc.TokenIndex[needleLower]; ok {
			for _, path := range candidates {
				if _, found := paths[path]; found {
					matching[path] = struct{}{}
				}
			}
			if len(matching) > 0 {
				return matching, nil
			}
		}
	}

	// Fallback: substring scan for multi-word queries or partial matches.
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

// Covers reports whether the built index belongs to the given vault directory
// and identity. A different vault directory (even with the same identity) or a
// different identity means the index must be rebuilt before it can be used for
// this vault's lookups.
func (idx *EncryptedIndex) Covers(vaultDir string, identity *age.X25519Identity) bool {
	if identity == nil {
		return false
	}
	idHash := sha256.Sum256([]byte(identity.Recipient().String()))
	want := canonicalVaultDir(vaultDir)

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.ciphertext != nil &&
		idx.idHash == idHash &&
		canonicalVaultDir(idx.vaultDir) == want
}

// Invalidate clears the encrypted index from memory and deletes the on-disk
// copy, forcing a rebuild on the next MatchEntries call.
func (idx *EncryptedIndex) Invalidate() {
	idx.mu.Lock()
	vaultDir := idx.vaultDir
	idx.ciphertext = nil
	idx.salt = nil
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

	storedSalt := idx.salt
	key := deriveIndexKey(identity, storedSalt)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(idx.ciphertext, key)
	if err != nil {
		idx.clearLocked()
		_ = os.Remove(indexFilePath(vaultDir))
		return nil
	}
	defer vaultcrypto.Wipe(plaintext)

	var doc indexDoc
	if err = json.Unmarshal(plaintext, &doc); err != nil {
		idx.clearLocked()
		_ = os.Remove(indexFilePath(vaultDir))
		return nil
	}

	if doc.Values == nil {
		doc.Values = make(map[string][]string)
	}
	if doc.TokenIndex == nil {
		doc.TokenIndex = make(map[string]map[string]struct{})
	}

	removeFromTokenIndex(doc.TokenIndex, path)
	delete(doc.Values, path)

	entry, readErr := ReadEntry(vaultDir, path, identity)
	if readErr == nil {
		var values []string
		collectStringValues(&values, entry.Data)
		if len(values) > 0 {
			doc.Values[path] = values
			addToTokenIndex(doc.TokenIndex, values, path)
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
	idx.idHash = sha256.Sum256([]byte(identity.Recipient().String()))

	// Persist the incrementally-updated index so the on-disk copy tracks the
	// write. Without this the edited entry's previous value would remain on
	// disk and, because an in-place edit leaves the entry count unchanged, be
	// reloaded as a valid index after a restart — returning stale results.
	return writeIndexFile(vaultDir, storedSalt, newCiphertext)
}

// RemoveEntry removes a single path from the encrypted index.
// If the index is not built, this is a no-op.
func (idx *EncryptedIndex) RemoveEntry(path string, identity *age.X25519Identity) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if idx.ciphertext == nil {
		return
	}

	vaultDir := idx.vaultDir
	dropDisk := func() {
		idx.clearLocked()
		if vaultDir != "" {
			_ = os.Remove(indexFilePath(vaultDir))
		}
	}

	if identity == nil {
		dropDisk()
		return
	}

	storedSalt := idx.salt
	key := deriveIndexKey(identity, storedSalt)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(idx.ciphertext, key)
	if err != nil {
		dropDisk()
		return
	}
	defer vaultcrypto.Wipe(plaintext)

	var doc indexDoc
	if err = json.Unmarshal(plaintext, &doc); err != nil {
		dropDisk()
		return
	}

	delete(doc.Values, path)
	if doc.TokenIndex != nil {
		removeFromTokenIndex(doc.TokenIndex, path)
	}
	// A delete removes exactly one vault entry; keep the persisted entry count
	// in step so the on-disk index stays valid (not flagged stale) on reload.
	if doc.EntryCount > 0 {
		doc.EntryCount--
	}

	newPlaintext, err := json.Marshal(doc)
	if err != nil {
		dropDisk()
		return
	}
	defer vaultcrypto.Wipe(newPlaintext)

	newCiphertext, err := vaultcrypto.EncryptWithKey(newPlaintext, key)
	if err != nil {
		dropDisk()
		return
	}

	idx.ciphertext = newCiphertext
	// Persist so the deletion is reflected on disk and survives a restart.
	_ = writeIndexFile(vaultDir, storedSalt, newCiphertext)
}

const indexFormatVersion = byte(0x01)

// writeIndexFile serializes the salted index ciphertext to the on-disk index
// file. It deliberately does not touch idx.mu, so callers that already hold the
// write lock (UpdateEntry, RemoveEntry) can persist without deadlocking against
// the non-reentrant RWMutex that saveToDisk's RLock would otherwise take.
func writeIndexFile(vaultDir string, salt, ciphertext []byte) error {
	if ciphertext == nil {
		return nil
	}
	data := make([]byte, 0, 1+len(salt)+len(ciphertext))
	data = append(data, indexFormatVersion)
	data = append(data, salt...)
	data = append(data, ciphertext...)
	return os.WriteFile(indexFilePath(vaultDir), data, 0600)
}

// clearLocked resets the in-memory index to the unbuilt state. The caller must
// hold idx.mu.
func (idx *EncryptedIndex) clearLocked() {
	idx.ciphertext = nil
	idx.salt = nil
	idx.vaultDir = ""
	idx.idHash = [sha256.Size]byte{}
}

func (idx *EncryptedIndex) saveToDisk(vaultDir string) error {
	idx.mu.RLock()
	ct := idx.ciphertext
	storedSalt := idx.salt
	idx.mu.RUnlock()

	return writeIndexFile(vaultDir, storedSalt, ct)
}

func (idx *EncryptedIndex) loadFromDisk(vaultDir string, identity *age.X25519Identity) error {
	indexPath := indexFilePath(vaultDir)
	raw, err := os.ReadFile(indexPath) // #nosec G304 — indexPath is filepath.Join(vaultDir, ".search-index"). Callers pass Vault.Dir from Open, which validates the directory via validateVaultDir(), and the filename is hardcoded.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	var salt []byte
	var ct []byte

	if len(raw) > 1 && raw[0] == indexFormatVersion {
		if len(raw) < 1+indexSaltLen+1 {
			_ = os.Remove(indexPath)
			return errors.New("truncated search index")
		}
		salt = raw[1 : 1+indexSaltLen]
		ct = raw[1+indexSaltLen:]
	} else {
		ct = raw
	}

	key := deriveIndexKey(identity, salt)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(ct, key)
	if err != nil && len(salt) == 0 {
		_ = os.Remove(indexPath)
		return err
	} else if err != nil {
		_ = os.Remove(indexPath)
		return err
	}
	defer vaultcrypto.Wipe(plaintext)

	var doc indexDoc
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		_ = os.Remove(indexPath)
		return err
	}

	paths, listErr := List(vaultDir, "", identity)
	if listErr != nil {
		_ = os.Remove(indexPath)
		return listErr
	}
	if doc.EntryCount != len(paths) {
		_ = os.Remove(indexPath)
		return errors.New("stale index")
	}

	idHash := sha256.Sum256([]byte(identity.Recipient().String()))

	idx.mu.Lock()
	idx.ciphertext = ct
	idx.salt = salt
	idx.vaultDir = vaultDir
	idx.idHash = idHash
	idx.mu.Unlock()

	if len(salt) == 0 {
		_ = idx.saveToDisk(vaultDir)
	}

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
	defaultVaultCache.Invalidate()
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
// identity using HKDF-SHA256 with a per-index random salt and an info label.
// Legacy indices without a salt use raw SHA-256 for backward compatibility.
func deriveIndexKey(identity *age.X25519Identity, salt []byte) []byte {
	identityBytes := []byte(identity.String())
	if len(salt) == 0 {
		h := sha256.Sum256(identityBytes)
		return h[:]
	}
	kdf := hkdf.New(sha256.New, identityBytes, salt, []byte("symvault-search-index-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		panic("hkdf read failed: " + err.Error())
	}
	return key
}

const indexSaltLen = 16

// tokenize splits a lowercased string into individual tokens on whitespace and
// punctuation boundaries. Consecutive delimiters produce no empty tokens.
func tokenize(s string) []string {
	var tokens []string
	current := strings.Builder{}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			current.WriteRune(r)
		} else if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

// isSingleToken returns true if the needle contains no whitespace or
// punctuation that would split it into multiple tokens.
func isSingleToken(needle string) bool {
	for _, r := range needle {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// addToTokenIndex adds all tokens from a set of values to the token index,
// associating them with the given entry path.
func addToTokenIndex(ti map[string]map[string]struct{}, values []string, path string) {
	for _, val := range values {
		for _, token := range tokenize(val) {
			if ti[token] == nil {
				ti[token] = make(map[string]struct{})
			}
			ti[token][path] = struct{}{}
		}
	}
}

// removeFromTokenIndex removes all references to a path from the token index.
// Empty token maps are cleaned up to keep the index compact.
func removeFromTokenIndex(ti map[string]map[string]struct{}, path string) {
	for token, paths := range ti {
		delete(paths, path)
		if len(paths) == 0 {
			delete(ti, token)
		}
	}
}
