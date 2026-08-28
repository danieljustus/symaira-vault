package vault

import (
	"bytes"
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
	"sync/atomic"
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
	persistErr error             // last on-disk persistence failure, if any
	suspended  bool              // batch mode: incremental writes defer to Resume
	dirty      bool              // set when a write was skipped while suspended
	doc        *indexDoc         // optional in-memory decrypted cache (config-gated)
	docValid   bool              // true when doc matches the current ciphertext
}

// indexBuildCounter counts successful index builds (buildIndex commits). It
// exists so tests and benchmarks can assert that a batch of writes triggers
// exactly one full index build instead of one rebuild per write.
var indexBuildCounter atomic.Int64

// isSearchIndexCacheEnabled returns true when the vault config explicitly
// enables the in-memory decrypted index cache. The default is false so
// ciphertext-only remains the documented safe default.
func isSearchIndexCacheEnabled(vaultDir string) bool {
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil || cfg == nil || cfg.Vault == nil {
		return false
	}
	return cfg.Vault.SearchIndexCache
}

// wipeIndexDoc drops all references to plaintext data in doc so the GC can
// reclaim the memory. The maps themselves are left for the garbage collector;
// only the indexDoc's references are cleared.
func wipeIndexDoc(doc *indexDoc) {
	if doc == nil {
		return
	}
	doc.Values = nil
	doc.TokenIndex = nil
	doc.PathTokens = nil
	doc.HostIndex = nil
	doc.PathHosts = nil
}

// Suspend puts the index into batch mode: subsequent UpdateEntry/RemoveEntry
// calls mark the index dirty instead of decrypting, re-marshaling,
// re-encrypting, and re-persisting the whole document per write. Resume must
// be called afterwards (typically deferred) to perform a single full rebuild
// if any write was skipped. Suspend is idempotent.
func (idx *EncryptedIndex) Suspend() {
	idx.mu.Lock()
	idx.suspended = true
	idx.mu.Unlock()
}

// Resume leaves batch mode. If any incremental write was skipped while
// suspended, it rebuilds the index exactly once from the current vault state
// and persists it. If the rebuild fails, the index is explicitly invalidated
// (in-memory and on-disk) so callers are never left with a silently stale
// index, and the build error is returned. Resume on a non-suspended index is
// a no-op.
func (idx *EncryptedIndex) Resume(vaultDir string, identity *age.X25519Identity) error {
	idx.mu.Lock()
	if !idx.suspended {
		idx.mu.Unlock()
		return nil
	}
	idx.suspended = false
	dirty := idx.dirty
	idx.dirty = false
	idx.mu.Unlock()

	if !dirty {
		return nil
	}
	if err := idx.buildIndex(vaultDir, identity, true); err != nil {
		idx.Invalidate()
		return err
	}
	return nil
}

// SuspendSearchIndex puts the search index for vaultDir into batch mode so a
// bulk write loop (e.g. import) does not pay a full index re-encryption per
// entry. Pair with a deferred ResumeSearchIndex.
func SuspendSearchIndex(vaultDir string) {
	searchIndexForVault(vaultDir).Suspend()
}

// ResumeSearchIndex leaves batch mode for vaultDir's search index. If writes
// were skipped while suspended it performs exactly one full rebuild; on
// rebuild failure the index is invalidated and the error returned.
func ResumeSearchIndex(vaultDir string, identity *age.X25519Identity) error {
	return searchIndexForVault(vaultDir).Resume(vaultDir, identity)
}

// LastPersistError returns the error from the most recent attempt to persist
// the search index to disk (full build, incremental update, or delete), or
// nil if the last attempt succeeded or none has been attempted yet. A failed
// persist never affects the correctness of in-memory search — the index
// keeps serving matches — but it does mean the next process start rebuilds
// the index from scratch instead of loading it from disk. Exposed so
// `symvault doctor` can surface persistent write failures instead of the
// vault silently losing this performance optimization.
func (idx *EncryptedIndex) LastPersistError() error {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.persistErr
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
	// PathTokens is the reverse of TokenIndex: entry path → the deduplicated
	// tokens extracted from its values. It lets incremental updates remove a
	// path from the token index in O(tokens of that path) instead of scanning
	// every token in the index. May be nil in indices written before this
	// field existed; it is rebuilt lazily on the first incremental update.
	PathTokens map[string][]string `json:"pt,omitempty"`
	// HostIndex maps normalized host → entry paths containing that host in their url field.
	HostIndex map[string]map[string]struct{} `json:"hi,omitempty"`
	// PathHosts is the reverse of HostIndex: entry path → deduplicated normalized hosts.
	PathHosts map[string][]string `json:"ph,omitempty"`
	// EntryCount is the number of entries in the vault when the index was built.
	// Used for stale detection — if the count differs, the index is rebuilt.
	EntryCount int `json:"c,omitempty"`
	// Salt is the random salt for HKDF-based index key derivation.
	// Empty for legacy indices (pre-v0.4.1) that used raw SHA-256 keying.
	Salt []byte `json:"s,omitempty"`
}

// maxIndexStoreSize is the maximum number of per-vault indices kept in the
// process-wide store. When the cap is exceeded the least-recently-used index
// is evicted (in-memory state cleared; the on-disk file survives so
// loadFromDisk can restore it without a full rebuild).
const maxIndexStoreSize = 8

// indexStore is a bounded, mutex-guarded map of per-vault encrypted search
// indices keyed by canonical vault directory. Each vault keeps its own built
// index across switches, and cross-vault isolation is preserved because
// lookups always resolve to the index that was built for that specific vault.
type indexStore struct {
	mu      sync.Mutex
	indices map[string]*EncryptedIndex
	order   []string // LRU: most-recently-used at end
}

// get returns the EncryptedIndex for vaultDir, creating a new empty one if
// absent. The entry is promoted to the most-recently-used position.
func (s *indexStore) get(vaultDir string) *EncryptedIndex {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := canonicalVaultDir(vaultDir)
	if idx, ok := s.indices[key]; ok {
		s.touchLocked(key)
		return idx
	}
	idx := &EncryptedIndex{}
	s.indices[key] = idx
	s.order = append(s.order, key)
	s.evictLocked()
	return idx
}

// touchLocked moves key to the end of the LRU order. Caller must hold s.mu.
func (s *indexStore) touchLocked(key string) {
	for i, k := range s.order {
		if k == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			s.order = append(s.order, key)
			return
		}
	}
}

// evictLocked removes the oldest entries when the store exceeds the cap.
// Evicted indices have their in-memory state cleared but their on-disk
// files are preserved so loadFromDisk can restore them later.
func (s *indexStore) evictLocked() {
	for len(s.order) > maxIndexStoreSize {
		oldest := s.order[0]
		s.order = s.order[1:]
		idx := s.indices[oldest]
		idx.mu.Lock()
		idx.clearLocked()
		idx.mu.Unlock()
		delete(s.indices, oldest)
	}
}

// invalidateAll clears every index in the store and deletes their on-disk
// files. Used by the global InvalidateSearchIndex function.
func (s *indexStore) invalidateAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, idx := range s.indices {
		idx.Invalidate()
	}
	s.indices = make(map[string]*EncryptedIndex)
	s.order = s.order[:0]
}

// searchIndexStore is the process-wide store of per-vault encrypted search
// indices. Each vault directory maps to its own EncryptedIndex, so multiple
// vaults opened with the same identity maintain independent indices.
var searchIndexStore = indexStore{indices: make(map[string]*EncryptedIndex)}

// searchIndexForVault returns the EncryptedIndex for the given vault
// directory, creating one if it does not yet exist. Callers use the returned
// index for Build, MatchEntries, Covers, and incremental updates.
func searchIndexForVault(vaultDir string) *EncryptedIndex {
	return searchIndexStore.get(vaultDir)
}

// SearchIndexPersistError returns the error from the most recent attempt to
// persist vaultDir's search index to disk, or nil if the last attempt
// succeeded or no index has been built for this vault in this process yet.
// Used by `symvault doctor` to surface a silently failing persistence path.
func SearchIndexPersistError(vaultDir string) error {
	return searchIndexForVault(vaultDir).LastPersistError()
}

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
	return idx.buildIndex(vaultDir, identity, true)
}

// BuildMemoryOnly builds the in-memory index without persisting to disk.
// This is used by WarmSearchIndex to eliminate cold-start latency without
// risking stale on-disk state from background goroutine races.
func (idx *EncryptedIndex) BuildMemoryOnly(vaultDir string, identity *age.X25519Identity) error {
	return idx.buildIndex(vaultDir, identity, false)
}

// buildIndex is the shared implementation behind Build and BuildMemoryOnly.
// When persist is true the encrypted index is saved to disk; when false only
// the in-memory state is updated.
func (idx *EncryptedIndex) buildIndex(vaultDir string, identity *age.X25519Identity, persist bool) error {
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
		PathTokens: make(map[string][]string, len(paths)),
		HostIndex:  make(map[string]map[string]struct{}),
		PathHosts:  make(map[string][]string, len(paths)),
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
		hosts  []string
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
				hosts := ExtractHostsFromData(entry.Data)
				results <- indexResult{i: job.i, path: job.path, values: values, hosts: hosts}
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
		if len(result.values) > 0 {
			doc.Values[result.path] = result.values
			addToTokenIndex(doc.TokenIndex, doc.PathTokens, result.values, result.path)
		}
		if len(result.hosts) > 0 {
			addToHostIndex(doc.HostIndex, doc.PathHosts, result.hosts, result.path)
		}
	}

	// Refuse to commit an index that covers zero entries when the vault
	// actually has entries. This is the signature of a wrong identity, a
	// vault-wide corruption, or any other condition where the index would
	// silently look empty. Returning an error lets callers fall back to
	// the full decrypt path (or surface the problem to the user) instead
	// of producing misleading "no matches" results.
	if len(paths) > 0 && len(doc.Values) == 0 && len(doc.HostIndex) == 0 {
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
	cacheEnabled := isSearchIndexCacheEnabled(vaultDir)

	idx.mu.Lock()
	idx.ciphertext = ciphertext
	idx.salt = salt
	idx.vaultDir = vaultDir
	idx.idHash = idHash
	if cacheEnabled {
		idx.doc = &doc
		idx.docValid = true
	} else {
		wipeIndexDoc(idx.doc)
		idx.doc = nil
		idx.docValid = false
	}
	idx.mu.Unlock()

	indexBuildCounter.Add(1)

	if persist {
		persistErr := idx.saveToDisk(vaultDir)
		idx.mu.Lock()
		idx.persistErr = persistErr
		idx.mu.Unlock()
	}
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

	cacheEnabled := isSearchIndexCacheEnabled(vaultDir)
	idx.mu.RLock()
	ct := idx.ciphertext
	idHash := idx.idHash
	storedSalt := idx.salt
	storedDir := idx.vaultDir
	doc := idx.doc
	docValid := idx.docValid
	if ct == nil {
		idx.mu.RUnlock()
		return nil, nil
	}
	if docValid && cacheEnabled && doc != nil {
		matching := matchEntriesWithDoc(candidates, needle, doc)
		idx.mu.RUnlock()
		return matching, nil
	}
	idx.mu.RUnlock()

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

	// The in-memory cache was checked while holding idx.mu.RLock above.
	// Reaching this point means the ciphertext must be decrypted.

	key := deriveIndexKey(identity, storedSalt)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(ct, key)
	if err != nil {
		return nil, err
	}
	defer vaultcrypto.Wipe(plaintext)

	var docParsed indexDoc
	if err := json.Unmarshal(plaintext, &docParsed); err != nil {
		return nil, err
	}

	// Populate cache for subsequent lookups if enabled.
	if isSearchIndexCacheEnabled(vaultDir) {
		idx.mu.Lock()
		if len(idx.ciphertext) == len(ct) && bytes.Equal(idx.ciphertext, ct) {
			idx.doc = &docParsed
			idx.docValid = true
		}
		idx.mu.Unlock()
	}

	return matchEntriesWithDoc(candidates, needle, &docParsed), nil
}

// MatchHost decrypts the index and returns the subset of entry paths whose
// "url" field matches the target URL or host (normalized). If candidates is
// non-empty, only candidates that match are returned; if candidates is empty,
// all matching paths in the vault index are returned.
func (idx *EncryptedIndex) MatchHost(vaultDir string, identity *age.X25519Identity, candidates []string, targetHostOrURL string) (map[string]struct{}, error) {
	if targetHostOrURL == "" {
		return nil, nil
	}

	targetHost, err := NormalizeHost(targetHostOrURL)
	if err != nil {
		return nil, err
	}

	cacheEnabled := isSearchIndexCacheEnabled(vaultDir)
	idx.mu.RLock()
	ct := idx.ciphertext
	idHash := idx.idHash
	storedSalt := idx.salt
	storedDir := idx.vaultDir
	doc := idx.doc
	docValid := idx.docValid
	if ct == nil {
		idx.mu.RUnlock()
		return nil, nil
	}
	if docValid && cacheEnabled && doc != nil {
		matching := matchHostWithDoc(candidates, targetHost, doc)
		idx.mu.RUnlock()
		return matching, nil
	}
	idx.mu.RUnlock()

	currentHash := sha256.Sum256([]byte(identity.Recipient().String()))
	if currentHash != idHash {
		return nil, errors.New("identity changed")
	}
	if canonicalVaultDir(storedDir) != canonicalVaultDir(vaultDir) {
		return nil, errors.New("vault directory changed")
	}

	// The in-memory cache was checked while holding idx.mu.RLock above.
	// Reaching this point means the ciphertext must be decrypted.

	key := deriveIndexKey(identity, storedSalt)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(ct, key)
	if err != nil {
		return nil, err
	}
	defer vaultcrypto.Wipe(plaintext)

	var docParsed indexDoc
	if err := json.Unmarshal(plaintext, &docParsed); err != nil {
		return nil, err
	}

	// Populate cache for subsequent lookups if enabled.
	if isSearchIndexCacheEnabled(vaultDir) {
		idx.mu.Lock()
		if len(idx.ciphertext) == len(ct) && bytes.Equal(idx.ciphertext, ct) {
			idx.doc = &docParsed
			idx.docValid = true
		}
		idx.mu.Unlock()
	}

	return matchHostWithDoc(candidates, targetHost, &docParsed), nil
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
	idx.clearLocked()
	idx.mu.Unlock()

	if vaultDir != "" {
		_ = os.Remove(indexFilePath(vaultDir))
	}
}

// UpdateEntry incrementally updates a single entry in the encrypted index.
// It uses the in-memory decrypted cache when available and config-enabled,
// falling back to decrypting the entire ciphertext. On-disk persistence stays
// synchronous so a successful return guarantees restart visibility.
// If the index is not built, this is a no-op (the index will be built lazily).
func (idx *EncryptedIndex) UpdateEntry(vaultDir, path string, identity *age.X25519Identity) error {
	idx.mu.Lock()

	if idx.ciphertext == nil {
		idx.mu.Unlock()
		return nil
	}

	// Batch mode: skip the per-write decrypt/re-encrypt/persist cycle and let
	// Resume rebuild the index once.
	if idx.suspended {
		idx.dirty = true
		idx.mu.Unlock()
		return nil
	}
	cacheEnabled := isSearchIndexCacheEnabled(vaultDir)
	useCache := idx.docValid && idx.doc != nil && cacheEnabled
	var doc *indexDoc
	if useCache {
		doc = idx.doc
	} else {
		storedSalt := idx.salt
		key := deriveIndexKey(identity, storedSalt)
		plaintext, err := vaultcrypto.DecryptWithKey(idx.ciphertext, key)
		vaultcrypto.Wipe(key)
		if err != nil {
			idx.clearLocked()
			_ = os.Remove(indexFilePath(vaultDir))
			idx.mu.Unlock()
			return nil
		}
		var parsed indexDoc
		if err = json.Unmarshal(plaintext, &parsed); err != nil {
			vaultcrypto.Wipe(plaintext)
			idx.clearLocked()
			_ = os.Remove(indexFilePath(vaultDir))
			idx.mu.Unlock()
			return nil
		}
		vaultcrypto.Wipe(plaintext)
		doc = &parsed
	}

	if doc.Values == nil {
		doc.Values = make(map[string][]string)
	}
	if doc.TokenIndex == nil {
		doc.TokenIndex = make(map[string]map[string]struct{})
	}
	if doc.HostIndex == nil {
		doc.HostIndex = make(map[string]map[string]struct{})
	}
	ensurePathTokens(doc)
	ensurePathHosts(doc)

	removeFromTokenIndex(doc.TokenIndex, doc.PathTokens, path)
	removeFromHostIndex(doc.HostIndex, doc.PathHosts, path)
	delete(doc.Values, path)

	entry, readErr := ReadEntry(vaultDir, path, identity)
	if readErr == nil {
		var values []string
		collectStringValues(&values, entry.Data)
		if len(values) > 0 {
			doc.Values[path] = values
			addToTokenIndex(doc.TokenIndex, doc.PathTokens, values, path)
		}
		hosts := ExtractHostsFromData(entry.Data)
		if len(hosts) > 0 {
			addToHostIndex(doc.HostIndex, doc.PathHosts, hosts, path)
		}
	}

	newPlaintext, err := json.Marshal(doc)
	if err != nil {
		idx.mu.Unlock()
		return err
	}
	defer vaultcrypto.Wipe(newPlaintext)

	storedSalt := idx.salt
	key := deriveIndexKey(identity, storedSalt)
	defer vaultcrypto.Wipe(key)

	newCiphertext, err := vaultcrypto.EncryptWithKey(newPlaintext, key)
	if err != nil {
		idx.mu.Unlock()
		return err
	}

	idx.ciphertext = newCiphertext
	idx.vaultDir = vaultDir
	idx.idHash = sha256.Sum256([]byte(identity.Recipient().String()))

	if cacheEnabled {
		idx.doc = doc
		idx.docValid = true
	} else {
		wipeIndexDoc(idx.doc)
		idx.doc = nil
		idx.docValid = false
	}

	// Persist while holding the write lock so another update cannot overwrite
	// the on-disk file with an older ciphertext after this update returns.
	persistErr := writeIndexFile(vaultDir, storedSalt, newCiphertext)
	idx.persistErr = persistErr
	idx.mu.Unlock()
	return persistErr
}

// RemoveEntry removes a single path from the encrypted index.
// If the index is not built, this is a no-op.
func (idx *EncryptedIndex) RemoveEntry(path string, identity *age.X25519Identity) {
	idx.mu.Lock()

	if idx.ciphertext == nil {
		idx.mu.Unlock()
		return
	}

	// Batch mode: skip the per-write decrypt/re-encrypt/persist cycle and let
	// Resume rebuild the index once.
	if idx.suspended {
		idx.dirty = true
		idx.mu.Unlock()
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
		idx.mu.Unlock()
		return
	}

	cacheEnabled := isSearchIndexCacheEnabled(vaultDir)
	useCache := idx.docValid && idx.doc != nil && cacheEnabled
	var doc *indexDoc
	if useCache {
		doc = idx.doc
	} else {
		storedSalt := idx.salt
		key := deriveIndexKey(identity, storedSalt)
		plaintext, err := vaultcrypto.DecryptWithKey(idx.ciphertext, key)
		vaultcrypto.Wipe(key)
		if err != nil {
			dropDisk()
			idx.mu.Unlock()
			return
		}
		var parsed indexDoc
		if err = json.Unmarshal(plaintext, &parsed); err != nil {
			vaultcrypto.Wipe(plaintext)
			dropDisk()
			idx.mu.Unlock()
			return
		}
		vaultcrypto.Wipe(plaintext)
		doc = &parsed
	}

	delete(doc.Values, path)
	if doc.TokenIndex != nil {
		ensurePathTokens(doc)
		removeFromTokenIndex(doc.TokenIndex, doc.PathTokens, path)
	}
	if doc.HostIndex != nil {
		ensurePathHosts(doc)
		removeFromHostIndex(doc.HostIndex, doc.PathHosts, path)
	}
	// A delete removes exactly one vault entry; keep the persisted entry count
	// in step so the on-disk index stays valid (not flagged stale) on reload.
	if doc.EntryCount > 0 {
		doc.EntryCount--
	}

	newPlaintext, err := json.Marshal(doc)
	if err != nil {
		dropDisk()
		idx.mu.Unlock()
		return
	}
	defer vaultcrypto.Wipe(newPlaintext)

	storedSalt := idx.salt
	key := deriveIndexKey(identity, storedSalt)
	newCiphertext, err := vaultcrypto.EncryptWithKey(newPlaintext, key)
	vaultcrypto.Wipe(key)
	if err != nil {
		dropDisk()
		idx.mu.Unlock()
		return
	}

	idx.ciphertext = newCiphertext
	if cacheEnabled {
		idx.doc = doc
		idx.docValid = true
	} else {
		wipeIndexDoc(idx.doc)
		idx.doc = nil
		idx.docValid = false
	}

	// Persist while holding the write lock so another update cannot overwrite
	// the on-disk file with an older ciphertext after this update returns.
	idx.persistErr = writeIndexFile(vaultDir, storedSalt, newCiphertext)
	idx.mu.Unlock()
}

const indexFormatVersion = byte(0x01)

// writeIndexFile serializes the salted index ciphertext to the on-disk index
// file. It deliberately does not touch idx.mu, so callers that already hold the
// write lock (UpdateEntry, RemoveEntry) can persist without deadlocking against
// the non-reentrant RWMutex that saveToDisk's RLock would otherwise take.
//
// The write is atomic: data is written to a temporary file in the same
// directory and then renamed into place, so a process crash or write error
// partway through can never leave a truncated or half-written index file
// that a later loadFromDisk would accept as valid.
func writeIndexFile(vaultDir string, salt, ciphertext []byte) error {
	if ciphertext == nil {
		return nil
	}
	data := make([]byte, 0, 1+len(salt)+len(ciphertext))
	data = append(data, indexFormatVersion)
	data = append(data, salt...)
	data = append(data, ciphertext...)

	finalPath := indexFilePath(vaultDir)
	tmp, err := os.CreateTemp(vaultDir, ".search-index.tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}

// clearLocked resets the in-memory index to the unbuilt state. The caller must
// hold idx.mu.
func (idx *EncryptedIndex) clearLocked() {
	if idx.doc != nil {
		wipeIndexDoc(idx.doc)
		idx.doc = nil
	}
	idx.docValid = false
	idx.ciphertext = nil
	idx.salt = nil
	idx.vaultDir = ""
	idx.idHash = [sha256.Size]byte{}
	idx.dirty = false
	idx.persistErr = nil
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

	cacheEnabled := isSearchIndexCacheEnabled(vaultDir)
	idx.mu.Lock()
	idx.ciphertext = ct
	idx.salt = salt
	idx.vaultDir = vaultDir
	idx.idHash = idHash
	if cacheEnabled {
		idx.doc = &doc
		idx.docValid = true
	} else {
		wipeIndexDoc(idx.doc)
		idx.doc = nil
		idx.docValid = false
	}
	idx.mu.Unlock()

	if len(salt) == 0 {
		persistErr := idx.saveToDisk(vaultDir)
		idx.mu.Lock()
		idx.persistErr = persistErr
		idx.mu.Unlock()
	}

	return nil
}

// InvalidateSearchIndex clears every per-vault encrypted search index in the
// process-wide store and invalidates the list cache. Called after write
// operations so both caches are rebuilt on the next search.
func InvalidateSearchIndex() {
	searchIndexStore.invalidateAll()
	defaultVaultCache.Invalidate()
}

// ClearMemory clears the in-memory index state without deleting the on-disk
// file. This simulates a process restart: the next MatchEntries or Covers
// call will reload from disk (or rebuild if the file is missing/stale).
func (idx *EncryptedIndex) ClearMemory() {
	idx.mu.Lock()
	idx.clearLocked()
	idx.mu.Unlock()
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
// associating them with the given entry path, and records the deduplicated
// token set in the reverse path→tokens map.
func addToTokenIndex(ti map[string]map[string]struct{}, pt map[string][]string, values []string, path string) {
	tokens := uniqueTokens(values)
	for _, token := range tokens {
		if ti[token] == nil {
			ti[token] = make(map[string]struct{})
		}
		ti[token][path] = struct{}{}
	}
	if pt != nil {
		pt[path] = tokens
	}
}

// uniqueTokens returns the deduplicated set of tokens across all values.
func uniqueTokens(values []string) []string {
	seen := make(map[string]struct{})
	var tokens []string
	for _, val := range values {
		for _, token := range tokenize(val) {
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			tokens = append(tokens, token)
		}
	}
	return tokens
}

// ensurePathTokens lazily rebuilds the reverse path→tokens map from Values
// for index documents written before PathTokens existed. This runs at most
// once per legacy document; afterwards removals are O(tokens of the path).
func ensurePathTokens(doc *indexDoc) {
	if doc.PathTokens != nil {
		return
	}
	doc.PathTokens = make(map[string][]string, len(doc.Values))
	for path, values := range doc.Values {
		doc.PathTokens[path] = uniqueTokens(values)
	}
}

// removeFromTokenIndex removes all references to a path from the token index
// using the reverse path→tokens map, so only the tokens that actually occur
// in the removed path are touched. Empty token maps are cleaned up to keep
// the index compact.
func removeFromTokenIndex(ti map[string]map[string]struct{}, pt map[string][]string, path string) {
	tokens, ok := pt[path]
	if !ok {
		return
	}
	for _, token := range tokens {
		paths, found := ti[token]
		if !found {
			continue
		}
		delete(paths, path)
		if len(paths) == 0 {
			delete(ti, token)
		}
	}
	delete(pt, path)
}

// addToHostIndex associates entry path with normalized hosts in doc.HostIndex and doc.PathHosts.
func addToHostIndex(hi map[string]map[string]struct{}, ph map[string][]string, hosts []string, path string) {
	if len(hosts) == 0 {
		return
	}
	for _, host := range hosts {
		if hi[host] == nil {
			hi[host] = make(map[string]struct{})
		}
		hi[host][path] = struct{}{}
	}
	if ph != nil {
		ph[path] = hosts
	}
}

// removeFromHostIndex removes all references to path from doc.HostIndex using doc.PathHosts.
func removeFromHostIndex(hi map[string]map[string]struct{}, ph map[string][]string, path string) {
	hosts, ok := ph[path]
	if !ok {
		return
	}
	for _, host := range hosts {
		paths, found := hi[host]
		if !found {
			continue
		}
		delete(paths, path)
		if len(paths) == 0 {
			delete(hi, host)
		}
	}
	delete(ph, path)
}

// ensurePathHosts lazily rebuilds the reverse path→hosts map from HostIndex
// for index documents written before PathHosts existed.
func ensurePathHosts(doc *indexDoc) {
	if doc.PathHosts != nil || doc.HostIndex == nil {
		if doc.HostIndex == nil {
			doc.HostIndex = make(map[string]map[string]struct{})
		}
		if doc.PathHosts == nil {
			doc.PathHosts = make(map[string][]string)
		}
		return
	}
	doc.PathHosts = make(map[string][]string)
	for host, paths := range doc.HostIndex {
		for path := range paths {
			doc.PathHosts[path] = append(doc.PathHosts[path], host)
		}
	}
}

// matchEntriesWithDoc returns the subset of candidates whose stored values
// contain needle as a case-insensitive substring. It operates purely on the
// provided doc without any I/O.
func matchEntriesWithDoc(candidates []string, needle string, doc *indexDoc) map[string]struct{} {
	needleLower := strings.ToLower(needle)
	matching := make(map[string]struct{}, len(candidates))

	if isSingleToken(needle) && doc.TokenIndex != nil {
		if paths, ok := doc.TokenIndex[needleLower]; ok {
			for _, path := range candidates {
				if _, found := paths[path]; found {
					matching[path] = struct{}{}
				}
			}
			if len(matching) > 0 {
				return matching
			}
		}
	}

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
	return matching
}

// matchHostWithDoc returns the subset of candidates whose url field matches
// targetHost. If candidates is non-empty, only candidates that match are
// returned; if candidates is empty, all matching paths in the doc are returned.
func matchHostWithDoc(candidates []string, targetHost string, doc *indexDoc) map[string]struct{} {
	if doc.HostIndex == nil {
		return make(map[string]struct{})
	}

	paths, found := doc.HostIndex[targetHost]
	if !found || len(paths) == 0 {
		return make(map[string]struct{})
	}

	matching := make(map[string]struct{}, len(paths))
	if len(candidates) > 0 {
		candSet := make(map[string]struct{}, len(candidates))
		for _, c := range candidates {
			candSet[c] = struct{}{}
		}
		for path := range paths {
			if _, ok := candSet[path]; ok {
				matching[path] = struct{}{}
			}
		}
	} else {
		for path := range paths {
			matching[path] = struct{}{}
		}
	}
	return matching
}
