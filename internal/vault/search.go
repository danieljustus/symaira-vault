// Package vault provides encrypted storage and search for Symaira Vault entries.
//
// =============================================================================
// DESIGN DOCUMENT: Scalable Search for Large Vaults
// =============================================================================
//
// Current Bottleneck:
// -------------------
// Find() uses a two-pass approach. The first pass (path matching) is fast O(n).
// The second pass (field search) requires decrypting ALL entries where the path
// didn't match. This sequential decryption is the primary bottleneck for large
// vaults. For a vault with 50k entries where no paths match, we must sequentially
// decrypt 50k entries before returning results.
//
// Why Concurrent Decryption Helps:
// --------------------------------
// Modern CPUs have multiple cores. Sequential decryption leaves cores idle.
// By decrypting entries in parallel using a bounded worker pool, we can
// utilize multiple cores simultaneously, proportionally reducing wall-clock time.
//
// Bounded Parallelism Rationale:
// -----------------------------
// We use a bounded worker pool (default: 4 concurrent decryptions) rather than
// unbounded parallelism for these reasons:
//
//  1. Memory Pressure: Each decrypted entry consumes memory. With unbounded
//     parallelism on a 50k entry vault, we could spawn 50k goroutines all
//     trying to decrypt simultaneously, causing memory exhaustion.
//
//  2. I/O Saturation: The underlying storage (SSD/HDD) has finite read throughput.
//     Beyond a certain concurrency level, additional workers simply compete for
//     the same I/O bandwidth without improvement.
//
//  3. Cryptographic Operations: Age decryption involves CPU-intensive operations
//     (X25519 key exchange, ChaCha20-Poly1305). Too many concurrent operations
//     can cause CPU cache thrashing.
//
//  4. Practical Results: Testing shows 4 workers provides near-optimal throughput
//     for typical user machines while keeping memory bounded.
//
// Performance Targets (4 workers):
// --------------------------------
// - 50k entries, path-only: ~500ms (no decryption needed)
// - 50k entries, field-search: ~2-4s (bounded by decrypt parallelism)
// - 10k entries, field-search: ~500ms-1s
// - 1k entries, field-search: ~100-200ms
//
// Security Tradeoffs of Persistent Encrypted Index:
// ------------------------------------------------
// An alternative approach would be to build a persistent index that maps
// search terms to encrypted entry references. This would enable O(1) or O(log n)
// searches without decryption.
//
// Security Considerations:
//   - A persistent index MUST be encrypted at rest to prevent leakage of entry
//     relationships and search patterns
//   - The index encryption key must be derived from the user's passphrase (like
//     the vault identity key) ensuring only authorized users can access it
//   - Even with encryption, an index reveals search patterns over time:
//   - Which terms are searched frequently
//   - Which entries are accessed together
//   - Temporal patterns of access
//   - If the index is stored alongside the vault (e.g., in the vault directory),
//     it could be stolen alongside encrypted entries
//
// Attack Scenarios:
//   - A passive observer who steals the vault but not the passphrase: encrypted
//     index provides no additional advantage over encrypted entries
//   - An active observer with passphrase but no vault: reveals search history
//     but not content
//   - A side-channel attack on a compromised machine: index access patterns
//     could reveal search behavior even with encrypted index
//
// For these reasons, we currently prefer the on-demand decrypt approach
// which provides no persistent search metadata to steal.
//
// Future encrypted index implementation would need to:
// 1. Use a key derived from the vault's master key
// 2. Store only term->entry mapping, never plaintext content
// 3. Consider adding plausible deniability via fake entries
//
// =============================================================================
// INDEX-FIRST FIELD SEARCH (issue #351)
// =============================================================================
//
// As of v0.4.1, the encrypted search index (internal/vault/search_index.go)
// doubles as a field-search accelerator:
//
//   - Build: when the index is built (lazily on first FindWithOptions after
//     vault unlock) it stores, per entry, a token→path map derived from
//     lowercased, space/punctuation-split tokens of every string value
//     (`indexDoc.TokenIndex`, search_index.go).
//   - Lookup: `filterPathsUsingIndex` decrypts the index once and uses the
//     token map to return the candidate set of entry paths whose values
//     contain the query token. For single-token queries the fast path is
//     O(1) per candidate; multi-token or partial-substring queries fall
//     back to a scan of `indexDoc.Values` (also inside the encrypted blob).
//   - Decrypt: only the candidate paths in `pathsNeedingDecrypt` are
//     decrypted for the final field-name resolution step. The O(n) full
//     decrypt pass is therefore avoided in the common case.
//
// FALLBACK POLICY (graceful degradation, issue #351 acceptance criterion):
//
//	The fallback to the original O(n) decrypt-everything pass is triggered
//	when ANY of the following is true:
//	  1. No identity is available (caller must not pass nil).
//	  2. The on-disk index file does not exist OR is stale (entry count
//	     mismatch) OR cannot be decrypted (corruption/wrong key) —
//	     `filterPathsUsingIndex` returns the input candidates unchanged
//	     and `FindWithOptions` then decrypts every non-path-matching entry.
//	  3. The on-disk index exists but `MatchEntries` reports zero
//	     candidates (the needle token has no entry in the token index).
//	     The search returns the empty set, which is correct: no entry
//	     contains the query, so there is nothing to decrypt. (A subsequent
//	     search for a different token would still use the index.)
//	The fallback path therefore always preserves correct results; the
//	index is a pure performance optimization. No plaintext ever leaves the
//	encrypted envelope on disk (see `search_index_test.go::TestSearchIndex
//	OnDiskHasNoPlaintextLeakage`).
//
// =============================================================================
// END DESIGN DOCUMENT
// =============================================================================
//
// Performance Characteristics:
//
// List is O(n) where n is the number of entries. It performs no decryption,
// only directory walking. For large vaults (1k+ entries), List is fast.
//
// Find uses a two-pass approach:
//   - First pass: O(n) path-only comparison (no decryption)
//   - Second pass: O(k) decryption + field search where k = entries where path didn't match
//
// The fast path optimization means:
//   - Queries matching paths (e.g., "github" matching "github.com/user") avoid decryption entirely
//   - Only field content searches require decrypting entries
//
// FindConcurrent uses a bounded worker pool for parallel decryption:
//   - Same two-pass logic as Find, but decrypts entries concurrently
//   - Default worker count derived from runtime.NumCPU() capped at 8,
//     overridable via config vault.search_workers or FindOptions.MaxWorkers
//   - Best for field-search queries on large vaults (10k+ entries)
//
// Limits:
//   - 100 entries: ~10ms (path-only when possible)
//   - 1,000 entries: ~100ms (path-only when possible)
//   - 10,000 entries: ~1s (path-only when possible)
//   - Field searches scale with number of non-path-matching entries
package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"golang.org/x/exp/slices"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/metrics"
)

type Match struct {
	Path   string
	Fields []string
}

// listCacheFor returns the VaultCache that owns the in-memory caches for
// the given vaultDir. Vaults registered via registerVaultCache take
// precedence; otherwise the process-wide default cache is used.
func listCacheFor(vaultDir string) *VaultCache {
	if c := lookupVaultCache(vaultDir); c != nil {
		return c
	}
	return defaultVaultCache
}

// CurrentSearchIdentity returns the cached decryption identity from the vault,
// or nil if no vault identity is available (e.g., vault not opened).
func (v *Vault) CurrentSearchIdentity() *age.X25519Identity {
	if v == nil {
		return nil
	}
	return v.searchIdentity.Load()
}

// SearchWorkerCount returns the number of concurrent decryption workers
// to use for search/listing operations. When configured > 0, that value is
// used (capped at 64 to prevent resource exhaustion). Otherwise it
// auto-scales to min(runtime.NumCPU(), 8).
func SearchWorkerCount(configured int) int {
	if configured > 0 {
		if configured > 64 {
			return 64
		}
		return configured
	}
	cpus := runtime.NumCPU()
	if cpus > 8 {
		return 8
	}
	if cpus < 1 {
		return 1
	}
	return cpus
}

// List returns all entry paths in the vault, optionally filtered by prefix.
// It uses os.ReadDir for efficient directory traversal without stat calls.
// Results are cached with a 30-second TTL to avoid repetitive walks during
// MCP sessions. The cache invalidates automatically when directory mtimes change.
// When pseudonymization is enabled, entries are decrypted to extract the plaintext
// path from the entry data.
func List(vaultDir string, prefix string, identity *age.X25519Identity) ([]string, error) {
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return nil, err
	}
	if isPseudonymizeEnabled(cfg) {
		if identity == nil {
			return nil, fmt.Errorf("identity required for pseudonymized vault listing")
		}
		workers := 0
		if cfg != nil && cfg.Vault != nil {
			workers = cfg.Vault.SearchWorkers
		}
		return listPseudonymized(vaultDir, prefix, identity, workers)
	}

	// Check cache when listing the entire vault (prefix == "").
	if prefix == "" {
		if cached := listCacheFor(vaultDir).cachedList(vaultDir); cached != nil {
			metrics.RecordVaultOperationDuration("list_cached", 0)
			return cached, nil
		}
	}

	// Manifest fast path: when listing the entire vault without a prefix,
	// the manifest already holds every entry path. This avoids a full
	// directory walk. Falls back to walk on any error (missing manifest,
	// no identity, decrypt failure).
	if prefix == "" {
		if paths := listViaManifest(vaultDir, identity); paths != nil {
			listCacheFor(vaultDir).storeListCache(vaultDir, paths)
			return paths, nil
		}
	}

	start := time.Now()
	seen := map[string]struct{}{}

	if err := listEntriesFast(entriesDir(vaultDir), entriesDir(vaultDir), prefix, seen, false); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	// Skip the legacy top-level walk when detectLegacyMode confirmed no legacy
	// entries exist. Saves a filepath.WalkDir over the whole vault dir for the
	// common (non-legacy) case.
	skipLegacyWalk := cfg != nil && cfg.Vault != nil && cfg.Vault.LegacyMode != nil && !*cfg.Vault.LegacyMode
	if !skipLegacyWalk {
		if err := listEntriesFast(vaultDir, vaultDir, prefix, seen, true); err != nil {
			return nil, err
		}
	}

	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	metrics.RecordVaultOperationDuration("list", time.Since(start))
	metrics.RecordVaultEntryCount(vaultDir, len(paths))

	if prefix == "" {
		listCacheFor(vaultDir).storeListCache(vaultDir, paths)
	}

	return paths, nil
}

// listPseudonymized walks all .age files under entries/ and decrypts each to extract
// the plaintext entry path from entry.Path. Falls back to the relative filepath
// if entry.Path is empty (backward compatibility with non-pseudonymized entries
// stored alongside pseudonymized ones).
//
// Uses a bounded worker pool for parallel decryption and caches results
// (including decrypted entry data) for reuse by FindWithOptions.
func listPseudonymized(vaultDir, prefix string, identity *age.X25519Identity, configuredWorkers int) ([]string, error) {
	return listPseudonymizedWithIdentity(vaultDir, prefix, identity, configuredWorkers)
}

func listPseudonymizedWithIdentity(vaultDir, prefix string, identity *age.X25519Identity, configuredWorkers int) ([]string, error) {
	if identity == nil {
		return nil, fmt.Errorf("no search identity available for pseudonymized listing")
	}

	// Check cache for full-vault listings (prefix == "").
	if prefix == "" {
		if paths := listCacheFor(vaultDir).cachedPseudonymizedList(vaultDir, identity); paths != nil {
			metrics.RecordVaultOperationDuration("list_pseudonymized_cached", 0)
			return paths, nil
		}
	}

	start := time.Now()

	// First pass: walk filesystem to collect all .age file paths.
	// This is fast O(n) and does not involve decryption.
	var filePaths []string
	err := filepath.WalkDir(entriesDir(vaultDir), func(filePath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(filePath) != ".age" { //nolint:goconst // file extension literal
			return nil
		}
		filePaths = append(filePaths, filePath)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	if len(filePaths) == 0 {
		metrics.RecordVaultOperationDuration("list_pseudonymized", time.Since(start))
		metrics.RecordVaultEntryCount(vaultDir, 0)
		if prefix == "" {
			listCacheFor(vaultDir).storePseudonymizedListCache(vaultDir, identity, nil, nil)
		}
		return nil, nil
	}

	// Second pass: decrypt entries in parallel using a bounded worker pool.
	maxWorkers := SearchWorkerCount(configuredWorkers)

	type decryptResult struct {
		entryPath string
		data      map[string]any
	}

	fileChan := make(chan string, len(filePaths))
	resultChan := make(chan decryptResult, len(filePaths))

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fp := range fileChan {
				// #nosec G304 -- fp comes from filepath.WalkDir of the vault entries directory
				raw, readErr := os.ReadFile(fp)
				if readErr != nil {
					continue
				}

				plaintext, decryptErr := vaultcrypto.Decrypt(raw, identity)
				if decryptErr != nil {
					continue
				}

				var entry Entry
				if jsonErr := json.Unmarshal(plaintext, &entry); jsonErr != nil {
					vaultcrypto.Wipe(plaintext)
					continue
				}
				vaultcrypto.Wipe(plaintext)

				entryPath := entry.Path
				if entryPath == "" {
					rel, relErr := filepath.Rel(entriesDir(vaultDir), fp)
					if relErr != nil {
						continue
					}
					entryPath = strings.TrimSuffix(filepath.ToSlash(rel), ".age")
				}

				if prefix != "" && !strings.HasPrefix(entryPath, prefix) {
					continue
				}

				resultChan <- decryptResult{entryPath: entryPath, data: entry.Data}
			}
		}()
	}

	go func() {
		for _, fp := range filePaths {
			fileChan <- fp
		}
		close(fileChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	paths := make([]string, 0, len(filePaths))
	cachedEntries := make(map[string]map[string]any, len(filePaths))

	for result := range resultChan {
		if result.entryPath == "" {
			continue
		}
		paths = append(paths, result.entryPath)
		if result.data != nil {
			if cachedData := pseudonymCacheSafeData(result.data); cachedData != nil {
				cachedEntries[result.entryPath] = cachedData
			}
		}
	}

	sort.Strings(paths)

	if prefix == "" {
		listCacheFor(vaultDir).storePseudonymizedListCache(vaultDir, identity, paths, cachedEntries)
	}

	metrics.RecordVaultOperationDuration("list_pseudonymized", time.Since(start))
	metrics.RecordVaultEntryCount(vaultDir, len(paths))
	return paths, nil
}

func pseudonymCacheSafeData(data map[string]any) map[string]any {
	if len(data) == 0 {
		return nil
	}
	cloned, stripped := cloneWithoutSensitiveFields("", data)
	if stripped {
		return nil
	}
	return cloned
}

func cloneWithoutSensitiveFields(prefix string, data map[string]any) (map[string]any, bool) {
	cloned := make(map[string]any, len(data))
	stripped := false
	for key, value := range data {
		field := key
		if prefix != "" {
			field = prefix + "." + key
		}
		if isSensitiveCacheField(field) {
			stripped = true
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			nested, nestedStripped := cloneWithoutSensitiveFields(field, typed)
			if nestedStripped {
				stripped = true
				continue
			}
			cloned[key] = nested
		default:
			cloned[key] = value
		}
	}
	return cloned, stripped
}

func isSensitiveCacheField(field string) bool {
	return !isSafeCacheField(field)
}

// isSafeCacheField returns true if the field is known to be non-sensitive
// metadata that can safely be retained in the pseudonymized list cache.
// Only fields in this allowlist are cached; all other fields are stripped
// to prevent secrets from remaining in heap memory for the cache TTL.
var safeCacheFields = map[string]bool{
	"username":    true,
	"user":        true,
	"email":       true,
	"url":         true,
	"host":        true,
	"domain":      true,
	"tags":        true,
	"notes":       true,
	"note":        true,
	"description": true,
	"title":       true,
	"name":        true,
	"group":       true,
	"category":    true,
	"type":        true,
	"created":     true,
	"updated":     true,
	"modified":    true,
	"version":     true,
	"label":       true,
	"labels":      true,
	"service":     true,
	"provider":    true,
	"website":     true,
	"pathname":    true,
	"path":        true,
	"identifier":  true,
	"id":          true,
	"icon":        true,
	"favicon":     true,
	"language":    true,
	"locale":      true,
	"color":       true,
	"icon_url":    true,
	"avatar_url":  true,
	"issuer":      true,
	"algorithm":   true,
	"digits":      true,
	"period":      true,
}

func isSafeCacheField(field string) bool {
	field = strings.ToLower(field)
	if safeCacheFields[field] {
		return true
	}
	for safe := range safeCacheFields {
		if strings.HasSuffix(field, "."+safe) {
			return true
		}
	}
	return false
}

// listViaManifest returns entry paths from the manifest when available and
// valid. Returns nil on any error so callers fall back to directory walk.
func listViaManifest(vaultDir string, identity *age.X25519Identity) []string {
	if identity == nil {
		return nil
	}
	FlushManifestUpdates()
	m, err := LoadManifest(vaultDir, identity)
	if err != nil || m == nil || len(m.Entries) == 0 {
		return nil
	}
	paths := make([]string, 0, len(m.Entries))
	for path := range m.Entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	metrics.RecordVaultEntryCount(vaultDir, len(paths))
	return paths
}

func listEntriesFast(root, base, prefix string, seen map[string]struct{}, legacy bool) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if legacy && path != root && (d.Name() == entriesDirName || d.Name() == ".git") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".age" { //nolint:goconst // file extension literal
			return nil
		}

		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		if legacy && (filepath.ToSlash(rel) == "identity.age" || filepath.ToSlash(rel) == "manifest.age") { //nolint:goconst // filename literal
			return nil
		}
		rel = strings.TrimSuffix(filepath.ToSlash(rel), ".age") //nolint:goconst // file extension literal
		if prefix != "" && !strings.HasPrefix(rel, prefix) {
			return nil
		}
		seen[rel] = struct{}{}
		return nil
	})
}

// FindOptions configures search behavior for FindWithOptions.
type FindOptions struct {
	// MaxWorkers controls the number of concurrent decryption workers.
	// Values <= 0 use sequential search (same as Find).
	MaxWorkers int
	// ScopeFilter, if non-nil, restricts search to paths that pass the filter.
	// Applied before decryption to avoid decrypting out-of-scope entries.
	ScopeFilter func(path string) bool
	// RedactFieldPatterns, if non-nil, prevents searching and reporting field
	// names that match redaction patterns, closing the side-channel where an
	// agent could probe the existence of a value in a redacted field via
	// substring search (SEC-002).
	RedactFieldPatterns []string
}

// isRedactedField checks if a field name matches any redaction pattern.
// Supports exact match, "*" (wildcard), and "prefix.*" (prefix wildcard).
func isRedactedField(field string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == field || pattern == "*" {
			return true
		}
		if strings.HasSuffix(pattern, ".*") {
			prefix := strings.TrimSuffix(pattern, ".*")
			if strings.HasPrefix(field, prefix+".") {
				return true
			}
		}
	}
	return false
}

// FindWithOptions searches vault entries with configurable options.
// It supports both sequential and concurrent decryption, and optional
// scope filtering before decrypt.
// Prefer Vault.FindWithOptions which passes identity from the vault instance.
//
//nolint:gocyclo // Search orchestration: listing, filtering, decryption, ranking
func FindWithOptions(vaultDir string, query string, opts FindOptions, identity *age.X25519Identity) ([]Match, error) {
	return findWithOptionsIdentity(vaultDir, query, opts, identity)
}

func findWithOptionsIdentity(vaultDir string, query string, opts FindOptions, identity *age.X25519Identity) ([]Match, error) {
	start := time.Now()
	defer func() {
		metrics.RecordVaultOperationDuration("search", time.Since(start))
	}()

	paths, err := List(vaultDir, "", identity)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, fmt.Errorf("no search identity available")
	}

	needle := strings.ToLower(query)
	var matches []Match
	pathOnlyMatches := make([]Match, 0)
	pathsNeedingDecrypt := make([]string, 0, len(paths))

	// First pass: separate path-only matches from paths needing field search
	for _, path := range paths {
		if opts.ScopeFilter != nil && !opts.ScopeFilter(path) {
			continue
		}
		if needle == "" || strings.Contains(strings.ToLower(path), needle) {
			// Path matches - no decryption needed
			pathOnlyMatches = append(pathOnlyMatches, Match{Path: path, Fields: []string{"path"}})
		} else {
			// Path doesn't match, need to decrypt and search fields
			pathsNeedingDecrypt = append(pathsNeedingDecrypt, path)
		}
	}

	// Use encrypted search index to pre-filter paths needing field decryption.
	// The index maps search tokens to entry paths. Entries whose field values
	// don't contain any query token can be safely skipped.
	if len(pathsNeedingDecrypt) > 0 && needle != "" {
		pathsNeedingDecrypt = filterPathsUsingIndex(vaultDir, pathsNeedingDecrypt, needle, identity)
	}

	maxWorkers := opts.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = min(runtime.NumCPU(), 8)
	}
	if maxWorkers <= 1 {
		for _, path := range pathsNeedingDecrypt {
			data := listCacheFor(vaultDir).cachedPseudonymizedEntry(vaultDir, identity, path)
			if data == nil {
				entry, err := ReadEntry(vaultDir, path, identity)
				if err != nil {
					return nil, err
				}
				data = entry.Data
			}

			fields := make(map[string]struct{})
			CollectFieldMatches(fields, "", data, needle, opts.RedactFieldPatterns)

			if len(fields) == 0 {
				continue
			}

			matchFields := make([]string, 0, len(fields))
			for field := range fields {
				matchFields = append(matchFields, field)
			}
			sort.Strings(matchFields)
			matches = append(matches, Match{Path: path, Fields: matchFields})
		}
	} else {
		if len(pathsNeedingDecrypt) == 0 {
			sort.Slice(pathOnlyMatches, func(i, j int) bool {
				return pathOnlyMatches[i].Path < pathOnlyMatches[j].Path
			})
			return pathOnlyMatches, nil
		}

		type decryptResult struct {
			err    error
			path   string
			fields []string
		}

		pathChan := make(chan string, len(pathsNeedingDecrypt))
		resultChan := make(chan decryptResult, len(pathsNeedingDecrypt))

		var wg sync.WaitGroup

		for i := 0; i < maxWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for path := range pathChan {
					data := listCacheFor(vaultDir).cachedPseudonymizedEntry(vaultDir, identity, path)
					if data == nil {
						entry, err := ReadEntry(vaultDir, path, identity)
						if err != nil {
							resultChan <- decryptResult{err: err, path: path}
							continue
						}
						data = entry.Data
					}

					fields := make(map[string]struct{})
					CollectFieldMatches(fields, "", data, needle, opts.RedactFieldPatterns)

					if len(fields) == 0 {
						resultChan <- decryptResult{path: path, fields: nil}
						continue
					}

					matchFields := make([]string, 0, len(fields))
					for field := range fields {
						matchFields = append(matchFields, field)
					}
					sort.Strings(matchFields)
					resultChan <- decryptResult{path: path, fields: matchFields}
				}
			}()
		}

		go func() {
			for _, path := range pathsNeedingDecrypt {
				pathChan <- path
			}
			close(pathChan)
		}()

		go func() {
			wg.Wait()
			close(resultChan)
		}()

		for result := range resultChan {
			if result.err != nil {
				return nil, result.err
			}
			if result.fields != nil {
				matches = append(matches, Match{Path: result.path, Fields: result.fields})
			}
		}
	}

	// Combine path-only matches with field matches
	matches = append(matches, pathOnlyMatches...)

	sort.Slice(matches, func(i, j int) bool {
		iPath := hasField(matches[i].Fields, "path")
		jPath := hasField(matches[j].Fields, "path")
		if iPath != jPath {
			return iPath
		}
		return matches[i].Path < matches[j].Path
	})

	return matches, nil
}

func hasField(fields []string, want string) bool {
	return slices.Contains(fields, want)
}

// filterPathsUsingIndex uses the encrypted search index to reduce the set of
// entry paths that need field-level decryption. It returns only paths whose
// stored string values contain the query as a substring. On any error the
// original slice is returned unchanged, preserving correct behavior.
//
// Fallback policy (graceful degradation): if the index cannot be loaded, the
// rebuild path is exercised, or the rebuild fails (e.g., the wrong identity
// is supplied and the resulting index is empty), the function returns the
// input candidates unchanged so the caller can still perform a full decrypt
// pass. This guards against silently returning an empty set when the
// on-disk index was built with a different key.
func filterPathsUsingIndex(vaultDir string, candidates []string, needle string, identity *age.X25519Identity) []string {
	if identity == nil {
		return candidates
	}

	// Build or load the index only when the shared slot does not already cover
	// this exact vault directory and identity. Covers (rather than IsBuilt)
	// ensures a second vault opened with the same identity does not reuse the
	// first vault's index.
	if !globalIndex.Covers(vaultDir, identity) {
		if err := globalIndex.loadFromDisk(vaultDir, identity); err != nil || !globalIndex.Covers(vaultDir, identity) {
			if err := globalIndex.Build(vaultDir, identity); err != nil {
				return candidates
			}
		}
	}

	matching, err := globalIndex.MatchEntries(vaultDir, identity, candidates, needle)
	if err != nil {
		// The slot now holds a different vault, or the index is stale: rebuild
		// for this vault and retry once. Build overwrites the in-memory slot and
		// rewrites this vault's on-disk index without deleting another vault's.
		if buildErr := globalIndex.Build(vaultDir, identity); buildErr != nil {
			return candidates
		}
		matching, err = globalIndex.MatchEntries(vaultDir, identity, candidates, needle)
		if err != nil {
			return candidates
		}
	}

	if len(matching) == 0 {
		return nil
	}
	result := make([]string, 0, len(matching))
	for path := range matching {
		result = append(result, path)
	}
	return result
}

// collectStringValues recursively collects string values from a map.

func CollectFieldMatches(matches map[string]struct{}, prefix string, value any, needle string, redactPatterns []string) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			field := key
			if prefix != "" {
				field = prefix + "." + key
			}
			// Skip redacted fields entirely — prevents probing existence of a
			// value in a redacted field via substring search (SEC-002).
			if isRedactedField(field, redactPatterns) {
				continue
			}
			CollectFieldMatches(matches, field, typed[key], needle, redactPatterns)
		}
	case []any:
		for i, item := range typed {
			field := fmt.Sprintf("%s[%d]", prefix, i)
			if prefix == "" {
				field = fmt.Sprintf("[%d]", i)
			}
			CollectFieldMatches(matches, field, item, needle, redactPatterns)
		}
	default:
		if prefix == "" {
			return
		}
		if isRedactedField(prefix, redactPatterns) {
			return
		}
		if needle == "" || strings.Contains(strings.ToLower(fmt.Sprint(typed)), needle) {
			matches[prefix] = struct{}{}
		}
	}
}
