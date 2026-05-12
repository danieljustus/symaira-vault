// Package vault provides encrypted storage and search for OpenPass entries.
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
//   - Default 4 concurrent workers balances throughput vs memory pressure
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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"
	"golang.org/x/exp/slices"

	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/metrics"
)

type Match struct {
	Path   string
	Fields []string
}

// listCacheEntry holds cached List results with invalidation metadata.
type listCacheEntry struct {
	paths        []string
	createdAt    time.Time
	entriesMtime time.Time
	vaultMtime   time.Time
}

// listCache provides TTL-cached path listings to avoid repetitive directory walks.
// It invalidates entries when the underlying directories' modification times change.
var listCache struct {
	mu    sync.RWMutex
	items map[string]listCacheEntry
	// TTL is the cache duration. It is a variable (not const) so tests can override it.
	ttl time.Duration
}

func init() {
	listCache.items = make(map[string]listCacheEntry)
	listCache.ttl = 30 * time.Second
}

// getDirMtime returns the modification time of a directory, or zero if unavailable.
func getDirMtime(dir string) time.Time {
	info, err := os.Stat(dir)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// cachedList returns cached paths if valid, or nil if cache miss / expired / invalidated.
func cachedList(vaultDir string) []string {
	listCache.mu.RLock()
	entry, ok := listCache.items[vaultDir]
	listCache.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.createdAt) > listCache.ttl {
		return nil
	}
	// Validate mtimes: if either directory changed since caching, invalidate
	if !getDirMtime(entriesDir(vaultDir)).Equal(entry.entriesMtime) {
		return nil
	}
	if !getDirMtime(vaultDir).Equal(entry.vaultMtime) {
		return nil
	}
	return entry.paths
}

// storeListCache stores the result of a List call for the given vaultDir.
func storeListCache(vaultDir string, paths []string) {
	listCache.mu.Lock()
	listCache.items[vaultDir] = listCacheEntry{
		paths:        append([]string(nil), paths...),
		createdAt:    time.Now(),
		entriesMtime: getDirMtime(entriesDir(vaultDir)),
		vaultMtime:   getDirMtime(vaultDir),
	}
	listCache.mu.Unlock()
}

// InvalidateListCache removes cached listings for a vault directory.
// Callers should invoke this after write operations that affect vault contents.
func InvalidateListCache(vaultDir string) {
	listCache.mu.Lock()
	delete(listCache.items, vaultDir)
	listCache.mu.Unlock()
}

// searchIdentity holds the cached decryption identity for search operations.
//
// DESIGN DECISION: Global State vs Per-Vault Context
//
// This is intentionally global state because:
//  1. OpenPass operates with a single active vault per process
//  2. The identity is session-scoped (tied to unlock duration), not vault-scoped
//  3. atomic.Pointer provides lock-free thread-safe access verified by `go test -race`
//  4. Per-vault caching would add complexity without clear benefit for single-vault usage
//
// Tradeoffs accepted:
//   - Parallel vault access in tests requires careful sequencing
//   - Multiple vaults in same process share cache (invalid for OpenPass use case)
//
// Future: If multi-vault support is needed, add vaultDir key to a map[VaultDir]*Identity.
var searchIdentity atomic.Pointer[age.X25519Identity]

func rememberSearchIdentity(identity *age.X25519Identity) {
	if identity == nil {
		return
	}
	searchIdentity.Store(identity)
}

func currentSearchIdentity() *age.X25519Identity {
	return searchIdentity.Load()
}

// CurrentSearchIdentity returns the cached decryption identity, or nil if
// no identity has been cached yet (e.g., vault not unlocked in this session).
// This is used by health checks to verify manifest integrity without requiring
// the user to re-enter their passphrase.
func CurrentSearchIdentity() *age.X25519Identity {
	return currentSearchIdentity()
}

// List returns all entry paths in the vault, optionally filtered by prefix.
// It uses os.ReadDir for efficient directory traversal without stat calls.
// Results are cached with a 30-second TTL to avoid repetitive walks during
// MCP sessions. The cache invalidates automatically when directory mtimes change.
// When pseudonymization is enabled, entries are decrypted to extract the plaintext
// path from the entry data.
func List(vaultDir string, prefix string) ([]string, error) {
	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return nil, err
	}
	if isPseudonymizeEnabled(cfg) {
		return listPseudonymized(vaultDir, prefix)
	}

	// Check cache when listing the entire vault (prefix == "").
	if prefix == "" {
		if cached := cachedList(vaultDir); cached != nil {
			metrics.RecordVaultOperationDuration("list_cached", 0)
			return cached, nil
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
		storeListCache(vaultDir, paths)
	}

	return paths, nil
}

// listPseudonymized walks all .age files under entries/ and decrypts each to extract
// the plaintext entry path from entry.Path. Falls back to the relative filepath
// if entry.Path is empty (backward compatibility with non-pseudonymized entries
// stored alongside pseudonymized ones).
func listPseudonymized(vaultDir, prefix string) ([]string, error) {
	identity := currentSearchIdentity()
	if identity == nil {
		return nil, fmt.Errorf("no search identity available for pseudonymized listing")
	}

	start := time.Now()
	var paths []string

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

		// #nosec G304 -- filePath comes from filepath.WalkDir of the vault entries directory
		raw, readErr := os.ReadFile(filePath)
		if readErr != nil {
			return nil
		}

		plaintext, decryptErr := vaultcrypto.Decrypt(raw, identity)
		if decryptErr != nil {
			return nil
		}
		defer vaultcrypto.Wipe(plaintext)

		var entry Entry
		if jsonErr := json.Unmarshal(plaintext, &entry); jsonErr != nil {
			return nil
		}

		entryPath := entry.Path
		if entryPath == "" {
			rel, relErr := filepath.Rel(entriesDir(vaultDir), filePath)
			if relErr != nil {
				return nil
			}
			entryPath = strings.TrimSuffix(filepath.ToSlash(rel), ".age")
		}

		if prefix != "" && !strings.HasPrefix(entryPath, prefix) {
			return nil
		}
		paths = append(paths, entryPath)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	sort.Strings(paths)
	metrics.RecordVaultOperationDuration("list_pseudonymized", time.Since(start))
	metrics.RecordVaultEntryCount(vaultDir, len(paths))
	return paths, nil
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
//
//nolint:gocyclo // Search orchestration: listing, filtering, decryption, ranking
func FindWithOptions(vaultDir string, query string, opts FindOptions) ([]Match, error) {
	start := time.Now()
	defer func() {
		metrics.RecordVaultOperationDuration("search", time.Since(start))
	}()

	paths, err := List(vaultDir, "")
	if err != nil {
		return nil, err
	}

	identity := currentSearchIdentity()
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

	maxWorkers := opts.MaxWorkers
	if maxWorkers <= 0 {
		for _, path := range pathsNeedingDecrypt {
			entry, err := ReadEntry(vaultDir, path, identity)
			if err != nil {
				return nil, err
			}

			fields := make(map[string]struct{})
			CollectFieldMatches(fields, "", entry.Data, needle, opts.RedactFieldPatterns)

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
					entry, err := ReadEntry(vaultDir, path, identity)
					if err != nil {
						resultChan <- decryptResult{err: err, path: path}
						continue
					}

					fields := make(map[string]struct{})
					CollectFieldMatches(fields, "", entry.Data, needle, opts.RedactFieldPatterns)

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
