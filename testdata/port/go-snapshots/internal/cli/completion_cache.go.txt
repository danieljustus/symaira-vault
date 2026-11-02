package cli

import (
	"sync"
	"time"
)

// completionCacheTTL is how long cached completion entries stay valid.
// Short enough to pick up vault changes quickly, long enough to avoid
// redundant vault opens during rapid TAB completion cycles.
const completionCacheTTL = 5 * time.Second

// completionCacheEntry holds a snapshot of vault entry paths and the time
// they were fetched. Only paths are cached — never secret content.
type completionCacheEntry struct {
	paths     []string
	timestamp time.Time
}

// CompletionCache provides thread-safe, TTL-based caching of vault entry
// paths for shell completion. It is keyed by vault directory so that
// multiple profiles or --vault overrides don't collide.
type CompletionCache struct {
	mu      sync.Mutex
	entries map[string]*completionCacheEntry
}

// newCompletionCache returns a ready-to-use cache.
func newCompletionCache() *CompletionCache {
	return &CompletionCache{
		entries: make(map[string]*completionCacheEntry),
	}
}

// Get returns cached entry paths for the given vault directory, or false
// if the cache has no entry or the entry has expired.
func (c *CompletionCache) Get(vaultDir string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[vaultDir]
	if !ok || time.Since(entry.timestamp) > completionCacheTTL {
		return nil, false
	}
	return entry.paths, true
}

// Set stores entry paths for the given vault directory with the current
// timestamp. Only paths are stored — never secret content.
func (c *CompletionCache) Set(vaultDir string, paths []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[vaultDir] = &completionCacheEntry{
		paths:     paths,
		timestamp: time.Now(),
	}
}

// Invalidate removes the cached entry for a specific vault directory.
func (c *CompletionCache) Invalidate(vaultDir string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, vaultDir)
}

// InvalidateAll clears all cached completions.
func (c *CompletionCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*completionCacheEntry)
}

// globalCompletionCache is the package-level cache used by entryPathSuggestions.
var globalCompletionCache = newCompletionCache()
