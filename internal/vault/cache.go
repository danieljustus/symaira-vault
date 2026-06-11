package vault

import (
	"container/list"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
)

const (
	defaultListCacheTTL      = 300 * time.Second
	minListCacheTTL          = 30 * time.Second
	maxListCacheTTL          = 10 * time.Minute
	defaultConfigCacheSize   = 32
	defaultListCacheVaults   = 16
	defaultPseudonymCacheTTL = 300 * time.Second
)

// VaultCacheConfig configures the in-memory caches owned by a VaultCache.
// The zero value produces a VaultCache with default settings.
type VaultCacheConfig struct {
	// ListCacheTTL is the base TTL for the directory listing cache.
	// Zero or negative disables TTL-based caching for directory listings.
	ListCacheTTL time.Duration

	// ConfigCacheSize is the maximum number of parsed vault configs
	// retained by the config cache. Zero or negative resets to the
	// default of 32 entries.
	ConfigCacheSize int
}

// VaultCache consolidates the in-memory caches previously scattered as
// package-level globals: the directory listing cache, the pseudonymized
// listing cache, and the parsed vault-config cache.
//
// The persistent encrypted search index (EncryptedIndex / globalIndex)
// remains a separate concern and is intentionally NOT part of this
// struct. Callers that need to wipe the persistent search index should
// invoke VaultCache.InvalidateSearchIndex or call EncryptedIndex.Invalidate
// directly.
//
// A VaultCache is safe for concurrent use by multiple goroutines. It is
// intended to be owned by a *Vault and accessed via the vault.Cache field.
type VaultCache struct {
	listCacheMu     sync.RWMutex
	listCacheIndex  map[string]*list.Element
	listCacheOrder  *list.List
	listCacheTTL    time.Duration
	configuredTTL   time.Duration
	listCacheHits   uint64
	listCacheMisses uint64

	pseudonymMu    sync.RWMutex
	pseudonymItems map[string]pseudonymizedCacheEntry
	pseudonymTTL   time.Duration

	configMu      sync.RWMutex
	configItems   map[string]configCacheEntry
	configMaxSize int
}

// listCacheEntry holds cached List results with invalidation metadata.
// Invalidation uses directory mtime (O(1)) instead of tree-walking hash.
type listCacheEntry struct {
	paths        []string
	createdAt    time.Time
	entriesMtime time.Time
	vaultMtime   time.Time
}

// listCachePayload pairs a vault directory key with its cached entry.
type listCachePayload struct {
	key   string
	entry listCacheEntry
}

// pseudonymizedCacheEntry holds cached pseudonymized list results.
// Unlike listCacheEntry, it may also store decrypted entry data so that
// FindWithOptions can reuse entries already decrypted during listing.
// Secret-bearing entries are deliberately omitted from entries so callers
// fall back to a single-entry decrypt instead of retaining those values in
// heap memory for the cache TTL.
type pseudonymizedCacheEntry struct {
	paths        []string
	entries      map[string]map[string]any
	createdAt    time.Time
	entriesMtime time.Time
	vaultMtime   time.Time
}

// configCacheEntry holds a parsed vault config together with the
// modification time of the source file for mtime-based invalidation.
type configCacheEntry struct {
	cfg        *vaultconfig.Config
	mtime      time.Time
	accessedAt time.Time
}

// NewVaultCache constructs a VaultCache with the given configuration.
// A nil config is equivalent to a zero-value VaultCacheConfig.
func NewVaultCache(cfg VaultCacheConfig) *VaultCache {
	if cfg.ConfigCacheSize <= 0 {
		cfg.ConfigCacheSize = defaultConfigCacheSize
	}
	ttl := cfg.ListCacheTTL
	if ttl < 0 {
		ttl = 0
	}
	return &VaultCache{
		listCacheIndex: make(map[string]*list.Element),
		listCacheOrder: list.New(),
		listCacheTTL:   ttl,
		configuredTTL:  ttl,
		pseudonymItems: make(map[string]pseudonymizedCacheEntry),
		pseudonymTTL:   defaultPseudonymCacheTTL,
		configItems:    make(map[string]configCacheEntry),
		configMaxSize:  cfg.ConfigCacheSize,
	}
}

// Invalidate drops all entries from every in-memory cache owned by this
// VaultCache. The persistent search index is unaffected.
func (c *VaultCache) Invalidate() {
	if c == nil {
		return
	}
	c.listCacheMu.Lock()
	c.listCacheIndex = make(map[string]*list.Element)
	c.listCacheOrder.Init()
	c.listCacheMu.Unlock()

	c.pseudonymMu.Lock()
	c.pseudonymItems = make(map[string]pseudonymizedCacheEntry)
	c.pseudonymMu.Unlock()

	c.configMu.Lock()
	c.configItems = make(map[string]configCacheEntry)
	c.configMu.Unlock()
}

// InvalidatePath removes cached data associated with a single entry
// path. The pseudonymized cache drops any per-vault entry whose
// contained decrypted data includes the path; the directory listing
// cache is keyed by vaultDir only and is left to the caller to flush
// when needed.
func (c *VaultCache) InvalidatePath(path string) {
	if c == nil {
		return
	}
	if path == "" {
		c.Invalidate()
		return
	}
	c.pseudonymMu.Lock()
	for k, entry := range c.pseudonymItems {
		if _, ok := entry.entries[path]; ok {
			delete(c.pseudonymItems, k)
		}
	}
	c.pseudonymMu.Unlock()
}

// InvalidateConfig drops the cached parsed config for vaultDir.
// Callers should invoke this after writing config.yaml so the next
// load sees the new value.
func (c *VaultCache) InvalidateConfig(vaultDir string) {
	if c == nil {
		return
	}
	c.configMu.Lock()
	delete(c.configItems, vaultDir)
	c.configMu.Unlock()
}

// InvalidateSearchIndex clears the global persistent encrypted search
// index and all in-memory caches.
func (c *VaultCache) InvalidateSearchIndex() {
	globalIndex.Invalidate()
	c.Invalidate()
}

// GetOrLoad returns the cached config associated with vaultDir, calling
// loader on miss and caching its result. It is the cache-miss-or-load
// helper for the config cache.
func (c *VaultCache) GetOrLoad(vaultDir string, loader func() (any, error)) (any, error) {
	if c == nil {
		return loader()
	}
	c.configMu.RLock()
	entry, ok := c.configItems[vaultDir]
	c.configMu.RUnlock()
	if ok && entry.cfg != nil {
		c.configMu.Lock()
		entry.accessedAt = time.Now()
		c.configItems[vaultDir] = entry
		c.configMu.Unlock()
		return entry.cfg, nil
	}
	v, err := loader()
	if err != nil {
		return nil, err
	}
	cfg, ok := v.(*vaultconfig.Config)
	if !ok {
		return v, nil
	}
	c.configMu.Lock()
	if c.configMaxSize > 0 && len(c.configItems) >= c.configMaxSize {
		var oldestKey string
		var oldestTime time.Time
		for k, e := range c.configItems {
			if oldestTime.IsZero() || e.accessedAt.Before(oldestTime) {
				oldestTime = e.accessedAt
				oldestKey = k
			}
		}
		if oldestKey != "" {
			delete(c.configItems, oldestKey)
		}
	}
	c.configItems[vaultDir] = configCacheEntry{cfg: cfg, mtime: time.Time{}, accessedAt: time.Now()}
	c.configMu.Unlock()
	return cfg, nil
}

// SetListCacheTTL overrides the effective list cache TTL. Pass 0 to
// disable caching. The adaptive TTL controller will not grow past the
// configured ceiling.
func (c *VaultCache) SetListCacheTTL(ttl time.Duration) {
	if c == nil {
		return
	}
	c.listCacheMu.Lock()
	if ttl <= 0 {
		c.listCacheTTL = 0
	} else {
		c.listCacheTTL = ttl
	}
	c.configuredTTL = ttl
	c.listCacheMu.Unlock()
}

// SetConfigCacheSize sets the maximum number of cached vault configs.
// Call during vault initialization with the value from config, or 0
// to reset to the default.
func (c *VaultCache) SetConfigCacheSize(n int) {
	if c == nil {
		return
	}
	if n <= 0 {
		n = defaultConfigCacheSize
	}
	c.configMu.Lock()
	c.configMaxSize = n
	c.configMu.Unlock()
}

// ListCacheTTL returns the current effective list-cache TTL. The
// returned value reflects the adaptive TTL controller.
func (c *VaultCache) ListCacheTTL() time.Duration {
	if c == nil {
		return 0
	}
	c.listCacheMu.RLock()
	defer c.listCacheMu.RUnlock()
	return c.listCacheTTL
}

// SetPseudonymCacheTTL sets the pseudonymized-list cache TTL.
func (c *VaultCache) SetPseudonymCacheTTL(ttl time.Duration) {
	if c == nil {
		return
	}
	c.pseudonymMu.Lock()
	c.pseudonymTTL = ttl
	c.pseudonymMu.Unlock()
}

// PseudonymCacheTTL returns the current effective pseudonymized-list
// cache TTL.
func (c *VaultCache) PseudonymCacheTTL() time.Duration {
	if c == nil {
		return 0
	}
	c.pseudonymMu.RLock()
	defer c.pseudonymMu.RUnlock()
	return c.pseudonymTTL
}

func (c *VaultCache) adaptListCacheTTL() {
	hits := atomic.LoadUint64(&c.listCacheHits)
	miss := atomic.LoadUint64(&c.listCacheMisses)
	total := hits + miss
	if total < 100 {
		return
	}
	ratio := float64(hits) / float64(total)
	c.listCacheMu.Lock()
	effectiveMax := maxListCacheTTL
	if c.configuredTTL > 0 && c.configuredTTL < effectiveMax {
		effectiveMax = c.configuredTTL
	}
	if ratio > 0.9 && c.listCacheTTL < effectiveMax {
		c.listCacheTTL *= 2
		if c.listCacheTTL > effectiveMax {
			c.listCacheTTL = effectiveMax
		}
	} else if ratio < 0.5 && c.listCacheTTL > minListCacheTTL {
		c.listCacheTTL /= 2
		if c.listCacheTTL < minListCacheTTL {
			c.listCacheTTL = minListCacheTTL
		}
	}
	c.listCacheMu.Unlock()
	atomic.StoreUint64(&c.listCacheHits, 0)
	atomic.StoreUint64(&c.listCacheMisses, 0)
}

// cachedList returns cached paths if valid, or nil if cache miss /
// expired / invalidated.
func (c *VaultCache) cachedList(vaultDir string) []string {
	if c == nil {
		return nil
	}
	c.listCacheMu.RLock()
	elem, ok := c.listCacheIndex[vaultDir]
	if !ok {
		c.listCacheMu.RUnlock()
		atomic.AddUint64(&c.listCacheMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	payload, ok := elem.Value.(*listCachePayload)
	if !ok {
		c.listCacheMu.RUnlock()
		atomic.AddUint64(&c.listCacheMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	entry := payload.entry
	ttl := c.listCacheTTL
	c.listCacheMu.RUnlock()
	if time.Since(entry.createdAt) > ttl {
		atomic.AddUint64(&c.listCacheMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	if !getDirMtime(entriesDir(vaultDir)).Equal(entry.entriesMtime) {
		atomic.AddUint64(&c.listCacheMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	if !getDirMtime(vaultDir).Equal(entry.vaultMtime) {
		atomic.AddUint64(&c.listCacheMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	atomic.AddUint64(&c.listCacheHits, 1)
	c.adaptListCacheTTL()
	c.listCacheMu.Lock()
	c.listCacheOrder.MoveToFront(elem)
	c.listCacheMu.Unlock()
	return entry.paths
}

// storeListCache stores the result of a List call for the given
// vaultDir. When the cache exceeds the per-cache vault limit the
// least-recently-used entry is evicted.
func (c *VaultCache) storeListCache(vaultDir string, paths []string) {
	if c == nil {
		return
	}
	c.listCacheMu.Lock()
	defer c.listCacheMu.Unlock()

	if elem, ok := c.listCacheIndex[vaultDir]; ok {
		payload, ok := elem.Value.(*listCachePayload)
		if !ok {
			return
		}
		payload.entry = listCacheEntry{
			paths:        append([]string(nil), paths...),
			createdAt:    time.Now(),
			entriesMtime: getDirMtime(entriesDir(vaultDir)),
			vaultMtime:   getDirMtime(vaultDir),
		}
		c.listCacheOrder.MoveToFront(elem)
		return
	}

	if c.listCacheOrder.Len() >= defaultListCacheVaults {
		oldest := c.listCacheOrder.Back()
		if oldest != nil {
			oldPayload, ok := oldest.Value.(*listCachePayload)
			if ok {
				delete(c.listCacheIndex, oldPayload.key)
				c.listCacheOrder.Remove(oldest)
			}
		}
	}

	payload := &listCachePayload{
		key: vaultDir,
		entry: listCacheEntry{
			paths:        append([]string(nil), paths...),
			createdAt:    time.Now(),
			entriesMtime: getDirMtime(entriesDir(vaultDir)),
			vaultMtime:   getDirMtime(vaultDir),
		},
	}
	elem := c.listCacheOrder.PushFront(payload)
	c.listCacheIndex[vaultDir] = elem
}

// pseudonymizedCacheKey builds a cache key unique to (vaultDir, identity).
// The recipient (public key) string is used rather than the full identity
// to avoid caching the secret key material in the in-memory map keys.
func pseudonymizedCacheKey(vaultDir string, identity *age.X25519Identity) string {
	return vaultDir + "\x00" + identity.Recipient().String()
}

// cachedPseudonymizedList returns cached pseudonymized paths if valid,
// or nil if cache miss / expired / invalidated.
func (c *VaultCache) cachedPseudonymizedList(vaultDir string, identity *age.X25519Identity) []string {
	if c == nil {
		return nil
	}
	key := pseudonymizedCacheKey(vaultDir, identity)
	c.pseudonymMu.RLock()
	entry, ok := c.pseudonymItems[key]
	c.pseudonymMu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.createdAt) > c.pseudonymTTL {
		return nil
	}
	if !getDirMtime(entriesDir(vaultDir)).Equal(entry.entriesMtime) {
		return nil
	}
	if !getDirMtime(vaultDir).Equal(entry.vaultMtime) {
		return nil
	}
	return entry.paths
}

// cachedPseudonymizedEntry returns the decrypted entry data for a
// single path from the pseudonymized cache, or nil if not found or
// invalid.
func (c *VaultCache) cachedPseudonymizedEntry(vaultDir string, identity *age.X25519Identity, path string) map[string]any {
	if c == nil {
		return nil
	}
	key := pseudonymizedCacheKey(vaultDir, identity)
	c.pseudonymMu.RLock()
	entry, ok := c.pseudonymItems[key]
	c.pseudonymMu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.createdAt) > c.pseudonymTTL {
		return nil
	}
	if !getDirMtime(entriesDir(vaultDir)).Equal(entry.entriesMtime) {
		return nil
	}
	if !getDirMtime(vaultDir).Equal(entry.vaultMtime) {
		return nil
	}
	return entry.entries[path]
}

// storePseudonymizedListCache stores the result of a pseudonymized
// List call.
func (c *VaultCache) storePseudonymizedListCache(vaultDir string, identity *age.X25519Identity, paths []string, entries map[string]map[string]any) {
	if c == nil {
		return
	}
	key := pseudonymizedCacheKey(vaultDir, identity)
	c.pseudonymMu.Lock()
	c.pseudonymItems[key] = pseudonymizedCacheEntry{
		paths:        append([]string(nil), paths...),
		entries:      entries,
		createdAt:    time.Now(),
		entriesMtime: getDirMtime(entriesDir(vaultDir)),
		vaultMtime:   getDirMtime(vaultDir),
	}
	c.pseudonymMu.Unlock()
}

// defaultVaultCache is the process-wide fallback VaultCache used by
// code paths that don't have a *Vault reference (notably the legacy
// package-level helpers and tests). Production code should use the
// *VaultCache attached to each opened Vault instead.
var defaultVaultCache = NewVaultCache(VaultCacheConfig{})

// DefaultVaultCache returns the process-wide fallback VaultCache.
func DefaultVaultCache() *VaultCache {
	return defaultVaultCache
}

// vaultCachesRegistry maps a vault directory to the *VaultCache that
// owns its in-memory caches. Each Vault registers itself in Open and
// unregisters when the vault directory is closed (or replaced). The
// registry is consulted by package-level helpers (List, Find) that
// receive a vaultDir but no *Vault reference.
var (
	vaultCachesMu sync.RWMutex
	vaultCaches   = map[string]*VaultCache{}
)

// registerVaultCache associates a *VaultCache with vaultDir in the
// process-level registry. It is called from (*Vault) construction.
func registerVaultCache(vaultDir string, c *VaultCache) {
	if c == nil || vaultDir == "" {
		return
	}
	vaultCachesMu.Lock()
	vaultCaches[vaultDir] = c
	vaultCachesMu.Unlock()
}

// lookupVaultCache returns the *VaultCache registered for vaultDir,
// or nil if no vault is currently registered for that directory.
func lookupVaultCache(vaultDir string) *VaultCache {
	if vaultDir == "" {
		return nil
	}
	vaultCachesMu.RLock()
	c := vaultCaches[vaultDir]
	vaultCachesMu.RUnlock()
	return c
}

// getDirMtime returns the modification time of a directory, or zero
// if unavailable.
func getDirMtime(dir string) time.Time {
	info, err := os.Stat(dir)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
