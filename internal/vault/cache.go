package vault

import (
	"container/list"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/age"
	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
)

type listCacheEntry struct {
	paths        []string
	createdAt    time.Time
	entriesMtime time.Time
	vaultMtime   time.Time
}

type listCachePayload struct {
	key   string
	entry listCacheEntry
}

type pseudonymizedCacheEntry struct {
	paths        []string
	entries      map[string]map[string]any // path -> decrypted entry data
	createdAt    time.Time
	entriesMtime time.Time
	vaultMtime   time.Time
}

type configCacheEntry struct {
	cfg        *vaultconfig.Config
	mtime      time.Time
	accessedAt time.Time
}

const (
	defaultListCacheTTL = 300 * time.Second
	minListCacheTTL     = 30 * time.Second
	maxListCacheTTL     = 10 * time.Minute
	maxListCacheVaults  = 16
)

type VaultCache struct {
	// List Cache
	listMu                 sync.RWMutex
	listIndex              map[string]*list.Element
	listOrder              *list.List
	listTTL                time.Duration
	configuredListCacheTTL time.Duration
	listHits               uint64
	listMisses             uint64

	// Pseudonymized Cache
	pseudoMu    sync.RWMutex
	pseudoItems map[string]pseudonymizedCacheEntry
	pseudoTTL   time.Duration

	// Config Cache
	configMu           sync.RWMutex
	configItems        map[string]configCacheEntry
	configCacheMaxSize int32
}

func NewVaultCache() *VaultCache {
	return &VaultCache{
		listIndex:          make(map[string]*list.Element),
		listOrder:          list.New(),
		listTTL:            defaultListCacheTTL,
		pseudoItems:        make(map[string]pseudonymizedCacheEntry),
		pseudoTTL:          300 * time.Second,
		configItems:        make(map[string]configCacheEntry),
		configCacheMaxSize: 32,
	}
}

var globalCache = NewVaultCache()

// listCache helpers

func (c *VaultCache) GetList(vaultDir string) []string {
	c.listMu.RLock()
	elem, ok := c.listIndex[vaultDir]
	c.listMu.RUnlock()
	if !ok {
		atomic.AddUint64(&c.listMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	payload, ok := elem.Value.(*listCachePayload)
	if !ok {
		atomic.AddUint64(&c.listMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	entry := payload.entry
	if time.Since(entry.createdAt) > c.listTTL {
		atomic.AddUint64(&c.listMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	if !getDirMtime(entriesDir(vaultDir)).Equal(entry.entriesMtime) {
		atomic.AddUint64(&c.listMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	if !getDirMtime(vaultDir).Equal(entry.vaultMtime) {
		atomic.AddUint64(&c.listMisses, 1)
		c.adaptListCacheTTL()
		return nil
	}
	atomic.AddUint64(&c.listHits, 1)
	c.adaptListCacheTTL()
	c.listMu.Lock()
	c.listOrder.MoveToFront(elem)
	c.listMu.Unlock()
	return entry.paths
}

func (c *VaultCache) StoreList(vaultDir string, paths []string) {
	c.listMu.Lock()
	defer c.listMu.Unlock()

	entriesMtime := getDirMtime(entriesDir(vaultDir))
	vaultMtime := getDirMtime(vaultDir)

	if elem, ok := c.listIndex[vaultDir]; ok {
		payload, ok := elem.Value.(*listCachePayload)
		if !ok {
			return
		}
		payload.entry = listCacheEntry{
			paths:        append([]string(nil), paths...),
			createdAt:    time.Now(),
			entriesMtime: entriesMtime,
			vaultMtime:   vaultMtime,
		}
		c.listOrder.MoveToFront(elem)
		return
	}

	if c.listOrder.Len() >= maxListCacheVaults {
		oldest := c.listOrder.Back()
		if oldest != nil {
			oldPayload, ok := oldest.Value.(*listCachePayload)
			if !ok {
				return
			}
			delete(c.listIndex, oldPayload.key)
			c.listOrder.Remove(oldest)
		}
	}

	payload := &listCachePayload{
		key: vaultDir,
		entry: listCacheEntry{
			paths:        append([]string(nil), paths...),
			createdAt:    time.Now(),
			entriesMtime: entriesMtime,
			vaultMtime:   vaultMtime,
		},
	}
	elem := c.listOrder.PushFront(payload)
	c.listIndex[vaultDir] = elem
}

func (c *VaultCache) SetListTTL(ttl time.Duration) {
	c.listMu.Lock()
	if ttl <= 0 {
		c.listTTL = 0
	} else {
		c.listTTL = ttl
	}
	c.listMu.Unlock()
	c.configuredListCacheTTL = ttl
}

func (c *VaultCache) adaptListCacheTTL() {
	hits := atomic.LoadUint64(&c.listHits)
	miss := atomic.LoadUint64(&c.listMisses)
	total := hits + miss
	if total < 100 {
		return
	}
	effectiveMax := maxListCacheTTL
	if c.configuredListCacheTTL > 0 && c.configuredListCacheTTL < effectiveMax {
		effectiveMax = c.configuredListCacheTTL
	}
	ratio := float64(hits) / float64(total)
	c.listMu.Lock()
	if ratio > 0.9 && c.listTTL < effectiveMax {
		c.listTTL *= 2
		if c.listTTL > effectiveMax {
			c.listTTL = effectiveMax
		}
	} else if ratio < 0.5 && c.listTTL > minListCacheTTL {
		c.listTTL /= 2
		if c.listTTL < minListCacheTTL {
			c.listTTL = minListCacheTTL
		}
	}
	c.listMu.Unlock()
	atomic.StoreUint64(&c.listHits, 0)
	atomic.StoreUint64(&c.listMisses, 0)
}

// Pseudonymized Cache helpers

func pseudonymizedCacheKey(vaultDir string, identity *age.X25519Identity) string {
	return vaultDir + "\x00" + identity.Recipient().String()
}

func (c *VaultCache) GetPseudonymizedList(vaultDir string, identity *age.X25519Identity) []string {
	key := pseudonymizedCacheKey(vaultDir, identity)
	c.pseudoMu.RLock()
	entry, ok := c.pseudoItems[key]
	c.pseudoMu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.createdAt) > c.pseudoTTL {
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

func (c *VaultCache) GetPseudonymizedEntry(vaultDir string, identity *age.X25519Identity, path string) map[string]any {
	key := pseudonymizedCacheKey(vaultDir, identity)
	c.pseudoMu.RLock()
	entry, ok := c.pseudoItems[key]
	c.pseudoMu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.createdAt) > c.pseudoTTL {
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

func (c *VaultCache) StorePseudonymizedList(vaultDir string, identity *age.X25519Identity, paths []string, entries map[string]map[string]any) {
	key := pseudonymizedCacheKey(vaultDir, identity)
	c.pseudoMu.Lock()
	c.pseudoItems[key] = pseudonymizedCacheEntry{
		paths:        append([]string(nil), paths...),
		entries:      entries,
		createdAt:    time.Now(),
		entriesMtime: getDirMtime(entriesDir(vaultDir)),
		vaultMtime:   getDirMtime(vaultDir),
	}
	c.pseudoMu.Unlock()
}

// Config Cache helpers

func (c *VaultCache) SetConfigCacheSize(n int) {
	if n <= 0 {
		n = 32
	}
	c.configMu.Lock()
	c.configCacheMaxSize = int32(n)
	c.configMu.Unlock()
}

func (c *VaultCache) GetOrLoadConfig(vaultDir string, load func() (*vaultconfig.Config, error)) (*vaultconfig.Config, error) {
	configPath := filepath.Join(vaultDir, "config.yaml")
	mtime := time.Time{}
	if info, err := os.Stat(configPath); err == nil {
		mtime = info.ModTime()
	}

	c.configMu.RLock()
	entry, ok := c.configItems[vaultDir]
	c.configMu.RUnlock()
	if ok && entry.mtime.Equal(mtime) && entry.cfg != nil {
		c.configMu.Lock()
		entry.accessedAt = time.Now()
		c.configItems[vaultDir] = entry
		c.configMu.Unlock()
		return entry.cfg, nil
	}

	cfg, err := load()
	if err != nil {
		return nil, err
	}

	c.configMu.Lock()
	if len(c.configItems) >= int(c.configCacheMaxSize) {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range c.configItems {
			if oldestTime.IsZero() || v.accessedAt.Before(oldestTime) {
				oldestTime = v.accessedAt
				oldestKey = k
			}
		}
		if oldestKey != "" {
			delete(c.configItems, oldestKey)
		}
	}
	c.configItems[vaultDir] = configCacheEntry{cfg: cfg, mtime: mtime, accessedAt: time.Now()}
	c.configMu.Unlock()
	return cfg, nil
}

func (c *VaultCache) InvalidateConfig(vaultDir string) {
	c.configMu.Lock()
	delete(c.configItems, vaultDir)
	c.configMu.Unlock()
}

// Global Invalidation helpers

func (c *VaultCache) Invalidate(vaultDir string) {
	c.listMu.Lock()
	if vaultDir == "" {
		c.listIndex = make(map[string]*list.Element)
		c.listOrder.Init()
	} else {
		if elem, ok := c.listIndex[vaultDir]; ok {
			delete(c.listIndex, vaultDir)
			c.listOrder.Remove(elem)
		}
	}
	c.listMu.Unlock()

	c.pseudoMu.Lock()
	if vaultDir == "" {
		c.pseudoItems = make(map[string]pseudonymizedCacheEntry)
	} else {
		prefix := vaultDir + "\x00"
		for k := range c.pseudoItems {
			if strings.HasPrefix(k, prefix) {
				delete(c.pseudoItems, k)
			}
		}
	}
	c.pseudoMu.Unlock()

	c.configMu.Lock()
	if vaultDir == "" {
		c.configItems = make(map[string]configCacheEntry)
	} else {
		delete(c.configItems, vaultDir)
	}
	c.configMu.Unlock()
}

func (c *VaultCache) InvalidatePath(vaultDir, path string) {
	c.listMu.Lock()
	if elem, ok := c.listIndex[vaultDir]; ok {
		delete(c.listIndex, vaultDir)
		c.listOrder.Remove(elem)
	}
	c.listMu.Unlock()

	c.pseudoMu.Lock()
	prefix := vaultDir + "\x00"
	for k := range c.pseudoItems {
		if strings.HasPrefix(k, prefix) {
			delete(c.pseudoItems, k)
		}
	}
	c.pseudoMu.Unlock()
}

// general helpers

func getDirMtime(dir string) time.Time {
	info, err := os.Stat(dir)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
