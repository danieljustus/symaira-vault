// Package update provides functionality for checking and managing Symaira Vault updates.
package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/pathutil"
)

const (
	// DefaultCacheTTL is the default time-to-live for cached update check results.
	DefaultCacheTTL = 24 * time.Hour

	cacheDirName  = ".symaira"
	cacheFileName = "update-cache.json"
)

// CacheEntry represents a cached update check result.
type CacheEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	LatestVersion string    `json:"latest_version"`
	ReleaseURL    string    `json:"release_url"`
}

// Cache manages persistent caching of update check results.
type Cache struct {
	path string
	ttl  time.Duration
}

// NewCache creates a new Cache instance with the default location and TTL.
func NewCache() *Cache {
	return NewCacheWithTTL("", DefaultCacheTTL)
}

// NewCacheWithTTL creates a new Cache instance with a custom path and TTL.
// If path is empty, the default location (~/.symaira/update-cache.json) is used.
func NewCacheWithTTL(path string, ttl time.Duration) *Cache {
	if path == "" {
		path = defaultCachePath()
	}
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{
		path: path,
		ttl:  ttl,
	}
}

// Load reads the cache entry from disk if it exists and is still valid.
// Returns nil if the cache doesn't exist, is expired, or can't be read.
func (c *Cache) Load() (*CacheEntry, error) {
	if c.path == "" {
		return nil, nil
	}

	if err := validateCachePath(c.path); err != nil {
		return nil, fmt.Errorf("invalid cache path: %w", err)
	}

	data, err := os.ReadFile(c.path) //nosec:G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache file: %w", err)
	}

	if len(data) == 0 {
		return nil, nil
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, nil
	}

	if entry.Timestamp.IsZero() {
		return nil, nil
	}

	if time.Since(entry.Timestamp) > c.ttl {
		return nil, nil
	}

	return &entry, nil
}

// Save writes the cache entry to disk.
func (c *Cache) Save(entry *CacheEntry) error {
	if c.path == "" {
		return nil
	}

	if entry == nil {
		return nil
	}

	if err := validateCachePath(c.path); err != nil {
		return fmt.Errorf("invalid cache path: %w", err)
	}

	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}

	if err := os.WriteFile(c.path, data, 0o600); err != nil {
		return fmt.Errorf("write cache file: %w", err)
	}

	return nil
}

// Invalidate removes the cache file.
func (c *Cache) Invalidate() error {
	if c.path == "" {
		return nil
	}

	if err := validateCachePath(c.path); err != nil {
		return fmt.Errorf("invalid cache path: %w", err)
	}

	err := os.Remove(c.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove cache file: %w", err)
	}
	return nil
}

// Path returns the cache file path.
func (c *Cache) Path() string {
	return c.path
}

// TTL returns the cache time-to-live duration.
func (c *Cache) TTL() time.Duration {
	return c.ttl
}

func defaultCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, cacheDirName, cacheFileName)
}

func validateCachePath(path string) error {
	if pathutil.HasTraversal(path) {
		return errors.New("cache file path escapes expected directory")
	}
	return nil
}
