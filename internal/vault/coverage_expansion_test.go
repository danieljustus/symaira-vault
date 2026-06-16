package vault

import (
	"fmt"
	"testing"
	"time"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
)

func TestEntry_RemoveTag(t *testing.T) {
	e := &Entry{}
	e.AddTag("tag1")
	e.AddTag("tag2")
	e.AddTag("tag3")
	e.RemoveTag("tag2")
	if e.HasTag("tag2") {
		t.Error("tag2 should have been removed")
	}
	if !e.HasTag("tag1") || !e.HasTag("tag3") {
		t.Error("other tags should still exist")
	}
}

func TestEntry_HasTag(t *testing.T) {
	e := &Entry{}
	e.AddTag("foo")
	if !e.HasTag("foo") {
		t.Error("HasTag('foo') should be true")
	}
	if e.HasTag("baz") {
		t.Error("HasTag('baz') should be false")
	}
}

func TestEntry_RemoveTag_NotFound(t *testing.T) {
	e := &Entry{}
	e.AddTag("tag1")
	e.AddTag("tag2")
	e.RemoveTag("nonexistent")
	if len(e.Metadata.Tags) != 2 {
		t.Errorf("expected 2 tags unchanged, got %d", len(e.Metadata.Tags))
	}
}

func TestEntry_WithoutCanary(t *testing.T) {
	e := &Entry{Canary: true, Path: "test/entry"}
	cp := e.WithoutCanary()
	if cp == nil {
		t.Fatal("WithoutCanary returned nil")
	}
	if cp.Canary {
		t.Error("WithoutCanary should clear canary flag")
	}
	if !e.Canary {
		t.Error("original entry should preserve canary flag")
	}
}

func TestEntry_WithoutCanary_Nil(t *testing.T) {
	var e *Entry
	if cp := e.WithoutCanary(); cp != nil {
		t.Fatal("WithoutCanary on nil should return nil")
	}
}

func TestEntry_IsCanary(t *testing.T) {
	if !(&Entry{Canary: true}).IsCanary() {
		t.Error("IsCanary should return true for canary entry")
	}
	if (&Entry{Canary: false}).IsCanary() {
		t.Error("IsCanary should return false for non-canary entry")
	}
}

func TestEntry_IsCanary_Nil(t *testing.T) {
	var e *Entry
	if e.IsCanary() {
		t.Error("IsCanary on nil should return false")
	}
}

func TestCanaryPath_Roundtrip(t *testing.T) {
	defer func() {
		canaryPaths.mu.Lock()
		canaryPaths.paths = make(map[string]bool)
		canaryPaths.mu.Unlock()
	}()

	if IsCanaryPath("test/path") {
		t.Fatal("IsCanaryPath should be false before MarkCanaryPath")
	}

	MarkCanaryPath("test/path")
	if !IsCanaryPath("test/path") {
		t.Fatal("IsCanaryPath should be true after MarkCanaryPath")
	}

	UnmarkCanaryPath("test/path")
	if IsCanaryPath("test/path") {
		t.Fatal("IsCanaryPath should be false after UnmarkCanaryPath")
	}
}

func TestDefaultCanaryEntries_NotEmpty(t *testing.T) {
	entries := DefaultCanaryEntries()
	if len(entries) == 0 {
		t.Fatal("DefaultCanaryEntries() returned empty slice")
	}
	for _, e := range entries {
		if e.Path == "" {
			t.Error("canary entry has empty path")
		}
		if len(e.Data) == 0 {
			t.Errorf("canary entry %q has no data", e.Path)
		}
	}
}

func TestSetEntryCanary_NilIdentity(t *testing.T) {
	err := SetEntryCanary(t.TempDir(), "test/path", nil, true)
	if err == nil {
		t.Fatal("SetEntryCanary with nil identity should return error")
	}
}

func TestInvalidateConfigCache(t *testing.T) {
	listCacheFor(t.TempDir()).InvalidateConfig(t.TempDir())
}

func TestCurrentSearchIdentity_InitialNil(t *testing.T) {
	var v *Vault
	id := v.CurrentSearchIdentity()
	if id != nil {
		t.Error("CurrentSearchIdentity() on nil vault should return nil")
	}
}

func TestHasField_Basic(t *testing.T) {
	if !hasField([]string{"name", "path"}, "name") {
		t.Error("hasField should find 'name'")
	}
	if hasField([]string{"name", "path"}, "") {
		t.Error("hasField should not find empty string")
	}
}

func TestVaultCache_InvalidatePath(t *testing.T) {
	cache := NewVaultCache(VaultCacheConfig{})

	// Test nil cache
	var nilCache *VaultCache
	nilCache.InvalidatePath("test/path") // should not panic

	// Test empty path (invalidates all)
	cache.InvalidatePath("")

	// Test path with pseudonym entries
	cache.pseudonymMu.Lock()
	cache.pseudonymItems["vault1"] = pseudonymizedCacheEntry{
		entries: map[string]map[string]any{
			"test/path": {"key": "value"},
		},
	}
	cache.pseudonymItems["vault2"] = pseudonymizedCacheEntry{
		entries: map[string]map[string]any{
			"other/path": {"key": "value"},
		},
	}
	cache.pseudonymMu.Unlock()

	cache.InvalidatePath("test/path")

	cache.pseudonymMu.RLock()
	if _, ok := cache.pseudonymItems["vault1"]; ok {
		t.Error("vault1 should have been invalidated")
	}
	if _, ok := cache.pseudonymItems["vault2"]; !ok {
		t.Error("vault2 should still exist")
	}
	cache.pseudonymMu.RUnlock()
}

func TestVaultCache_InvalidateSearchIndex(t *testing.T) {
	cache := NewVaultCache(VaultCacheConfig{})
	cache.InvalidateSearchIndex() // should not panic
}

func TestVaultCache_GetOrLoad(t *testing.T) {
	cache := NewVaultCache(VaultCacheConfig{})

	// Test nil cache
	var nilCache *VaultCache
	loaded := false
	v, err := nilCache.GetOrLoad("/test", func() (any, error) {
		loaded = true
		return &vaultconfig.Config{}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loaded {
		t.Error("loader should have been called")
	}
	if v == nil {
		t.Error("expected non-nil config")
	}

	// Test cache miss with Config type
	loaded = false
	v, err = cache.GetOrLoad("/test", func() (any, error) {
		loaded = true
		return &vaultconfig.Config{}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loaded {
		t.Error("loader should have been called on cache miss")
	}
	if v == nil {
		t.Error("expected non-nil config")
	}

	// Test cache hit
	loaded = false
	v, err = cache.GetOrLoad("/test", func() (any, error) {
		loaded = true
		return &vaultconfig.Config{}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loaded {
		t.Error("loader should not have been called on cache hit")
	}
	if v == nil {
		t.Error("expected non-nil config from cache")
	}

	// Test non-Config type (not cached)
	loaded = false
	v, err = cache.GetOrLoad("/string", func() (any, error) {
		loaded = true
		return "string value", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !loaded {
		t.Error("loader should have been called for non-Config type")
	}
	if v != "string value" {
		t.Errorf("expected 'string value', got %v", v)
	}

	// Test loader error
	_, err = cache.GetOrLoad("/error", func() (any, error) {
		return nil, fmt.Errorf("load error")
	})
	if err == nil {
		t.Error("expected error from loader")
	}
}

func TestVaultCache_SetConfigCacheSize(t *testing.T) {
	cache := NewVaultCache(VaultCacheConfig{})

	// Test nil cache
	var nilCache *VaultCache
	nilCache.SetConfigCacheSize(10) // should not panic

	// Test valid size
	cache.SetConfigCacheSize(50)
	if cache.configMaxSize != 50 {
		t.Errorf("expected configMaxSize 50, got %d", cache.configMaxSize)
	}

	// Test zero (resets to default)
	cache.SetConfigCacheSize(0)
	if cache.configMaxSize != defaultConfigCacheSize {
		t.Errorf("expected configMaxSize %d, got %d", defaultConfigCacheSize, cache.configMaxSize)
	}

	// Test negative (resets to default)
	cache.SetConfigCacheSize(-1)
	if cache.configMaxSize != defaultConfigCacheSize {
		t.Errorf("expected configMaxSize %d, got %d", defaultConfigCacheSize, cache.configMaxSize)
	}
}

func TestVaultCache_SetPseudonymCacheTTL(t *testing.T) {
	cache := NewVaultCache(VaultCacheConfig{})

	// Test nil cache
	var nilCache *VaultCache
	nilCache.SetPseudonymCacheTTL(time.Minute) // should not panic

	// Test valid TTL
	cache.SetPseudonymCacheTTL(5 * time.Minute)
	if cache.pseudonymTTL != 5*time.Minute {
		t.Errorf("expected pseudonymTTL 5m, got %v", cache.pseudonymTTL)
	}
}

func TestVaultCache_PseudonymCacheTTL(t *testing.T) {
	cache := NewVaultCache(VaultCacheConfig{})

	// Test nil cache
	var nilCache *VaultCache
	if ttl := nilCache.PseudonymCacheTTL(); ttl != 0 {
		t.Errorf("expected 0, got %v", ttl)
	}

	// Test default TTL
	if ttl := cache.PseudonymCacheTTL(); ttl != defaultPseudonymCacheTTL {
		t.Errorf("expected %v, got %v", defaultPseudonymCacheTTL, ttl)
	}

	// Test custom TTL
	cache.SetPseudonymCacheTTL(10 * time.Minute)
	if ttl := cache.PseudonymCacheTTL(); ttl != 10*time.Minute {
		t.Errorf("expected 10m, got %v", ttl)
	}
}

func TestDefaultVaultCache(t *testing.T) {
	cache := DefaultVaultCache()
	if cache == nil {
		t.Fatal("DefaultVaultCache() returned nil")
	}
	if cache != DefaultVaultCache() {
		t.Error("DefaultVaultCache() should return the same instance")
	}
}

func TestRegisterVaultCache(t *testing.T) {
	vaultCachesMu.Lock()
	original := vaultCaches
	vaultCaches = make(map[string]*VaultCache)
	vaultCachesMu.Unlock()

	defer func() {
		vaultCachesMu.Lock()
		vaultCaches = original
		vaultCachesMu.Unlock()
	}()

	cache := NewVaultCache(VaultCacheConfig{})
	registerVaultCache("/test/vault", cache)

	if got := lookupVaultCache("/test/vault"); got != cache {
		t.Error("registerVaultCache did not register the cache")
	}

	// Test nil cache
	registerVaultCache("/test/nil", nil)
	if got := lookupVaultCache("/test/nil"); got != nil {
		t.Error("registerVaultCache with nil should not register")
	}

	// Test empty vaultDir
	registerVaultCache("", cache)
	if got := lookupVaultCache(""); got != nil {
		t.Error("registerVaultCache with empty vaultDir should not register")
	}
}
