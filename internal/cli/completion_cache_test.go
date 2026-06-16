package cli

import (
	"sync"
	"testing"
	"time"
)

func TestCompletionCache_GetSet(t *testing.T) {
	c := newCompletionCache()

	c.Set("/vault/a", []string{"github", "gitlab"})
	paths, ok := c.Get("/vault/a")
	if !ok {
		t.Fatal("expected cache hit after Set")
	}
	if len(paths) != 2 || paths[0] != "github" || paths[1] != "gitlab" {
		t.Fatalf("paths = %v, want [github gitlab]", paths)
	}
}

func TestCompletionCache_MissOnUnknownKey(t *testing.T) {
	c := newCompletionCache()

	_, ok := c.Get("/nonexistent")
	if ok {
		t.Fatal("expected cache miss for unknown key")
	}
}

func TestCompletionCache_ExpiresAfterTTL(t *testing.T) {
	c := newCompletionCache()

	c.Set("/vault/a", []string{"github"})
	_, ok := c.Get("/vault/a")
	if !ok {
		t.Fatal("expected cache hit immediately after Set")
	}

	// Artificially age the entry past the TTL.
	c.mu.Lock()
	c.entries["/vault/a"].timestamp = time.Now().Add(-completionCacheTTL - time.Second)
	c.mu.Unlock()

	_, ok = c.Get("/vault/a")
	if ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestCompletionCache_IsolationPerVaultDir(t *testing.T) {
	c := newCompletionCache()

	c.Set("/vault/a", []string{"entry-a"})
	c.Set("/vault/b", []string{"entry-b"})

	pathsA, ok := c.Get("/vault/a")
	if !ok || len(pathsA) != 1 || pathsA[0] != "entry-a" {
		t.Fatalf("vault/a = %v, %v, want [entry-a] true", pathsA, ok)
	}
	pathsB, ok := c.Get("/vault/b")
	if !ok || len(pathsB) != 1 || pathsB[0] != "entry-b" {
		t.Fatalf("vault/b = %v, %v, want [entry-b] true", pathsB, ok)
	}
}

func TestCompletionCache_Invalidate(t *testing.T) {
	c := newCompletionCache()

	c.Set("/vault/a", []string{"github"})
	c.Invalidate("/vault/a")

	_, ok := c.Get("/vault/a")
	if ok {
		t.Fatal("expected cache miss after Invalidate")
	}
}

func TestCompletionCache_InvalidateAll(t *testing.T) {
	c := newCompletionCache()

	c.Set("/vault/a", []string{"github"})
	c.Set("/vault/b", []string{"gitlab"})
	c.InvalidateAll()

	_, okA := c.Get("/vault/a")
	_, okB := c.Get("/vault/b")
	if okA || okB {
		t.Fatal("expected all entries cleared after InvalidateAll")
	}
}

func TestCompletionCache_ConcurrentAccess(t *testing.T) {
	c := newCompletionCache()
	var wg sync.WaitGroup

	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dir := "/vault/concurrent"
			c.Set(dir, []string{"entry"})
			c.Get(dir)
			c.Invalidate(dir)
			c.Get(dir)
		}()
	}
	wg.Wait()
}

func TestFilterPathsByPrefix(t *testing.T) {
	paths := []string{"github", "gitlab", "work/aws", "work/gcp"}

	tests := []struct {
		prefix string
		want   []string
	}{
		{"", paths},
		{"gi", []string{"github", "gitlab"}},
		{"work/", []string{"work/aws", "work/gcp"}},
		{"github", []string{"github"}},
		{"zzz", nil},
	}

	for _, tt := range tests {
		got := filterPathsByPrefix(paths, tt.prefix)
		if len(got) != len(tt.want) {
			t.Errorf("filterPathsByPrefix(%q) = %v, want %v", tt.prefix, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("filterPathsByPrefix(%q)[%d] = %q, want %q", tt.prefix, i, got[i], tt.want[i])
			}
		}
	}
}
