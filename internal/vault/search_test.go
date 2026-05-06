package vault

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/testutil"
)

func TestListReturnsAllEntriesWithoutPrefix(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "github.com/work", map[string]interface{}{"username": "bob"})
	mustWriteEntry(t, vaultDir, id, "personal/email", map[string]interface{}{"username": "carol"})

	got, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	want := []string{"github.com/user", "github.com/work", "personal/email"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List() = %#v, want %#v", got, want)
	}
}

func TestListFiltersByPrefix(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "github.com/work", map[string]interface{}{"username": "bob"})
	mustWriteEntry(t, vaultDir, id, "personal/email", map[string]interface{}{"username": "carol"})

	got, err := List(vaultDir, "github.com")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	want := []string{"github.com/user", "github.com/work"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List(prefix) = %#v, want %#v", got, want)
	}
}

func TestListReturnsSortedResults(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "zeta/last", map[string]interface{}{"username": "z"})
	mustWriteEntry(t, vaultDir, id, "alpha/first", map[string]interface{}{"username": "a"})
	mustWriteEntry(t, vaultDir, id, "middle/item", map[string]interface{}{"username": "m"})

	got, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	want := []string{"alpha/first", "middle/item", "zeta/last"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List() sort order = %#v, want %#v", got, want)
	}
}

func TestListIncludesLegacyRootEntries(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "new/path", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "legacy/path", map[string]interface{}{"username": "bob"})
	newPath := filepath.Join(vaultDir, "entries", "legacy", "path.age")
	legacyPath := filepath.Join(vaultDir, "legacy", "path.age")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatalf("create legacy dir: %v", err)
	}
	if err := os.Rename(newPath, legacyPath); err != nil {
		t.Fatalf("move entry to legacy path: %v", err)
	}

	got, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	want := []string{"legacy/path", "new/path"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List() = %#v, want %#v", got, want)
	}
}

func TestFindMatchesPaths(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "personal/email", map[string]interface{}{"username": "bob"})

	got, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(Find()) = %d, want 1", len(got))
	}
	if got[0].Path != "github.com/user" {
		t.Fatalf("Find() path = %q, want %q", got[0].Path, "github.com/user")
	}
	if !containsString(got[0].Fields, "path") {
		t.Fatalf("Find() fields = %#v, want path match", got[0].Fields)
	}
}

func TestFindMatchesFieldValues(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{
		"username": "alice",
		"password": "s3cr3t",
	})

	got, err := FindWithOptions(vaultDir, "s3cr", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(Find()) = %d, want 1", len(got))
	}
	if got[0].Path != "github.com/user" {
		t.Fatalf("Find() path = %q, want %q", got[0].Path, "github.com/user")
	}
	if !containsString(got[0].Fields, "password") {
		t.Fatalf("Find() fields = %#v, want password match", got[0].Fields)
	}
}

func TestFindReturnsFieldNamesThatMatched(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{
		"username": "alpha",
		"profile": map[string]interface{}{
			"email":  "alpha@example.com",
			"handle": "alpha-handle",
		},
	})

	got, err := FindWithOptions(vaultDir, "alpha", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(Find()) = %d, want 1", len(got))
	}
	want := []string{"profile.email", "profile.handle", "username"}
	if !reflect.DeepEqual(got[0].Fields, want) {
		t.Fatalf("Find() fields = %#v, want %#v", got[0].Fields, want)
	}
}

func TestFindIsCaseInsensitive(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "GitHub.Com/User", map[string]interface{}{"username": "Alice"})

	got, err := FindWithOptions(vaultDir, "gItHuB", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(Find()) = %d, want 1", len(got))
	}
	if got[0].Path != "GitHub.Com/User" {
		t.Fatalf("Find() path = %q, want %q", got[0].Path, "GitHub.Com/User")
	}
}

func mustWriteEntry(t *testing.T, vaultDir string, identity *age.X25519Identity, path string, data map[string]interface{}) {
	t.Helper()
	if err := WriteEntry(vaultDir, path, &Entry{Data: data}, identity); err != nil {
		t.Fatalf("WriteEntry(%s) error = %v", path, err)
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestCurrentSearchIdentity(t *testing.T) {
	id := testutil.TempIdentity(t)

	rememberSearchIdentity(id)

	got := currentSearchIdentity()
	if got == nil {
		t.Fatal("currentSearchIdentity should return the stored identity")
	}
	if got.String() != id.String() {
		t.Errorf("currentSearchIdentity = %q, want %q", got.String(), id.String())
	}
}

func TestCurrentSearchIdentityNil(t *testing.T) {
	searchIdentity.Store(nil)

	got := currentSearchIdentity()
	if got != nil {
		t.Error("currentSearchIdentity should return nil when no identity is set")
	}
}

func TestFindWithNoIdentity(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	searchIdentity.Store(nil)

	_, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 0})
	if err == nil {
		t.Fatal("expected error when no search identity is available")
	}
}

func TestFindMatchesNestedArrayFields(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "app/users", map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{"name": "alice", "email": "alice@example.com"},
			map[string]interface{}{"name": "bob", "email": "bob@example.com"},
		},
	})

	got, err := FindWithOptions(vaultDir, "alice", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(Find()) = %d, want 1", len(got))
	}
	if !containsString(got[0].Fields, "users[0].name") {
		t.Fatalf("Find() fields = %#v, want users[0].name match", got[0].Fields)
	}
}

func TestFindWithEmptyQuery(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	got, err := FindWithOptions(vaultDir, "", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(Find()) = %d, want 1 for empty query", len(got))
	}
}

func TestFindConcurrentMatchesFind(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "personal/email", map[string]interface{}{"username": "bob"})
	mustWriteEntry(t, vaultDir, id, "work/aws", map[string]interface{}{
		"username": "carol",
		"password": "s3cr3t",
	})

	queries := []string{"github", "s3cr", "alice", ""}

	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			findResults, err := FindWithOptions(vaultDir, q, FindOptions{MaxWorkers: 0})
			if err != nil {
				t.Fatalf("Find() error = %v", err)
			}

			concurrentResults, err := FindWithOptions(vaultDir, q, FindOptions{MaxWorkers: 4})
			if err != nil {
				t.Fatalf("FindWithOptions() error = %v", err)
			}

			if len(concurrentResults) != len(findResults) {
				t.Fatalf("FindWithOptions() len=%d, FindWithOptions() len=%d for query %q", len(concurrentResults), len(findResults), q)
			}

			findPaths := make(map[string]bool)
			for _, m := range findResults {
				findPaths[m.Path] = true
			}
			for _, m := range concurrentResults {
				if !findPaths[m.Path] {
					t.Errorf("FindWithOptions() returned path %q not in FindWithOptions() results", m.Path)
				}
			}
		})
	}
}

func TestFindConcurrentNoIdentity(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	searchIdentity.Store(nil)
	t.Cleanup(func() {
		rememberSearchIdentity(id)
	})

	_, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 4})
	if err == nil {
		t.Fatal("expected error when no search identity is available")
	}
}

func TestFindConcurrentEmptyVault(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	got, err := FindWithOptions(vaultDir, "query", FindOptions{MaxWorkers: 4})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("FindWithOptions() on empty vault returned %d results, want 0", len(got))
	}
}

func TestFindConcurrentDefaultsMaxWorkers(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	got, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FindWithOptions() with MaxWorkers=0 returned %d results, want 1", len(got))
	}

	got2, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: -1})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got2) != 1 {
		t.Fatalf("FindWithOptions() with MaxWorkers=-1 returned %d results, want 1", len(got2))
	}
}

func TestListCacheHit(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "example.com/admin", map[string]interface{}{"username": "admin"})

	// First call populates cache
	paths1, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(paths1) != 2 {
		t.Fatalf("List() returned %d paths, want 2", len(paths1))
	}

	// Second call should hit cache
	paths2, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() cached error = %v", err)
	}
	if len(paths2) != 2 {
		t.Fatalf("List() cached returned %d paths, want 2", len(paths2))
	}
}

func TestListCacheInvalidation(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	// First call populates cache
	paths1, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(paths1) != 1 {
		t.Fatalf("List() returned %d paths, want 1", len(paths1))
	}

	// Invalidate cache
	InvalidateListCache(vaultDir)

	// Add another entry
	mustWriteEntry(t, vaultDir, id, "example.com/admin", map[string]interface{}{"username": "admin"})

	// Next call should re-walk and find both entries
	paths2, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() after invalidate error = %v", err)
	}
	if len(paths2) != 2 {
		t.Fatalf("List() after invalidate returned %d paths, want 2", len(paths2))
	}
}

func TestListCachePrefixBypass(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "example.com/admin", map[string]interface{}{"username": "admin"})

	// Prefix queries bypass cache
	paths, err := List(vaultDir, "github")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("List() returned %d paths, want 1", len(paths))
	}

	// Full listing still uses cache
	allPaths, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(allPaths) != 2 {
		t.Fatalf("List() returned %d paths, want 2", len(allPaths))
	}
}

func TestListCacheTTLExpiration(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	// Set a very short TTL
	originalTTL := listCache.ttl
	listCache.ttl = 1 * time.Millisecond
	defer func() { listCache.ttl = originalTTL }()

	// First call populates cache
	_, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	// Add another entry
	mustWriteEntry(t, vaultDir, id, "example.com/admin", map[string]interface{}{"username": "admin"})

	// Cache should have expired, so we should see both entries
	paths, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() after TTL expiry error = %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("List() after TTL expiry returned %d paths, want 2", len(paths))
	}
}
