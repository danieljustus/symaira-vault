package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

func TestListReturnsAllEntriesWithoutPrefix(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "github.com/work", map[string]interface{}{"username": "bob"})
	mustWriteEntry(t, vaultDir, id, "personal/email", map[string]interface{}{"username": "carol"})

	got, err := List(vaultDir, "", nil)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	want := []string{"github.com/user", "github.com/work", "personal/email"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List() sort order = %#v, want %#v", got, want)
	}
}

func BenchmarkListPseudonymized(b *testing.B) {
	vaultDir := b.TempDir()
	id := testutil.TempIdentity(b)

	cfg := vaultconfig.Default()
	cfg.VaultDir = vaultDir
	cfg.Vault = &vaultconfig.VaultConfig{PseudonymizePaths: true}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		b.Fatalf("save config: %v", err)
	}

	const numEntries = 100
	for i := 0; i < numEntries; i++ {
		path := fmt.Sprintf("bench/entry-%03d", i)
		mustWriteEntry(b, vaultDir, id, path, map[string]interface{}{
			"username": fmt.Sprintf("user-%03d", i),
			"password": fmt.Sprintf("pass-%03d", i),
		})
	}

	// Force cache miss every iteration to measure parallel decryption.
	origTTL := globalCache.pseudoTTL
	globalCache.pseudoTTL = 0
	defer func() { globalCache.pseudoTTL = origTTL }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		InvalidateListCache(vaultDir)
		paths, err := List(vaultDir, "", nil)
		if err != nil {
			b.Fatalf("List() error = %v", err)
		}
		if len(paths) != numEntries {
			b.Fatalf("List() returned %d paths, want %d", len(paths), numEntries)
		}
	}
}

func BenchmarkListPseudonymizedCached(b *testing.B) {
	vaultDir := b.TempDir()
	id := testutil.TempIdentity(b)

	cfg := vaultconfig.Default()
	cfg.VaultDir = vaultDir
	cfg.Vault = &vaultconfig.VaultConfig{PseudonymizePaths: true}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		b.Fatalf("save config: %v", err)
	}

	const numEntries = 100
	for i := 0; i < numEntries; i++ {
		path := fmt.Sprintf("bench/entry-%03d", i)
		mustWriteEntry(b, vaultDir, id, path, map[string]interface{}{
			"username": fmt.Sprintf("user-%03d", i),
			"password": fmt.Sprintf("pass-%03d", i),
		})
	}

	// Warm the cache.
	if _, err := List(vaultDir, "", nil); err != nil {
		b.Fatalf("List() warm-up error = %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		paths, err := List(vaultDir, "", nil)
		if err != nil {
			b.Fatalf("List() error = %v", err)
		}
		if len(paths) != numEntries {
			b.Fatalf("List() returned %d paths, want %d", len(paths), numEntries)
		}
	}
}

func TestListReturnsSortedResults(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "zeta/last", map[string]interface{}{"username": "z"})
	mustWriteEntry(t, vaultDir, id, "alpha/first", map[string]interface{}{"username": "a"})
	mustWriteEntry(t, vaultDir, id, "middle/item", map[string]interface{}{"username": "m"})

	got, err := List(vaultDir, "", nil)
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

	got, err := List(vaultDir, "", nil)
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

	got, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 0}, id)
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

	got, err := FindWithOptions(vaultDir, "s3cr", FindOptions{MaxWorkers: 0}, id)
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

	got, err := FindWithOptions(vaultDir, "alpha", FindOptions{MaxWorkers: 0}, id)
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

	got, err := FindWithOptions(vaultDir, "gItHuB", FindOptions{MaxWorkers: 0}, id)
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

func mustWriteEntry(t testing.TB, vaultDir string, identity *age.X25519Identity, path string, data map[string]interface{}) {
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

	v := &Vault{}
	v.searchIdentity.Store(id)

	got := v.CurrentSearchIdentity()
	if got == nil {
		t.Fatal("CurrentSearchIdentity should return the stored identity")
	}
	if got.String() != id.String() {
		t.Errorf("CurrentSearchIdentity = %q, want %q", got.String(), id.String())
	}
}

func TestCurrentSearchIdentityNil(t *testing.T) {
	v := &Vault{}
	got := v.CurrentSearchIdentity()
	if got != nil {
		t.Error("CurrentSearchIdentity should return nil when no identity is set")
	}
}

func TestFindWithNoIdentity(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	_, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 0}, nil)
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

	got, err := FindWithOptions(vaultDir, "alice", FindOptions{MaxWorkers: 0}, id)
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

	got, err := FindWithOptions(vaultDir, "", FindOptions{MaxWorkers: 0}, id)
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
			findResults, err := FindWithOptions(vaultDir, q, FindOptions{MaxWorkers: 0}, id)
			if err != nil {
				t.Fatalf("Find() error = %v", err)
			}

			concurrentResults, err := FindWithOptions(vaultDir, q, FindOptions{MaxWorkers: 4}, id)
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

	t.Cleanup(func() {
	})

	_, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 4}, nil)
	if err == nil {
		t.Fatal("expected error when no search identity is available")
	}
}

func TestFindConcurrentEmptyVault(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	got, err := FindWithOptions(vaultDir, "query", FindOptions{MaxWorkers: 4}, id)
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

	got, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 0}, id)
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FindWithOptions() with MaxWorkers=0 returned %d results, want 1", len(got))
	}

	got2, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: -1}, id)
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
	paths1, err := List(vaultDir, "", nil)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(paths1) != 2 {
		t.Fatalf("List() returned %d paths, want 2", len(paths1))
	}

	// Second call should hit cache
	paths2, err := List(vaultDir, "", nil)
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
	paths1, err := List(vaultDir, "", nil)
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
	paths2, err := List(vaultDir, "", nil)
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
	paths, err := List(vaultDir, "github", nil)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("List() returned %d paths, want 1", len(paths))
	}

	// Full listing still uses cache
	allPaths, err := List(vaultDir, "", nil)
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
	originalTTL := globalCache.listTTL
	globalCache.listTTL = 1 * time.Millisecond
	defer func() { globalCache.listTTL = originalTTL }()

	// First call populates cache
	_, err := List(vaultDir, "", nil)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	// Add another entry
	mustWriteEntry(t, vaultDir, id, "example.com/admin", map[string]interface{}{"username": "admin"})

	// Cache should have expired, so we should see both entries
	paths, err := List(vaultDir, "", nil)
	if err != nil {
		t.Fatalf("List() after TTL expiry error = %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("List() after TTL expiry returned %d paths, want 2", len(paths))
	}
}

func TestListCacheSurvivesMtimeOnlyChange(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	beforeTouch, err := List(vaultDir, "", nil)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(beforeTouch) != 1 {
		t.Fatalf("List() returned %d paths, want 1", len(beforeTouch))
	}

	future := time.Now().Add(1 * time.Second)
	if terr := os.Chtimes(vaultDir, future, future); terr != nil {
		t.Fatalf("Chtimes(vaultDir) error = %v", terr)
	}
	if terr := os.Chtimes(filepath.Join(vaultDir, "entries"), future, future); terr != nil {
		t.Fatalf("Chtimes(entriesDir) error = %v", terr)
	}

	afterTouch, err := List(vaultDir, "", nil)
	if err != nil {
		t.Fatalf("List() after touch error = %v", err)
	}
	if !reflect.DeepEqual(beforeTouch, afterTouch) {
		t.Fatalf("List() after touch = %v, want %v", afterTouch, beforeTouch)
	}

	mustWriteEntry(t, vaultDir, id, "example.com/admin", map[string]interface{}{"username": "admin"})

	afterAdd, err := List(vaultDir, "", nil)
	if err != nil {
		t.Fatalf("List() after add error = %v", err)
	}
	if len(afterAdd) != 2 {
		t.Fatalf("List() after add returned %d paths, want 2", len(afterAdd))
	}
}

func TestFindWithRedactFieldPatterns(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "acc", map[string]interface{}{
		"totp.secret": "JBSWY3DPEHPK3PXP",
		"email":       "alice@example.com",
	})

	// With redact patterns: field 'totp.secret' must NOT match via value search
	got, err := FindWithOptions(vaultDir, "JBSW", FindOptions{
		MaxWorkers:          0,
		RedactFieldPatterns: []string{"totp.secret"},
	}, id)
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("FindWithOptions(redacted) = %v matches, want 0 (redacted field should be excluded)", len(got))
	}

	// Without redact patterns: field 'totp.secret' SHOULD match
	gotNoRedact, err := FindWithOptions(vaultDir, "JBSW", FindOptions{
		MaxWorkers:          0,
		RedactFieldPatterns: nil,
	}, id)
	if err != nil {
		t.Fatalf("FindWithOptions(no redact) error = %v", err)
	}
	if len(gotNoRedact) == 0 {
		t.Error("FindWithOptions(no_redact) = 0 matches, expected 1 (field should be searchable)")
	}

	// Same behavior for wrong query: both should return empty
	gotWrong, err := FindWithOptions(vaultDir, "WRONG", FindOptions{
		MaxWorkers:          0,
		RedactFieldPatterns: []string{"totp.secret"},
	}, id)
	if err != nil {
		t.Fatalf("FindWithOptions(wrong query) error = %v", err)
	}
	if len(gotWrong) != 0 {
		t.Errorf("FindWithOptions(wrong query) = %v matches, want 0", len(gotWrong))
	}
}

func TestFindWithRedactFieldPatternsConcurrent(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, id, "acc", map[string]interface{}{
		"password":    "s3cr3t",
		"api.key":     "sk-12345",
		"description": "my account",
	})

	// With concurrent search and wildcard redact pattern
	got, err := FindWithOptions(vaultDir, "sk-", FindOptions{
		MaxWorkers:          4,
		RedactFieldPatterns: []string{"api.*"},
	}, id)
	if err != nil {
		t.Fatalf("FindWithOptions(concurrent) error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("FindWithOptions(concurrent, redacted) = %v matches, want 0", len(got))
	}

	// Verify non-redacted field is still searchable
	gotDesc, err := FindWithOptions(vaultDir, "account", FindOptions{
		MaxWorkers:          4,
		RedactFieldPatterns: []string{"api.*"},
	}, id)
	if err != nil {
		t.Fatalf("FindWithOptions(description) error = %v", err)
	}
	if len(gotDesc) != 1 {
		t.Errorf("FindWithOptions(description) = %v matches, want 1", len(gotDesc))
	}
	// The matched field should only be "description", not "api.key"
	if len(gotDesc[0].Fields) != 1 || gotDesc[0].Fields[0] != "description" {
		t.Errorf("FindWithOptions(description) fields = %v, want [description]", gotDesc[0].Fields)
	}
}

func TestIsRedactedField(t *testing.T) {
	tests := []struct {
		field    string
		patterns []string
		want     bool
	}{
		{field: "totp.secret", patterns: []string{"totp.secret"}, want: true},
		{field: "totp.secret", patterns: []string{"password"}, want: false},
		{field: "totp.secret", patterns: []string{"*"}, want: true},
		{field: "password", patterns: []string{"*"}, want: true},
		{field: "api.key", patterns: []string{"api.*"}, want: true},
		{field: "api_key", patterns: []string{"api.*"}, want: false},
		{field: "nested.totp.secret", patterns: []string{"totp.*"}, want: false},
		{field: "nested.totp.secret", patterns: []string{"nested.totp.secret"}, want: true},
		{field: "email", patterns: []string{"password", "totp.secret"}, want: false},
		{field: "", patterns: []string{"*"}, want: true},
		{field: "password", patterns: nil, want: false},
		{field: "password", patterns: []string{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got := isRedactedField(tt.field, tt.patterns)
			if got != tt.want {
				t.Errorf("isRedactedField(%q, %v) = %v, want %v", tt.field, tt.patterns, got, tt.want)
			}
		})
	}
}

func TestSearchWorkerCount_AutoScale(t *testing.T) {
	workers := SearchWorkerCount(0)
	cpus := runtime.NumCPU()
	if cpus > 8 {
		if workers != 8 {
			t.Errorf("SearchWorkerCount(0) = %d, want 8 (capped at 8 with %d CPUs)", workers, cpus)
		}
	} else {
		if workers < 1 || workers > 8 {
			t.Errorf("SearchWorkerCount(0) = %d, want between 1 and 8", workers)
		}
	}
}

func TestSearchWorkerCount_ConfiguredValue(t *testing.T) {
	workers := SearchWorkerCount(12)
	if workers != 12 {
		t.Errorf("SearchWorkerCount(12) = %d, want 12", workers)
	}
}

func TestSearchWorkerCount_CappedAtMaximum(t *testing.T) {
	workers := SearchWorkerCount(99999)
	if workers != 64 {
		t.Errorf("SearchWorkerCount(99999) = %d, want 64 (capped)", workers)
	}
}

func TestSearchWorkerCount_BoundaryValues(t *testing.T) {
	if w := SearchWorkerCount(1); w != 1 {
		t.Errorf("SearchWorkerCount(1) = %d, want 1", w)
	}
	if w := SearchWorkerCount(64); w != 64 {
		t.Errorf("SearchWorkerCount(64) = %d, want 64", w)
	}
	if w := SearchWorkerCount(65); w != 64 {
		t.Errorf("SearchWorkerCount(65) = %d, want 64 (capped)", w)
	}
}

func TestSearchWorkerCount_NegativeDefault(t *testing.T) {
	workers := SearchWorkerCount(-1)
	if workers < 1 {
		t.Errorf("SearchWorkerCount(-1) = %d, want >= 1", workers)
	}
}
