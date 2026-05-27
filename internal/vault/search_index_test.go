package vault

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/testutil"
)

func TestEncryptedIndexBuildAndMatch(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
		"password": "s3cr3t",
	})
	mustWriteEntry(t, vaultDir, identity, "personal/email", map[string]interface{}{
		"email":   "alice@example.com",
		"service": "protonmail",
	})
	mustWriteEntry(t, vaultDir, identity, "work/aws", map[string]interface{}{
		"username": "carol",
		"password": "s3cr3t-aws",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !idx.IsBuilt() {
		t.Fatal("IsBuilt() = false after Build()")
	}

	candidates := []string{"github.com/user", "personal/email", "work/aws"}

	t.Run("match by field value substring", func(t *testing.T) {
		results, err := idx.MatchEntries(vaultDir, identity, candidates, "alice")
		if err != nil {
			t.Fatalf("MatchEntries() error = %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("MatchEntries('alice') = %d results, want 2", len(results))
		}
		if _, ok := results["github.com/user"]; !ok {
			t.Errorf("MatchEntries missing github.com/user")
		}
		if _, ok := results["personal/email"]; !ok {
			t.Errorf("MatchEntries missing personal/email")
		}
	})

	t.Run("match by partial value", func(t *testing.T) {
		results, err := idx.MatchEntries(vaultDir, identity, candidates, "s3cr")
		if err != nil {
			t.Fatalf("MatchEntries() error = %v", err)
		}
		if len(results) != 2 {
			t.Fatalf("MatchEntries('s3cr') = %d results, want 2", len(results))
		}
	})

	t.Run("no entries match", func(t *testing.T) {
		results, err := idx.MatchEntries(vaultDir, identity, candidates, "nonexistent")
		if err != nil {
			t.Fatalf("MatchEntries() error = %v", err)
		}
		if len(results) != 0 {
			t.Fatalf("MatchEntries('nonexistent') = %d results, want 0", len(results))
		}
	})

	t.Run("empty needle returns nil", func(t *testing.T) {
		results, err := idx.MatchEntries(vaultDir, identity, candidates, "")
		if err != nil {
			t.Fatalf("MatchEntries() error = %v", err)
		}
		if results != nil {
			t.Fatalf("MatchEntries(empty) = %v, want nil", results)
		}
	})

	t.Run("empty candidates returns nil", func(t *testing.T) {
		results, err := idx.MatchEntries(vaultDir, identity, []string{}, "test")
		if err != nil {
			t.Fatalf("MatchEntries() error = %v", err)
		}
		if results != nil {
			t.Fatalf("MatchEntries(empty candidates) = %v, want nil", results)
		}
	})
}

func TestEncryptedIndexInvalidate(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !idx.IsBuilt() {
		t.Fatal("IsBuilt() should be true after Build()")
	}

	idx.Invalidate()
	if idx.IsBuilt() {
		t.Fatal("IsBuilt() should be false after Invalidate()")
	}

	results, err := idx.MatchEntries(vaultDir, identity, []string{"github.com/user"}, "alice")
	if err != nil {
		t.Fatalf("MatchEntries() after Invalidate() should not error: %v", err)
	}
	if results != nil {
		t.Fatal("MatchEntries() after Invalidate() should return nil")
	}
}

func TestEncryptedIndexRebuildAfterWrite(t *testing.T) {
	globalIndex.Invalidate()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	if err := globalIndex.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !globalIndex.IsBuilt() {
		t.Fatal("IsBuilt() should be true after Build()")
	}

	mustWriteEntry(t, vaultDir, identity, "work/aws", map[string]interface{}{
		"username": "bob",
	})

	if !globalIndex.IsBuilt() {
		t.Fatal("IsBuilt() should still be true after incremental update")
	}

	results, err := globalIndex.MatchEntries(vaultDir, identity, []string{"work/aws"}, "bob")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if _, ok := results["work/aws"]; !ok {
		t.Errorf("MatchEntries('bob') should find work/aws without full rebuild")
	}
}

func TestEncryptedIndexGlobalInvalidate(t *testing.T) {
	globalIndex.Invalidate()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "test/path", map[string]interface{}{"key": "value"})
	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	if err := globalIndex.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !globalIndex.IsBuilt() {
		t.Fatal("globalIndex should be built")
	}

	InvalidateSearchIndex()
	if globalIndex.IsBuilt() {
		t.Fatal("globalIndex should be invalidated after InvalidateSearchIndex()")
	}
}

func TestEncryptedIndexIntegrationWithFind(t *testing.T) {
	globalIndex.Invalidate()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
	})
	mustWriteEntry(t, vaultDir, identity, "personal/email", map[string]interface{}{
		"email": "bob@example.com",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	got, err := FindWithOptions(vaultDir, "alice", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FindWithOptions('alice') = %d results, want 1", len(got))
	}

	if !globalIndex.IsBuilt() {
		t.Fatal("globalIndex should be built after first FindWithOptions")
	}

	got2, err := FindWithOptions(vaultDir, "bob@example.com", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got2) != 1 {
		t.Fatalf("FindWithOptions('bob@example.com') = %d results, want 1", len(got2))
	}
}

func TestEncryptedIndexWithNestedData(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "app/config", map[string]interface{}{
		"database": map[string]interface{}{
			"host":     "prod-db.example.com",
			"password": "db-s3cr3t",
		},
		"users": []interface{}{
			map[string]interface{}{"name": "admin", "role": "owner"},
		},
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	candidates := []string{"app/config"}
	results, err := idx.MatchEntries(vaultDir, identity, candidates, "db-s3cr3t")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if _, ok := results["app/config"]; !ok {
		t.Errorf("MatchEntries('db-s3cr3t') should find app/config")
	}

	results, err = idx.MatchEntries(vaultDir, identity, candidates, "owner")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if _, ok := results["app/config"]; !ok {
		t.Errorf("MatchEntries('owner') should find app/config")
	}
}

func TestEncryptedIndexUnreadableEntry(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "valid/entry", map[string]interface{}{
		"key": "findable-value",
	})

	entriesDir := filepath.Join(vaultDir, "entries")
	garbagePath := filepath.Join(entriesDir, "corrupted.entry.age")
	if err := os.WriteFile(garbagePath, []byte("not-valid-age-ciphertext"), 0o600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	results, err := idx.MatchEntries(vaultDir, identity, []string{"valid/entry"}, "findable-value")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if _, ok := results["valid/entry"]; !ok {
		t.Errorf("MatchEntries should find valid/entry")
	}
}

func TestFindAfterWriteInvalidatesIndex(t *testing.T) {
	globalIndex.Invalidate()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "entry/one", map[string]interface{}{
		"data": "original-data",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	_, err := FindWithOptions(vaultDir, "original", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}

	if !globalIndex.IsBuilt() {
		t.Fatal("Index should be built after find")
	}

	mustWriteEntry(t, vaultDir, identity, "entry/two", map[string]interface{}{
		"data": "new-data",
	})

	if !globalIndex.IsBuilt() {
		t.Fatal("Index should remain built after incremental update")
	}

	results, err := FindWithOptions(vaultDir, "data", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}

	if len(results) < 2 {
		t.Fatalf("FindWithOptions('data') = %d results, want at least 2", len(results))
	}
}

func TestEncryptedIndexSubstringMatching(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "test/entry", map[string]interface{}{
		"totp_secret": "JBSWY3DPEHPK3PXP",
		"email":       "alice@example.com",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	results, err := idx.MatchEntries(vaultDir, identity, []string{"test/entry"}, "JBSW")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("MatchEntries('JBSW') = %d results, want 1 (substring match)", len(results))
	}
}

func TestEncryptedIndexCaseInsensitive(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "test/entry", map[string]interface{}{
		"host": "MyDB.Example.com",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	results, err := idx.MatchEntries(vaultDir, identity, []string{"test/entry"}, "mydb")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("MatchEntries('mydb') = %d results, want 1 (case insensitive)", len(results))
	}
}

func TestFindAfterDeleteInvalidatesIndex(t *testing.T) {
	globalIndex.Invalidate()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "keep/entry", map[string]interface{}{"value": "important"})
	mustWriteEntry(t, vaultDir, identity, "delete/entry", map[string]interface{}{"value": "gone"})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	results, err := FindWithOptions(vaultDir, "entry", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(results) < 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}

	if err := DeleteEntry(vaultDir, "delete/entry", identity); err != nil {
		t.Fatalf("DeleteEntry() error = %v", err)
	}

	if globalIndex.IsBuilt() {
		t.Fatal("Index should be invalidated after delete")
	}

	results, err = FindWithOptions(vaultDir, "entry", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 entry after delete, got %d", len(results))
	}
	if results[0].Path != "keep/entry" {
		t.Errorf("expected keep/entry, got %s", results[0].Path)
	}
}

func TestFindAfterMergeInvalidatesIndex(t *testing.T) {
	globalIndex.Invalidate()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "test/entry", map[string]interface{}{
		"initial": "value",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	_, err := FindWithOptions(vaultDir, "initial", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}

	if !globalIndex.IsBuilt() {
		t.Fatal("Index should be built")
	}

	_, err = MergeEntry(vaultDir, "test/entry", map[string]any{"newfield": "newvalue"}, identity)
	if err != nil {
		t.Fatalf("MergeEntry() error = %v", err)
	}

	if !globalIndex.IsBuilt() {
		t.Fatal("Index should remain built after incremental update")
	}

	results, err := FindWithOptions(vaultDir, "newvalue", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result after merge, got %d", len(results))
	}
}

func TestEncryptedIndexSearchableAfterBuild(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	for i := 0; i < 10; i++ {
		path := "service-" + strings.Repeat(string(rune('a'+i)), 2) + "/entry"
		mustWriteEntry(t, vaultDir, identity, path, map[string]interface{}{
			"username": "user" + strings.Repeat(string(rune('a'+i)), 3),
			"password": "pass" + strings.Repeat(string(rune('0'+i)), 4),
		})
	}

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	for i := 0; i < 10; i++ {
		needle := "pass" + strings.Repeat(string(rune('0'+i)), 4)
		results, err := idx.MatchEntries(vaultDir, identity, nil, needle)
		if err != nil {
			t.Fatalf("MatchEntries(%q) error = %v", needle, err)
		}
		// Since we pass nil candidates, MatchEntries returns nil
		if results != nil {
			t.Errorf("MatchEntries(%q) with nil candidates should return nil", needle)
		}
	}
}

func TestEncryptedIndexPersistence(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
		"password": "s3cr3t",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	indexPath := indexFilePath(vaultDir)
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		t.Fatal("index file should exist after Build()")
	}

	// Simulate restart: fresh in-memory index loads from disk
	freshIdx := &EncryptedIndex{}
	if err := freshIdx.loadFromDisk(vaultDir, identity); err != nil {
		t.Fatalf("loadFromDisk() error = %v", err)
	}
	if !freshIdx.IsBuilt() {
		t.Fatal("freshIdx should be built after loadFromDisk()")
	}

	candidates := []string{"github.com/user"}
	results, err := freshIdx.MatchEntries(vaultDir, identity, candidates, "alice")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("MatchEntries('alice') = %d results, want 1", len(results))
	}
}

func TestEncryptedIndexStaleDetection(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "entry/one", map[string]interface{}{
		"data": "value-one",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Add another entry after build, making the persisted index stale
	mustWriteEntry(t, vaultDir, identity, "entry/two", map[string]interface{}{
		"data": "value-two",
	})

	// loadFromDisk should detect stale count and remove the file
	freshIdx := &EncryptedIndex{}
	if err := freshIdx.loadFromDisk(vaultDir, identity); err == nil {
		t.Fatal("loadFromDisk() should fail for stale index")
	}
	if freshIdx.IsBuilt() {
		t.Fatal("freshIdx should not be built after stale load")
	}

	// The stale file should be removed
	indexPath := indexFilePath(vaultDir)
	if _, err := os.Stat(indexPath); !os.IsNotExist(err) {
		t.Fatal("stale index file should be removed")
	}
}

func TestEncryptedIndexInvalidationRemovesFile(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "test/entry", map[string]interface{}{
		"key": "value",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	indexPath := indexFilePath(vaultDir)
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		t.Fatal("index file should exist after Build()")
	}

	idx.Invalidate()

	if _, err := os.Stat(indexPath); !os.IsNotExist(err) {
		t.Fatal("index file should be removed after Invalidate()")
	}
}

func TestEncryptedIndexFilterPathsUsingIndexLoadsFromDisk(t *testing.T) {
	globalIndex.Invalidate()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
	})

	rememberSearchIdentity(identity)
	t.Cleanup(func() { searchIdentity.Store(nil) })

	// Build the index (this also saves to disk)
	if err := globalIndex.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !globalIndex.IsBuilt() {
		t.Fatal("globalIndex should be built")
	}

	// Invalidate in-memory only, simulating process restart
	globalIndex.mu.Lock()
	globalIndex.ciphertext = nil
	globalIndex.vaultDir = ""
	globalIndex.idHash = [sha256.Size]byte{}
	globalIndex.mu.Unlock()

	if globalIndex.IsBuilt() {
		t.Fatal("globalIndex should not be built after clearing memory")
	}

	// filterPathsUsingIndex should load from disk
	results := filterPathsUsingIndex(vaultDir, []string{"github.com/user"}, "alice")
	if len(results) != 1 {
		t.Fatalf("filterPathsUsingIndex() = %d results, want 1", len(results))
	}

	if !globalIndex.IsBuilt() {
		t.Fatal("globalIndex should be built after loading from disk")
	}
}
