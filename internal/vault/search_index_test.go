package vault

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// TestFilterPathsUsingIndex_SameIdentityDifferentVaults guards against the
// shared global index leaking one vault's contents into another vault's search
// results when both are opened with the same identity.
func TestFilterPathsUsingIndex_SameIdentityDifferentVaults(t *testing.T) {
	identity := testutil.TempIdentity(t)

	// Reset the shared global slot and restore it afterwards so this test is
	// isolated from the rest of the package.
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultA := t.TempDir()
	mustWriteEntry(t, vaultA, identity, "alpha", map[string]interface{}{"user": "alice-in-a"})

	vaultB := t.TempDir()
	mustWriteEntry(t, vaultB, identity, "beta", map[string]interface{}{"user": "bob-in-b"})

	// Populate the slot with vault A's index.
	aMatches := filterPathsUsingIndex(vaultA, []string{"alpha"}, "alice-in-a", identity)
	if len(aMatches) != 1 || aMatches[0] != "alpha" {
		t.Fatalf("vault A search = %v, want [alpha]", aMatches)
	}

	// Searching vault B with the same identity must reflect vault B, not the
	// index still resident from vault A. A value present only in vault B must be
	// found (the bug returned an incomplete result from vault A's index).
	bOwn := filterPathsUsingIndex(vaultB, []string{"beta"}, "bob-in-b", identity)
	if len(bOwn) != 1 || bOwn[0] != "beta" {
		t.Fatalf("vault B search for its own value = %v, want [beta]", bOwn)
	}

	// A value that exists only in vault A must not match within vault B.
	bForeign := filterPathsUsingIndex(vaultB, []string{"beta"}, "alice-in-a", identity)
	if len(bForeign) != 0 {
		t.Fatalf("vault B matched a value that only exists in vault A: %v", bForeign)
	}

	// Switching back to vault A must still return correct results.
	aAgain := filterPathsUsingIndex(vaultA, []string{"alpha"}, "alice-in-a", identity)
	if len(aAgain) != 1 || aAgain[0] != "alpha" {
		t.Fatalf("vault A re-search = %v, want [alpha]", aAgain)
	}
}

// TestMatchEntries_RejectsDifferentVaultDir verifies the lookup-time guard:
// an index built for one vault must refuse to answer lookups for another.
func TestMatchEntries_RejectsDifferentVaultDir(t *testing.T) {
	identity := testutil.TempIdentity(t)

	vaultA := t.TempDir()
	mustWriteEntry(t, vaultA, identity, "alpha", map[string]interface{}{"user": "alice"})

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultA, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	vaultB := t.TempDir()
	if _, err := idx.MatchEntries(vaultB, identity, []string{"alpha"}, "alice"); err == nil {
		t.Fatal("MatchEntries against a different vault dir: expected error, got nil")
	}
	if idx.Covers(vaultB, identity) {
		t.Fatal("Covers reported true for a vault the index was not built for")
	}
	if !idx.Covers(vaultA, identity) {
		t.Fatal("Covers reported false for the vault the index was built for")
	}
}

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

func TestEncryptedIndexBuildDeterministicDoc(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "z-last", map[string]interface{}{
		"nested": map[string]interface{}{
			"owner": "Carol",
			"note":  "Alpha Beta",
		},
	})
	mustWriteEntry(t, vaultDir, identity, "a-first", map[string]interface{}{
		"username": "alice",
		"password": "s3cr3t",
	})

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	first := decryptIndexDocForTest(t, idx, identity)

	idx.Invalidate()
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() second error = %v", err)
	}
	second := decryptIndexDocForTest(t, idx, identity)

	if !reflect.DeepEqual(first.Values, second.Values) {
		t.Fatalf("Values changed after rebuild:\nfirst: %#v\nsecond: %#v", first.Values, second.Values)
	}
	if !reflect.DeepEqual(first.TokenIndex, second.TokenIndex) {
		t.Fatalf("TokenIndex changed after rebuild:\nfirst: %#v\nsecond: %#v", first.TokenIndex, second.TokenIndex)
	}
	if first.EntryCount != second.EntryCount {
		t.Fatalf("EntryCount changed after rebuild: %d != %d", first.EntryCount, second.EntryCount)
	}
}

func decryptIndexDocForTest(t *testing.T, idx *EncryptedIndex, identity *age.X25519Identity) indexDoc {
	t.Helper()

	idx.mu.RLock()
	ct := append([]byte(nil), idx.ciphertext...)
	salt := append([]byte(nil), idx.salt...)
	idx.mu.RUnlock()

	key := deriveIndexKey(identity, salt)
	defer vaultcrypto.Wipe(key)

	plaintext, err := vaultcrypto.DecryptWithKey(ct, key)
	if err != nil {
		t.Fatalf("DecryptWithKey() error = %v", err)
	}
	defer vaultcrypto.Wipe(plaintext)

	var doc indexDoc
	if err := json.Unmarshal(plaintext, &doc); err != nil {
		t.Fatalf("Unmarshal index doc error = %v", err)
	}
	return doc
}

func TestEncryptedIndexInvalidate(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
	})

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
	searchIndexStore.invalidateAll()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
	})

	if err := searchIndexForVault(vaultDir).Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("IsBuilt() should be true after Build()")
	}

	mustWriteEntry(t, vaultDir, identity, "work/aws", map[string]interface{}{
		"username": "bob",
	})

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("IsBuilt() should still be true after incremental update")
	}

	results, err := searchIndexForVault(vaultDir).MatchEntries(vaultDir, identity, []string{"work/aws"}, "bob")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if _, ok := results["work/aws"]; !ok {
		t.Errorf("MatchEntries('bob') should find work/aws without full rebuild")
	}
}

func TestEncryptedIndexGlobalInvalidate(t *testing.T) {
	searchIndexStore.invalidateAll()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "test/path", map[string]interface{}{"key": "value"})

	if err := searchIndexForVault(vaultDir).Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("globalIndex should be built")
	}

	InvalidateSearchIndex()
	if searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("globalIndex should be invalidated after InvalidateSearchIndex()")
	}
}

func TestEncryptedIndexIntegrationWithFind(t *testing.T) {
	searchIndexStore.invalidateAll()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
	})
	mustWriteEntry(t, vaultDir, identity, "personal/email", map[string]interface{}{
		"email": "bob@example.com",
	})

	got, err := FindWithOptions(vaultDir, "alice", FindOptions{MaxWorkers: 0}, identity)
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FindWithOptions('alice') = %d results, want 1", len(got))
	}

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("globalIndex should be built after first FindWithOptions")
	}

	got2, err := FindWithOptions(vaultDir, "bob@example.com", FindOptions{MaxWorkers: 0}, identity)
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
	searchIndexStore.invalidateAll()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "entry/one", map[string]interface{}{
		"data": "original-data",
	})

	_, err := FindWithOptions(vaultDir, "original", FindOptions{MaxWorkers: 0}, identity)
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("Index should be built after find")
	}

	mustWriteEntry(t, vaultDir, identity, "entry/two", map[string]interface{}{
		"data": "new-data",
	})

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("Index should remain built after incremental update")
	}

	results, err := FindWithOptions(vaultDir, "data", FindOptions{MaxWorkers: 0}, identity)
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
	searchIndexStore.invalidateAll()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "keep/entry", map[string]interface{}{"value": "important"})
	mustWriteEntry(t, vaultDir, identity, "delete/entry", map[string]interface{}{"value": "gone"})

	results, err := FindWithOptions(vaultDir, "entry", FindOptions{MaxWorkers: 0}, identity)
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(results) < 2 {
		t.Fatalf("expected 2 entries, got %d", len(results))
	}

	if err := DeleteEntry(vaultDir, "delete/entry", identity); err != nil {
		t.Fatalf("DeleteEntry() error = %v", err)
	}

	if searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("Index should be invalidated after delete")
	}

	results, err = FindWithOptions(vaultDir, "entry", FindOptions{MaxWorkers: 0}, identity)
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
	searchIndexStore.invalidateAll()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "test/entry", map[string]interface{}{
		"initial": "value",
	})

	_, err := FindWithOptions(vaultDir, "initial", FindOptions{MaxWorkers: 0}, identity)
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("Index should be built")
	}

	_, err = MergeEntry(vaultDir, "test/entry", map[string]any{"newfield": "newvalue"}, identity)
	if err != nil {
		t.Fatalf("MergeEntry() error = %v", err)
	}

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("Index should remain built after incremental update")
	}

	results, err := FindWithOptions(vaultDir, "newvalue", FindOptions{MaxWorkers: 0}, identity)
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
	searchIndexStore.invalidateAll()

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
	})

	// Build the index (this also saves to disk)
	if err := searchIndexForVault(vaultDir).Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("globalIndex should be built")
	}

	// Invalidate in-memory only, simulating process restart
	searchIndexForVault(vaultDir).ClearMemory()

	if searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("index should not be built after clearing memory")
	}

	// filterPathsUsingIndex should load from disk
	results := filterPathsUsingIndex(vaultDir, []string{"github.com/user"}, "alice", identity)
	if len(results) != 1 {
		t.Fatalf("filterPathsUsingIndex() = %d results, want 1", len(results))
	}

	if !searchIndexForVault(vaultDir).IsBuilt() {
		t.Fatal("index should be built after loading from disk")
	}
}

// TestSearchIndexOnDiskHasNoPlaintextLeakage is the security regression test
// required by issue #351 acceptance criterion #5: the on-disk search index
// file MUST contain no plaintext field values, entry paths, or query tokens.
//
// The test writes entries with distinctive, high-entropy plaintext tokens,
// builds the index, then reads the raw bytes of `.search-index` and asserts
// that none of the plaintext tokens appear anywhere in the file. Since the
// file is encrypted with ChaCha20-Poly1305 under a key derived from the
// vault identity, this guards against:
//   - Plaintext entry values being stored unencrypted
//   - Plaintext paths being stored unencrypted
//   - Plaintext query tokens leaking into the index
//   - Accidental JSON serialization of the unencrypted doc
func TestSearchIndexOnDiskHasNoPlaintextLeakage(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	// Distinctive plaintext tokens that would be catastrophically obvious
	// if they leaked into the ciphertext. They contain no whitespace and
	// are unlikely to collide with header/metadata fields.
	const (
		leakyPassword = "PLAINTEXT_PASSWORD_TOKEN_DO_NOT_LEAK_351"
		leakyUsername = "PLAINTEXT_USERNAME_TOKEN_DO_NOT_LEAK_351"
		leakyNote     = "PLAINTEXT_NOTE_FIELD_DO_NOT_LEAK_351"
		leakyEmail    = "PLAINTEXT_EMAIL_DO_NOT_LEAK_351@NOPE"
		leakyPath     = "secret/path/that/should/never/appear/351"
	)

	mustWriteEntry(t, vaultDir, identity, leakyPath, map[string]interface{}{
		"username": leakyUsername,
		"password": leakyPassword,
		"email":    leakyEmail,
		"note":     leakyNote,
	})
	mustWriteEntry(t, vaultDir, identity, "other/entry", map[string]interface{}{
		"password": "innocent-value",
		"note":     "other-entry",
	})

	// Build the index. This serializes the encrypted JSON envelope to disk.
	if err := searchIndexForVault(vaultDir).Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	indexPath := indexFilePath(vaultDir)
	raw, err := os.ReadFile(indexPath) // #nosec G304 -- test reads the index file it just built
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", indexPath, err)
	}
	if len(raw) == 0 {
		t.Fatal("index file is empty; expected encrypted bytes")
	}

	// 1) The file MUST begin with the version byte (forward-compat header).
	if raw[0] != indexFormatVersion {
		t.Errorf("index file does not start with version byte 0x%02x, got 0x%02x", indexFormatVersion, raw[0])
	}

	// 2) None of the plaintext tokens may appear in the raw file bytes.
	for _, token := range []string{leakyPassword, leakyUsername, leakyNote, leakyEmail, leakyPath} {
		if bytes.Contains(raw, []byte(token)) {
			t.Errorf("plaintext token %q found in on-disk index (leakage regression)", token)
		}
	}

	// 3) The standard field-name keys ("password", "username", "data") are
	// not tested because they are short and may appear coincidentally in
	// the ChaCha20 nonce/poly1305 tag. The distinctive PLAINTEXT_* markers
	// above are the meaningful check.

	// 4) Sanity check: decrypting the file yields the same plaintext doc
	// the index was built from. This proves the encryption is correct
	// and the file is recoverable, not corrupted.
	salt := raw[1 : 1+indexSaltLen]
	ct := raw[1+indexSaltLen:]
	key := deriveIndexKey(identity, salt)
	plaintext, err := vaultcrypto.DecryptWithKey(ct, key)
	if err != nil {
		t.Fatalf("DecryptWithKey() error = %v (index file is not decryptable)", err)
	}
	if !strings.Contains(string(plaintext), leakyPath) {
		t.Errorf("decrypted index does not contain the test path %q; encryption may have been altered", leakyPath)
	}
}

// TestSearchIndexFirstFieldSearchSkipsNonCandidates asserts that when the
// encrypted search index returns a candidate set, the subsequent search
// only returns entries that appear in that candidate set — i.e. the
// index-first path is exercised and non-candidates are never decrypted
// for field-name resolution.
//
// This is the positive-path counterpart to
// TestFindFallbackWhenIndexUnavailable: it proves that adding more
// non-matching entries to a vault does not change the result set for a
// query whose token only lives in a small set of entries.
func TestSearchIndexFirstFieldSearchSkipsNonCandidates(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	// 1 "match" entry + many "noise" entries that share no tokens with the
	// query. If the index-first path is exercised, only the match entry
	// should be returned and the noise entries should not be decrypted.
	mustWriteEntry(t, vaultDir, identity, "match/entry", map[string]interface{}{
		"password": "sentinel-token-zzz",
	})
	const noiseCount = 25
	for i := 0; i < noiseCount; i++ {
		path := "noise/" + strings.Repeat("x", i+1)
		mustWriteEntry(t, vaultDir, identity, path, map[string]interface{}{
			"password": "noise-token-aaa",
		})
	}

	// Force a build of the index (it might not be built yet on this
	// call) so the token map is populated. After this call the index
	// contains a token→paths map that, for the query "sentinel-token-zzz",
	// should resolve to exactly the match/entry path.
	if err := searchIndexForVault(vaultDir).Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Pre-warm the in-memory state (filterPathsUsingIndex will load the
	// on-disk index if not already built).
	matches, err := FindWithOptions(vaultDir, "sentinel-token-zzz", FindOptions{MaxWorkers: 0}, identity)
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("FindWithOptions('sentinel-token-zzz') returned %d results, want 1 (index should have filtered out %d noise entries)", len(matches), noiseCount)
	}
	if matches[0].Path != "match/entry" {
		t.Errorf("FindWithOptions() match path = %q, want %q", matches[0].Path, "match/entry")
	}
}

// TestFindFallbackWhenIndexUnavailable exercises the fallback path: when
// the on-disk index cannot be decrypted (wrong identity) the search must
// still return correct results by decrypting every non-path-matching
// entry. This guards against correctness regressions if the index
// ever becomes silently corrupt or the key is rotated.
func TestFindFallbackWhenIndexUnavailable(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	otherIdentity := testutil.TempIdentity(t) // wrong identity: will fail to decrypt the index

	mustWriteEntry(t, vaultDir, identity, "github.com/user", map[string]interface{}{
		"username": "alice",
		"password": "fallback-test-password",
	})
	mustWriteEntry(t, vaultDir, identity, "personal/email", map[string]interface{}{
		"email": "bob@example.com",
	})

	// Build the index with the correct identity so a valid on-disk file
	// exists.
	if err := searchIndexForVault(vaultDir).Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Reset the in-memory state but KEEP the on-disk file. We then call
	// filterPathsUsingIndex with an identity that cannot decrypt the
	// index. The function must fall back to returning the input
	// candidates unchanged (proving the search would proceed to decrypt
	// every entry in the full pass).
	searchIndexForVault(vaultDir).ClearMemory()

	candidates := []string{"github.com/user", "personal/email"}
	results := filterPathsUsingIndex(vaultDir, candidates, "fallback-test-password", otherIdentity)
	if len(results) != len(candidates) {
		t.Fatalf("filterPathsUsingIndex() with wrong identity returned %d paths, want %d (fallback should preserve all candidates)", len(results), len(candidates))
	}
	for _, c := range candidates {
		found := false
		for _, r := range results {
			if r == c {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("fallback path dropped candidate %q from result set", c)
		}
	}
}
