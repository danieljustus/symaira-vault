package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/testutil"
)

// TestOpenWithPathTraversal covers validateVaultDir error path + Open error return.
func TestOpenWithPathTraversal(t *testing.T) {
	identity := testutil.TempIdentity(t)
	_, err := Open("../evil-vault", identity)
	if err == nil {
		t.Fatal("Open() error = nil, want ErrVaultDirEscapes for path traversal")
	}
}

// TestOpenWithMissingConfig covers the config load error path in Open.
func TestOpenWithMissingConfig(t *testing.T) {
	dir := t.TempDir() // exists but has no config.yaml
	identity := testutil.TempIdentity(t)
	_, err := Open(dir, identity)
	if err == nil {
		t.Fatal("Open() error = nil, want error when config.yaml is missing")
	}
}

// TestOpenWithPassphrasePathTraversal covers validateVaultDir error in OpenWithPassphrase.
func TestOpenWithPassphrasePathTraversal(t *testing.T) {
	_, err := OpenWithPassphrase("../evil-vault", []byte("passphrase"))
	if err == nil {
		t.Fatal("OpenWithPassphrase() error = nil, want ErrVaultDirEscapes")
	}
}

// TestVaultInitMkdirAllError covers the os.MkdirAll failure branch in vault.Init.
func TestVaultInitMkdirAllError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0 has no effect")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(parent, 0o700) //nolint:errcheck

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	err := Init(parent+"/new-vault", identity, cfg)
	if err == nil {
		t.Fatal("Init() error = nil, want error when parent dir is not writable")
	}
}

// TestUnmarshalJSONInvalid covers the json.Unmarshal error path in Entry.UnmarshalJSON.
func TestUnmarshalJSONInvalid(t *testing.T) {
	var e Entry
	if err := e.UnmarshalJSON([]byte("this is not json {")); err == nil {
		t.Fatal("UnmarshalJSON() error = nil, want error for invalid JSON")
	}
}

// TestDeleteEntryNotFound covers os.Remove error when the file doesn't exist.
func TestDeleteEntryNotFound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx access violation in AcquireWriteLock")
	}
	vaultDir := t.TempDir()
	err := DeleteEntry(vaultDir, "nonexistent/entry", nil)
	if err == nil {
		t.Fatal("DeleteEntry() error = nil, want error for non-existent entry")
	}
}

// TestMergeEntryNotFound covers the ReadEntry error path in MergeEntry.
func TestMergeEntryNotFound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: LockFileEx access violation in AcquireWriteLock")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	_, err := MergeEntry(vaultDir, "nonexistent/entry", map[string]any{"key": "val"}, id)
	if err == nil {
		t.Fatal("MergeEntry() error = nil, want error for non-existent entry")
	}
}

// TestInitWithPassphraseMkdirAllError covers the os.MkdirAll failure in InitWithPassphrase.
func TestInitWithPassphraseMkdirAllError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0 has no effect")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(parent, 0o700) //nolint:errcheck

	_, err := InitWithPassphrase(parent+"/new-vault", []byte("passphrase"), config.Default())
	if err == nil {
		t.Fatal("InitWithPassphrase() error = nil, want error when parent dir is not writable")
	}
}

// TestCollectFieldMatchesPrefixlessScalar covers the prefix=="" early-return branch.
func TestCollectFieldMatchesPrefixlessScalar(t *testing.T) {
	matches := make(map[string]struct{})
	// A scalar value with empty prefix should be skipped (not added to matches)
	CollectFieldMatches(matches, "", "just-a-scalar", "just", nil)
	if len(matches) != 0 {
		t.Errorf("expected no matches for prefix-less scalar, got %v", matches)
	}
}

// TestGetRecipientNilVaultPointer covers the v==nil branch of GetRecipient.
func TestGetRecipientNilVaultPointer(t *testing.T) {
	var v *Vault
	_, err := v.GetRecipient()
	if err == nil {
		t.Fatal("GetRecipient() on nil vault should return error")
	}
}

// TestRememberSearchIdentityNilSkips covers the nil-identity early return.
func TestRememberSearchIdentityNilSkips(t *testing.T) {
	// Should not panic and should not overwrite existing identity
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)
	rememberSearchIdentity(nil)
	got := currentSearchIdentity()
	if got == nil {
		t.Error("rememberSearchIdentity(nil) should not overwrite existing identity")
	}
}

// TestFindListError covers the List error return path in Find.
func TestFindListError(t *testing.T) {
	// vaultDir does not exist → List will fail → FindWithOptions returns error
	_, err := FindWithOptions("/nonexistent/vault/dir/that/does/not/exist", "query", FindOptions{MaxWorkers: 0})
	if err == nil {
		t.Fatal("FindWithOptions() error = nil, want error when vault dir does not exist")
	}
}

// TestMergeEntryWithRecipientsNotFound covers the ReadEntry error path in MergeEntryWithRecipients.
func TestMergeEntryWithRecipientsNotFoundCoverage(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	_, err := MergeEntryWithRecipients(vaultDir, "nonexistent/entry", map[string]any{"k": "v"}, id)
	if err == nil {
		t.Fatal("MergeEntryWithRecipients() error = nil, want error for non-existent entry")
	}
}

// TestSafeWriteFileOnDirectory covers the ENOTDIR error when writing to a directory.
func TestSafeWriteFileOnDirectory(t *testing.T) {
	dir := t.TempDir()
	err := SafeWriteFile(dir, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("SafeWriteFile() on directory = nil, want error")
	}
}

// TestSafeRemoveOnDirectory covers the ENOTDIR error when removing a directory.
func TestSafeRemoveOnDirectory(t *testing.T) {
	dir := t.TempDir()
	subdir := dir + "/subdir"
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	err := SafeRemove(subdir)
	if err == nil {
		t.Fatal("SafeRemove() on directory = nil, want error")
	}
}

// TestSafeRemoveNonexistent covers the error when removing a nonexistent file.
func TestSafeRemoveNonexistent(t *testing.T) {
	err := SafeRemove("/nonexistent/file/that/does/not/exist.age")
	if err == nil {
		t.Fatal("SafeRemove() on nonexistent file = nil, want error")
	}
}

// TestReadEntryCorruptedFile covers the decrypt error path with a corrupted .age file.
func TestReadEntryCorruptedFile(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	entryDir := vaultDir + "/entries/test"
	os.MkdirAll(entryDir, 0o700)
	os.WriteFile(entryDir+"/entry.age", []byte("this is not valid age ciphertext"), 0o600)

	_, err := ReadEntry(vaultDir, "test/entry", id)
	if err == nil {
		t.Fatal("ReadEntry() with corrupted file = nil, want decrypt error")
	}
}

// TestCollectFieldMatchesNilMap covers nil map handling in CollectFieldMatches.
func TestCollectFieldMatchesNilMap(t *testing.T) {
	matches := make(map[string]struct{})
	CollectFieldMatches(matches, "prefix", nil, "search", nil)
	if len(matches) != 0 {
		t.Errorf("expected no matches for nil, got %v", matches)
	}
}

// TestCollectFieldMatchesEmptyMap covers empty map handling.
func TestCollectFieldMatchesEmptyMap(t *testing.T) {
	matches := make(map[string]struct{})
	CollectFieldMatches(matches, "prefix", map[string]any{}, "search", nil)
	if len(matches) != 0 {
		t.Errorf("expected no matches for empty map, got %v", matches)
	}
}

// TestCollectFieldMatchesArrayWithNil covers array with nil elements.
func TestCollectFieldMatchesArrayWithNil(t *testing.T) {
	matches := make(map[string]struct{})
	CollectFieldMatches(matches, "arr", []any{nil, "valid"}, "valid", nil)
	if _, ok := matches["arr[1]"]; !ok {
		t.Errorf("expected arr[1] to match, got %v", matches)
	}
}

// TestCollectFieldMatchesDeeplyNested covers deeply nested structure.
func TestCollectFieldMatchesDeeplyNested(t *testing.T) {
	matches := make(map[string]struct{})
	CollectFieldMatches(matches, "", map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": "secret123",
			},
		},
	}, "secret", nil)
	if _, ok := matches["level1.level2.level3"]; !ok {
		t.Errorf("expected nested path to match, got %v", matches)
	}
}

// TestFindReturnsEmptyForNoMatches covers Find with query that matches nothing.
func TestFindReturnsEmptyForNoMatches(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntryCoverage(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	got, err := FindWithOptions(vaultDir, "nomatch", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("Find() with no matches returned %d results, want 0", len(got))
	}
}

// TestFindWithOptionsReturnsEmptyForNoMatches covers FindWithOptions with query that matches nothing.
func TestFindWithOptionsReturnsEmptyForNoMatches(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntryCoverage(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})

	got, err := FindWithOptions(vaultDir, "nomatch", FindOptions{MaxWorkers: 4})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("FindWithOptions() with no matches returned %d results, want 0", len(got))
	}
}

// TestFindWithUnicodeQuery covers Find with unicode query.
func TestFindWithUnicodeQuery(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntryCoverage(t, vaultDir, id, "test/entry", map[string]interface{}{"data": "日本語テスト"})

	got, err := FindWithOptions(vaultDir, "日本語", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Find() with unicode query returned %d results, want 1", len(got))
	}
}

// TestFindPathMatchesBeforeFieldSearch covers path matching that avoids decryption.
func TestFindPathMatchesBeforeFieldSearch(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntryCoverage(t, vaultDir, id, "github.com/user", map[string]interface{}{
		"username": "alice",
		"password": "secret123",
	})

	got, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Find() returned %d results, want 1", len(got))
	}
	if !containsStringCoverage(got[0].Fields, "path") {
		t.Errorf("expected path match, got fields %v", got[0].Fields)
	}
}

// TestFindWithOptionsPathMatchesBeforeFieldSearch covers path matching in concurrent search.
func TestFindWithOptionsPathMatchesBeforeFieldSearch(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntryCoverage(t, vaultDir, id, "github.com/user", map[string]interface{}{
		"username": "alice",
		"password": "secret123",
	})

	got, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 4})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FindWithOptions() returned %d results, want 1", len(got))
	}
	if !containsStringCoverage(got[0].Fields, "path") {
		t.Errorf("expected path match, got fields %v", got[0].Fields)
	}
}

// TestInitWithEmptyDir tests Init with empty vaultDir.
func TestInitWithEmptyDir(t *testing.T) {
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	err := Init("", identity, cfg)
	if err == nil {
		t.Fatal("Init() with empty vaultDir = nil, want error")
	}
}

// TestInitNilIdentity tests Init with nil identity.
func TestInitNilIdentity(t *testing.T) {
	cfg := config.Default()
	err := Init(t.TempDir(), nil, cfg)
	if err == nil {
		t.Fatal("Init() with nil identity = nil, want error")
	}
}

// TestInitNilConfig tests Init with nil config.
func TestInitNilConfig(t *testing.T) {
	identity := testutil.TempIdentity(t)
	err := Init(t.TempDir(), identity, nil)
	if err == nil {
		t.Fatal("Init() with nil config = nil, want error")
	}
}

// TestInitWriteFileError covers the os.WriteFile error path in Init.
func TestInitWriteFileError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permissions test meaningless")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}
	parent := t.TempDir()
	os.Chmod(parent, 0o500)
	defer os.Chmod(parent, 0o700)

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	err := Init(parent+"/vault", identity, cfg)
	if err == nil {
		t.Fatal("Init() = nil, want error when parent is not writable")
	}
}

// TestFindWithOptionsListError covers List error path in FindWithOptions.
func TestFindWithOptionsListError(t *testing.T) {
	searchIdentity.Store(nil)

	_, err := FindWithOptions("/nonexistent/path", "query", FindOptions{MaxWorkers: 4})
	if err == nil {
		t.Fatal("FindWithOptions() error = nil, want error for nonexistent vault")
	}
}

// TestListNonExistentVault covers List with nonexistent vault.
func TestListNonExistentVault(t *testing.T) {
	_, err := List("/nonexistent/vault", "")
	if err == nil {
		t.Fatal("List() error = nil, want error for nonexistent vault")
	}
}

// TestListWithPrefixNonExistentVault covers List with nonexistent vault and prefix.
func TestListWithPrefixNonExistentVault(t *testing.T) {
	_, err := List("/nonexistent/vault", "prefix")
	if err == nil {
		t.Fatal("List() error = nil, want error for nonexistent vault")
	}
}

// TestAutoCommitNilConfig covers AutoCommit with nil config.
func TestAutoCommitNilConfig(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.Git = nil

	Init(vaultDir, identity, cfg)
	v, _ := Open(vaultDir, identity)

	err := v.AutoCommit("test")
	if err != nil {
		t.Fatalf("AutoCommit() with nil Git config error = %v", err)
	}
}

// TestOpenWithPassphraseFileNotFound covers OpenWithPassphrase when identity file is missing.
func TestOpenWithPassphraseFileNotFound(t *testing.T) {
	vaultDir := t.TempDir()
	_, err := OpenWithPassphrase(vaultDir, []byte("passphrase"))
	if err == nil {
		t.Fatal("OpenWithPassphrase() error = nil, want error when identity file is missing")
	}
}

// TestFindNoPathMatchesDecryptsAll covers Find when no paths match and all entries need decryption.
func TestFindNoPathMatchesDecryptsAll(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntryCoverage(t, vaultDir, id, "github.com/user", map[string]interface{}{
		"username": "alice",
		"password": "secret123",
	})

	got, err := FindWithOptions(vaultDir, "secret", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Find() returned %d results, want 1", len(got))
	}
	if !containsStringCoverage(got[0].Fields, "password") {
		t.Errorf("expected password match, got fields %v", got[0].Fields)
	}
}

// TestFindMatchesMultipleEntries covers FindWithOptions when multiple entries match.
func TestFindMatchesMultipleEntries(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntryCoverage(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntryCoverage(t, vaultDir, id, "github.com/work", map[string]interface{}{"username": "bob"})
	mustWriteEntryCoverage(t, vaultDir, id, "gitlab.com/user", map[string]interface{}{"username": "carol"})

	got, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 0})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("FindWithOptions() returned %d results, want 2", len(got))
	}
}

// TestFindWithOptionsMatchesMultipleEntries covers FindWithOptions when multiple entries match.
func TestFindWithOptionsMatchesMultipleEntries(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntryCoverage(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntryCoverage(t, vaultDir, id, "github.com/work", map[string]interface{}{"username": "bob"})
	mustWriteEntryCoverage(t, vaultDir, id, "gitlab.com/user", map[string]interface{}{"username": "carol"})

	got, err := FindWithOptions(vaultDir, "github", FindOptions{MaxWorkers: 4})
	if err != nil {
		t.Fatalf("FindWithOptions() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("FindWithOptions() returned %d results, want 2", len(got))
	}
}

func TestOpenMigrateGitignoreError(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.Git = &config.GitConfig{AutoPush: false}

	Init(vaultDir, identity, cfg)
	WriteEntry(vaultDir, "test", &Entry{Data: map[string]any{"k": "v"}}, identity)

	os.MkdirAll(filepath.Join(vaultDir, ".git"), 0o700)

	if _, err := Open(vaultDir, identity); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
}

func TestOpenCreatesGitignore(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.Git = &config.GitConfig{AutoPush: false}

	Init(vaultDir, identity, cfg)

	gitDir := filepath.Join(vaultDir, ".git")
	os.MkdirAll(gitDir, 0o700)

	_, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	gitignorePath := filepath.Join(vaultDir, ".gitignore")
	if _, statErr := os.Stat(gitignorePath); statErr != nil {
		t.Errorf(".gitignore not created: %v", statErr)
	}
}

func TestGetEntryMetadataFileNotFound(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	_, err := GetEntryMetadata(vaultDir, "nonexistent/entry", id)
	if err == nil {
		t.Fatal("GetEntryMetadata() error = nil, want error for nonexistent entry")
	}
}

func TestGetEntryMetadataCorruptedFile(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	entryDir := filepath.Join(vaultDir, "entries", "test")
	os.MkdirAll(entryDir, 0o700)
	os.WriteFile(filepath.Join(entryDir, "entry.age"), []byte("corrupt"), 0o600)

	_, err := GetEntryMetadata(vaultDir, "test/entry", id)
	if err == nil {
		t.Fatal("GetEntryMetadata() error = nil, want decrypt error")
	}
}

func TestDeleteEntryLegacyNotFound(t *testing.T) {
	vaultDir := t.TempDir()
	os.MkdirAll(filepath.Join(vaultDir, "entries"), 0o700)

	err := DeleteEntry(vaultDir, "nonexistent", nil)
	if err == nil {
		t.Fatal("DeleteEntry() error = nil, want error")
	}
}

func TestWriteEntryToReadOnlyDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; permissions test meaningless")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}
	parent := t.TempDir()
	os.Chmod(parent, 0o555)
	defer os.Chmod(parent, 0o700)

	identity := testutil.TempIdentity(t)
	err := WriteEntry(parent, "test", &Entry{Data: map[string]any{"k": "v"}}, identity)
	if err == nil {
		t.Fatal("WriteEntry() = nil, want error")
	}
}

func TestEntryUnmarshalInitializesNilData(t *testing.T) {
	var entry Entry
	if err := entry.UnmarshalJSON([]byte(`{"meta":{}}`)); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if entry.Data == nil {
		t.Fatal("Data = nil, want initialized map")
	}
}

func TestEntryNilGuardsAndDefaults(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	if _, err := ReadEntry(vaultDir, "test", nil); err == nil {
		t.Fatal("ReadEntry() nil identity error = nil")
	}
	if err := WriteEntry(vaultDir, "test", nil, identity); err == nil {
		t.Fatal("WriteEntry() nil entry error = nil")
	}
	if err := WriteEntry(vaultDir, "test", &Entry{}, nil); err == nil {
		t.Fatal("WriteEntry() nil identity error = nil")
	}
	if err := WriteEntry(vaultDir, "empty", &Entry{}, identity); err != nil {
		t.Fatalf("WriteEntry() empty entry error = %v", err)
	}
	got, err := ReadEntry(vaultDir, "empty", identity)
	if err != nil {
		t.Fatalf("ReadEntry() empty entry error = %v", err)
	}
	if got.Data == nil {
		t.Fatal("Data = nil, want initialized map")
	}
	if cloneEntry(nil) != nil {
		t.Fatal("cloneEntry(nil) != nil")
	}
}

func TestNormalizeConfigInitializesAgentAllowedPaths(t *testing.T) {
	cfg := &config.Config{Agents: map[string]config.AgentProfile{"agent": {}}}
	normalizeConfig(cfg)
	profile := cfg.Agents["agent"]
	if profile.Name != "agent" {
		t.Fatalf("Name = %q, want agent", profile.Name)
	}
	if profile.AllowedPaths == nil {
		t.Fatal("AllowedPaths = nil, want empty slice")
	}
}

func TestRecipientsManagerRejectsTraversalVaultDir(t *testing.T) {
	rm := NewRecipientsManager("../vault")
	if _, err := rm.LoadRecipients(); err == nil {
		t.Fatal("LoadRecipients() error = nil")
	}
	if _, err := rm.LoadRecipientStrings(); err == nil {
		t.Fatal("LoadRecipientStrings() error = nil")
	}
	if err := rm.AddRecipient(testutil.TempIdentity(t).Recipient().String()); err == nil {
		t.Fatal("AddRecipient() error = nil")
	}
	if err := rm.RemoveRecipient(testutil.TempIdentity(t).Recipient().String()); err == nil {
		t.Fatal("RemoveRecipient() error = nil")
	}
	if _, err := rm.ListRecipients(); err == nil {
		t.Fatal("ListRecipients() error = nil")
	}
}

func TestWriteEntryWithRecipientsNilData(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	if err := WriteEntryWithRecipients(vaultDir, "empty", &Entry{}, identity); err != nil {
		t.Fatalf("WriteEntryWithRecipients() error = %v", err)
	}
	got, err := ReadEntry(vaultDir, "empty", identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if got.Data == nil {
		t.Fatal("Data = nil, want initialized map")
	}
}

func TestAutoCommitUsesDefaultMessage(t *testing.T) {
	v := &Vault{Dir: t.TempDir(), Config: &config.Config{}}
	if err := v.AutoCommit(""); err != nil {
		t.Fatalf("AutoCommit() error = %v", err)
	}
}

func mustWriteEntryCoverage(t *testing.T, vaultDir string, identity *age.X25519Identity, path string, data map[string]interface{}) {
	t.Helper()
	if err := WriteEntry(vaultDir, path, &Entry{Data: data}, identity); err != nil {
		t.Fatalf("WriteEntry(%q) error = %v", path, err)
	}
}

func containsStringCoverage(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// TestInitReadOnlyDirectory covers the write error when vault dir is not writable.
func TestInitReadOnlyDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod 0 has no effect")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: chmod behavior differs")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	defer os.Chmod(parent, 0o700) //nolint:errcheck

	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	err := Init(parent+"/readonly-vault", identity, cfg)
	if err == nil {
		t.Fatal("Init() on read-only parent = nil, want write error")
	}
}
