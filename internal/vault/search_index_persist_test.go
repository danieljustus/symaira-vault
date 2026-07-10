package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// TestUpdateEntryPersistsEditToDisk verifies that an in-place edit applied via
// the incremental UpdateEntry path is written to the on-disk index, so a fresh
// process reloading the index sees the new value rather than the stale one. An
// in-place edit leaves the vault entry count unchanged, so the on-disk
// staleness check (entry count) would otherwise happily accept a stale index.
func TestUpdateEntryPersistsEditToDisk(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "acct", map[string]interface{}{"user": "oldvalue"})

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Edit the entry in place, then update the index incrementally.
	mustWriteEntry(t, vaultDir, identity, "acct", map[string]interface{}{"user": "newvalue"})
	if err := idx.UpdateEntry(vaultDir, "acct", identity); err != nil {
		t.Fatalf("UpdateEntry() error = %v", err)
	}

	// Simulate a restart: a fresh index loads only what is on disk.
	fresh := &EncryptedIndex{}
	if err := fresh.loadFromDisk(vaultDir, identity); err != nil {
		t.Fatalf("loadFromDisk() error = %v", err)
	}
	if !fresh.IsBuilt() {
		t.Fatal("fresh index not built from disk after UpdateEntry persist")
	}

	newMatch, err := fresh.MatchEntries(vaultDir, identity, []string{"acct"}, "newvalue")
	if err != nil {
		t.Fatalf("MatchEntries(new) error = %v", err)
	}
	if _, ok := newMatch["acct"]; !ok {
		t.Error("on-disk index is missing the edited value after restart")
	}

	oldMatch, err := fresh.MatchEntries(vaultDir, identity, []string{"acct"}, "oldvalue")
	if err != nil {
		t.Fatalf("MatchEntries(old) error = %v", err)
	}
	if _, ok := oldMatch["acct"]; ok {
		t.Error("on-disk index still matches the stale pre-edit value after restart")
	}
}

// TestRemoveEntryPersistsDeleteToDisk verifies that a delete applied via the
// incremental RemoveEntry path is persisted AND that the stored entry count is
// decremented, so the reloaded index passes the staleness check and no longer
// matches the removed entry.
func TestRemoveEntryPersistsDeleteToDisk(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "keep", map[string]interface{}{"user": "keepvalue"})
	mustWriteEntry(t, vaultDir, identity, "gone", map[string]interface{}{"user": "gonevalue"})

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if err := DeleteEntry(vaultDir, "gone", identity); err != nil {
		t.Fatalf("DeleteEntry() error = %v", err)
	}
	idx.RemoveEntry("gone", identity)

	// Simulate a restart. The reloaded index must be accepted (entry count was
	// decremented to match the now-smaller vault) and must not match the
	// deleted entry.
	fresh := &EncryptedIndex{}
	if err := fresh.loadFromDisk(vaultDir, identity); err != nil {
		t.Fatalf("loadFromDisk() error = %v", err)
	}
	if !fresh.IsBuilt() {
		t.Fatal("fresh index not built from disk after RemoveEntry (entry count not decremented?)")
	}

	goneMatch, err := fresh.MatchEntries(vaultDir, identity, []string{"gone"}, "gonevalue")
	if err != nil {
		t.Fatalf("MatchEntries(gone) error = %v", err)
	}
	if len(goneMatch) != 0 {
		t.Error("on-disk index still matches the deleted entry after restart")
	}

	keepMatch, err := fresh.MatchEntries(vaultDir, identity, []string{"keep"}, "keepvalue")
	if err != nil {
		t.Fatalf("MatchEntries(keep) error = %v", err)
	}
	if _, ok := keepMatch["keep"]; !ok {
		t.Error("on-disk index lost the surviving entry after a delete")
	}
}

// skipIfRoot skips permission-based failure-injection tests when running as
// root, since root bypasses the write-permission checks these tests rely on.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("skipping permission-based test: running as root")
	}
}

// TestBuildPersistFailureRecordedButIndexStaysUsable verifies that when the
// on-disk write fails during a full build, the failure is recorded via
// LastPersistError but the in-memory index is still built and usable for
// search — a failed persist must never corrupt or discard correct in-memory
// search state.
func TestBuildPersistFailureRecordedButIndexStaysUsable(t *testing.T) {
	skipIfRoot(t)
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "acct", map[string]interface{}{"user": "somevalue"})

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v (unwanted before permission change)", err)
	}
	if idx.LastPersistError() != nil {
		t.Fatalf("LastPersistError() = %v, want nil before permission change", idx.LastPersistError())
	}

	// Remove write permission on the vault directory so the atomic write's
	// os.CreateTemp cannot create its temp file there.
	if err := os.Chmod(vaultDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(vaultDir, 0o700) })

	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v, want nil (persist failure must not fail the build)", err)
	}
	if idx.LastPersistError() == nil {
		t.Fatal("LastPersistError() = nil, want a recorded persistence failure")
	}

	match, err := idx.MatchEntries(vaultDir, identity, []string{"acct"}, "somevalue")
	if err != nil {
		t.Fatalf("MatchEntries() error = %v", err)
	}
	if _, ok := match["acct"]; !ok {
		t.Error("in-memory index lost correctness after a persist failure")
	}
}

// TestUpdateEntryPersistFailureRecorded verifies that a persistence failure
// during the incremental UpdateEntry path is both returned to the caller and
// recorded via LastPersistError.
func TestUpdateEntryPersistFailureRecorded(t *testing.T) {
	skipIfRoot(t)
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "acct", map[string]interface{}{"user": "oldvalue"})

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	mustWriteEntry(t, vaultDir, identity, "acct", map[string]interface{}{"user": "newvalue"})

	if err := os.Chmod(vaultDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(vaultDir, 0o700) })

	if err := idx.UpdateEntry(vaultDir, "acct", identity); err == nil {
		t.Fatal("UpdateEntry() error = nil, want a persistence error")
	}
	if idx.LastPersistError() == nil {
		t.Fatal("LastPersistError() = nil, want a recorded persistence failure")
	}
}

// TestRemoveEntryPersistFailureRecorded verifies that a persistence failure
// during the incremental RemoveEntry path is recorded via LastPersistError
// even though RemoveEntry itself has no error return.
func TestRemoveEntryPersistFailureRecorded(t *testing.T) {
	skipIfRoot(t)
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "keep", map[string]interface{}{"user": "keepvalue"})
	mustWriteEntry(t, vaultDir, identity, "gone", map[string]interface{}{"user": "gonevalue"})

	idx := &EncryptedIndex{}
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if err := DeleteEntry(vaultDir, "gone", identity); err != nil {
		t.Fatalf("DeleteEntry() error = %v", err)
	}

	if err := os.Chmod(vaultDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(vaultDir, 0o700) })

	idx.RemoveEntry("gone", identity)

	if idx.LastPersistError() == nil {
		t.Fatal("LastPersistError() = nil, want a recorded persistence failure")
	}
}

// TestWriteIndexFileAtomicNoStrayTempFiles verifies that a successful
// writeIndexFile call leaves exactly the final index file behind and no
// leftover ".search-index.tmp-*" temp files, confirming the write-then-rename
// sequence completed and cleaned up as expected.
func TestWriteIndexFileAtomicNoStrayTempFiles(t *testing.T) {
	vaultDir := t.TempDir()

	if err := writeIndexFile(vaultDir, []byte("saltsaltsaltsalt"), []byte("some-ciphertext")); err != nil {
		t.Fatalf("writeIndexFile() error = %v", err)
	}

	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("stray temp file left behind: %s", e.Name())
		}
	}
	if len(names) != 1 || names[0] != filepath.Base(indexFilePath(vaultDir)) {
		t.Fatalf("vaultDir contents = %v, want exactly [%s]", names, filepath.Base(indexFilePath(vaultDir)))
	}
}

// TestWriteIndexFileMissingDirReturnsError verifies that writing to a
// nonexistent directory surfaces a clear error rather than silently
// succeeding or panicking.
func TestWriteIndexFileMissingDirReturnsError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if err := writeIndexFile(missing, []byte("saltsaltsaltsalt"), []byte("ct")); err == nil {
		t.Fatal("writeIndexFile() error = nil, want error for missing directory")
	}
}
