package vault

import (
	"testing"

	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// TestUpdateEntryPersistsEditToDisk verifies that an in-place edit applied via
// the incremental UpdateEntry path is written to the on-disk index, so a fresh
// process reloading the index sees the new value rather than the stale one. An
// in-place edit leaves the vault entry count unchanged, so the on-disk
// staleness check (entry count) would otherwise happily accept a stale index.
func TestUpdateEntryPersistsEditToDisk(t *testing.T) {
	globalIndex.Invalidate()
	t.Cleanup(globalIndex.Invalidate)

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
	globalIndex.Invalidate()
	t.Cleanup(globalIndex.Invalidate)

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
