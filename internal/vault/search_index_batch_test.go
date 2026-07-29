package vault

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// TestSuspendResumeSingleBuild verifies that a batch of writes between
// Suspend and Resume triggers exactly one full index build instead of one
// rebuild per write, and that the rebuilt index returns correct results.
func TestSuspendResumeSingleBuild(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "keep", map[string]interface{}{"user": "keepvalue"})
	mustWriteEntry(t, vaultDir, identity, "gone", map[string]interface{}{"user": "gonevalue"})

	idx := searchIndexForVault(vaultDir)
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	buildsBefore := indexBuildCounter.Load()

	idx.Suspend()

	// Simulate a bulk import loop: adds, an in-place edit, and a delete.
	mustWriteEntry(t, vaultDir, identity, "new1", map[string]interface{}{"user": "alphavalue"})
	mustWriteEntry(t, vaultDir, identity, "new2", map[string]interface{}{"user": "bravovalue"})
	mustWriteEntry(t, vaultDir, identity, "keep", map[string]interface{}{"user": "keepedited"})
	for _, p := range []string{"new1", "new2", "keep"} {
		if err := idx.UpdateEntry(vaultDir, p, identity); err != nil {
			t.Fatalf("UpdateEntry(%s) error = %v", p, err)
		}
	}
	if err := DeleteEntry(vaultDir, "gone", identity); err != nil {
		t.Fatalf("DeleteEntry() error = %v", err)
	}
	idx.RemoveEntry("gone", identity)

	if err := idx.Resume(vaultDir, identity); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}

	if got := indexBuildCounter.Load() - buildsBefore; got != 1 {
		t.Fatalf("index builds during batch = %d, want exactly 1", got)
	}

	candidates, err := List(vaultDir, "", identity)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	assertMatch := func(needle string, want ...string) {
		t.Helper()
		m, err := idx.MatchEntries(vaultDir, identity, candidates, needle)
		if err != nil {
			t.Fatalf("MatchEntries(%q) error = %v", needle, err)
		}
		got := make([]string, 0, len(m))
		for p := range m {
			got = append(got, p)
		}
		sort.Strings(got)
		if want == nil {
			want = []string{}
		}
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("MatchEntries(%q) = %v, want %v", needle, got, want)
		}
	}
	assertMatch("alphavalue", "new1")
	assertMatch("bravovalue", "new2")
	assertMatch("keepedited", "keep")
	assertMatch("gonevalue")
	assertMatch("keepvalue")
}

// TestBatchVsIndividualWritesIdenticalResults verifies that search results
// after a suspended batch (Suspend + skipped writes + Resume) are identical
// to results after applying the same writes via the individual incremental
// update path.
func TestBatchVsIndividualWritesIdenticalResults(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	identity := testutil.TempIdentity(t)

	setup := func() string {
		dir := t.TempDir()
		mustWriteEntry(t, dir, identity, "a", map[string]interface{}{"user": "sharedtoken alpha-one"})
		mustWriteEntry(t, dir, identity, "b", map[string]interface{}{"user": "sharedtoken beta-two"})
		mustWriteEntry(t, dir, identity, "c", map[string]interface{}{"user": "charlie-three"})
		return dir
	}
	mutate := func(dir string) {
		mustWriteEntry(t, dir, identity, "a", map[string]interface{}{"user": "edited alpha-one"})
		mustWriteEntry(t, dir, identity, "d", map[string]interface{}{"user": "delta-four sharedtoken"})
		if err := DeleteEntry(dir, "b", identity); err != nil {
			t.Fatalf("DeleteEntry() error = %v", err)
		}
	}

	// Reference: individual incremental updates.
	dirA := setup()
	idxA := searchIndexForVault(dirA)
	if err := idxA.Build(dirA, identity); err != nil {
		t.Fatalf("Build(A) error = %v", err)
	}
	mutate(dirA)
	for _, p := range []string{"a", "d"} {
		if err := idxA.UpdateEntry(dirA, p, identity); err != nil {
			t.Fatalf("UpdateEntry(A, %s) error = %v", p, err)
		}
	}
	idxA.RemoveEntry("b", identity)

	// Batch: suspended writes + single Resume.
	dirB := setup()
	idxB := searchIndexForVault(dirB)
	if err := idxB.Build(dirB, identity); err != nil {
		t.Fatalf("Build(B) error = %v", err)
	}
	idxB.Suspend()
	mutate(dirB)
	for _, p := range []string{"a", "d"} {
		if err := idxB.UpdateEntry(dirB, p, identity); err != nil {
			t.Fatalf("UpdateEntry(B, %s) error = %v", p, err)
		}
	}
	idxB.RemoveEntry("b", identity)
	if err := idxB.Resume(dirB, identity); err != nil {
		t.Fatalf("Resume(B) error = %v", err)
	}

	candidates, err := List(dirA, "", identity)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	for _, needle := range []string{"sharedtoken", "alpha", "edited", "delta-four", "beta-two", "charlie-three", "token alpha"} {
		mA, err := idxA.MatchEntries(dirA, identity, candidates, needle)
		if err != nil {
			t.Fatalf("MatchEntries(A, %q) error = %v", needle, err)
		}
		mB, err := idxB.MatchEntries(dirB, identity, candidates, needle)
		if err != nil {
			t.Fatalf("MatchEntries(B, %q) error = %v", needle, err)
		}
		if !reflect.DeepEqual(mA, mB) {
			t.Errorf("needle %q: individual = %v, batch = %v — results differ", needle, mA, mB)
		}
	}
}

// TestResumeFailureInvalidatesIndex verifies that when the single rebuild at
// Resume fails (here: every entry became undecryptable mid-batch), the index
// is explicitly invalidated — in memory and on disk — rather than left
// silently stale.
func TestResumeFailureInvalidatesIndex(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "x", map[string]interface{}{"user": "xvalue"})
	mustWriteEntry(t, vaultDir, identity, "y", map[string]interface{}{"user": "yvalue"})

	idx := searchIndexForVault(vaultDir)
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	idx.Suspend()
	mustWriteEntry(t, vaultDir, identity, "z", map[string]interface{}{"user": "zvalue"})
	if err := idx.UpdateEntry(vaultDir, "z", identity); err != nil {
		t.Fatalf("UpdateEntry() error = %v", err)
	}

	// Mid-import failure: corrupt every entry file so the Resume rebuild
	// cannot decrypt anything (ErrIndexBuildEmpty).
	entriesDir := filepath.Join(vaultDir, "entries")
	err := filepath.Walk(entriesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		return os.WriteFile(path, []byte("not-an-age-file"), 0o600)
	})
	if err != nil {
		t.Fatalf("corrupting entries: %v", err)
	}
	listCacheFor(vaultDir).Invalidate()

	if err := idx.Resume(vaultDir, identity); err == nil {
		t.Fatal("Resume() error = nil, want rebuild failure")
	}
	if idx.IsBuilt() {
		t.Error("index still built after failed Resume; want explicit invalidation")
	}
	if _, statErr := os.Stat(indexFilePath(vaultDir)); !os.IsNotExist(statErr) {
		t.Error("on-disk index file still present after failed Resume; want it removed")
	}
}

// TestResumeWithoutSuspendNoop verifies Resume on a non-suspended index is a
// no-op and triggers no build.
func TestResumeWithoutSuspendNoop(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)

	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	mustWriteEntry(t, vaultDir, identity, "x", map[string]interface{}{"user": "xvalue"})

	idx := searchIndexForVault(vaultDir)
	if err := idx.Build(vaultDir, identity); err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	before := indexBuildCounter.Load()
	if err := idx.Resume(vaultDir, identity); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if got := indexBuildCounter.Load() - before; got != 0 {
		t.Fatalf("Resume without Suspend triggered %d builds, want 0", got)
	}

	// Suspend without any skipped writes must also not rebuild.
	idx.Suspend()
	if err := idx.Resume(vaultDir, identity); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if got := indexBuildCounter.Load() - before; got != 0 {
		t.Fatalf("Resume with clean Suspend triggered %d builds, want 0", got)
	}
}

// TestRemoveFromTokenIndexReverseMap verifies that removal via the reverse
// path→tokens map removes exactly the removed path's token references and
// keeps other paths' references intact — including for legacy documents
// where PathTokens is rebuilt lazily by ensurePathTokens.
func TestRemoveFromTokenIndexReverseMap(t *testing.T) {
	doc := indexDoc{
		Values: map[string][]string{
			"p1": {"alpha beta shared"},
			"p2": {"gamma shared"},
		},
		TokenIndex: map[string]map[string]struct{}{
			"alpha":  {"p1": {}},
			"beta":   {"p1": {}},
			"shared": {"p1": {}, "p2": {}},
			"gamma":  {"p2": {}},
		},
		// PathTokens deliberately nil: legacy document.
	}

	ensurePathTokens(&doc)
	if len(doc.PathTokens) != 2 {
		t.Fatalf("ensurePathTokens rebuilt %d paths, want 2", len(doc.PathTokens))
	}

	removeFromTokenIndex(doc.TokenIndex, doc.PathTokens, "p1")

	if _, ok := doc.TokenIndex["alpha"]; ok {
		t.Error("token 'alpha' survived removal of its only path")
	}
	if _, ok := doc.TokenIndex["beta"]; ok {
		t.Error("token 'beta' survived removal of its only path")
	}
	shared, ok := doc.TokenIndex["shared"]
	if !ok {
		t.Fatal("token 'shared' wrongly removed; still used by p2")
	}
	if _, ok := shared["p2"]; !ok {
		t.Error("token 'shared' lost reference to p2")
	}
	if _, ok := doc.TokenIndex["gamma"]["p2"]; !ok {
		t.Error("token 'gamma' lost reference to p2")
	}
	if _, ok := doc.PathTokens["p1"]; ok {
		t.Error("reverse map still contains removed path p1")
	}
}
