package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/testutil"
)

func TestEntryFileStem(t *testing.T) {
	tests := map[string]string{
		"login.example.age":                                "login.example",
		"login.example.conflict-20260826T101500.age":       "login.example",
		"login.example.conflict-20260826T101500.extra.age": "login.example",
		"login.example":                                    "login.example",
	}
	for input, want := range tests {
		if got := entryFileStem(input); got != want {
			t.Errorf("entryFileStem(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestVersionAfter(t *testing.T) {
	base := EntryMetadata{Version: 2, Updated: time.Unix(100, 0)}
	tests := []struct {
		name  string
		a     EntryMetadata
		aPath string
		b     EntryMetadata
		bPath string
		want  bool
	}{
		{name: "higher version", a: EntryMetadata{Version: 3}, aPath: "a", b: base, bPath: "b", want: true},
		{name: "lower version", a: EntryMetadata{Version: 1}, aPath: "a", b: base, bPath: "b", want: false},
		{name: "newer timestamp", a: EntryMetadata{Version: 2, Updated: time.Unix(200, 0)}, aPath: "a", b: base, bPath: "b", want: true},
		{name: "older timestamp", a: base, aPath: "a", b: EntryMetadata{Version: 2, Updated: time.Unix(200, 0)}, bPath: "b", want: false},
		{name: "lexicographically larger path", a: base, aPath: "b", b: base, bPath: "a", want: true},
		{name: "lexicographically smaller path", a: base, aPath: "a", b: base, bPath: "b", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionAfter(tt.a, tt.aPath, tt.b, tt.bPath); got != tt.want {
				t.Fatalf("versionAfter() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestPreserveConflictCopyErrorsAndCollision(t *testing.T) {
	dir := t.TempDir()
	if _, err := preserveConflictCopy(filepath.Join(dir, "missing.age")); !os.IsNotExist(err) {
		t.Fatalf("missing source error = %v, want not-exist", err)
	}

	directory := filepath.Join(dir, "directory.age")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create source directory: %v", err)
	}
	if _, err := preserveConflictCopy(directory); err == nil {
		t.Fatal("directory source should be rejected")
	}

	src := filepath.Join(dir, "login.age")
	want := []byte("encrypted loser")
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	first, err := preserveConflictCopy(src)
	if err != nil {
		t.Fatalf("first conflict copy: %v", err)
	}
	second, err := preserveConflictCopy(src)
	if err != nil {
		t.Fatalf("second conflict copy: %v", err)
	}
	if first == second {
		t.Fatal("collision should receive a suffixed conflict-copy name")
	}
	for _, path := range []string{first, second} {
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read conflict copy %q: %v", path, readErr)
		}
		if string(got) != string(want) {
			t.Fatalf("conflict copy %q = %q, want %q", path, got, want)
		}
	}
}

func TestPreserveConflictCopyUnreadableSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "login.age")
	if err := os.WriteFile(src, []byte("encrypted"), 0o000); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	defer os.Chmod(src, 0o600) // restore so t.TempDir cleanup can remove it

	if _, err := preserveConflictCopy(src); err == nil {
		t.Fatal("unreadable source should fail")
	}
}

func TestPreserveConflictCopyUnwritableTargetDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "login.age")
	if err := os.WriteFile(src, []byte("encrypted"), 0o600); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("make target dir read-only: %v", err)
	}
	defer os.Chmod(dir, 0o700) // restore so t.TempDir cleanup can remove it

	if _, err := preserveConflictCopy(src); err == nil {
		t.Fatal("unwritable target directory should fail")
	}
}

// writeConflictCopy duplicates an existing entry file under a sync-conflict
// name so the reconciler sees two files for one logical entry.
func writeConflictCopy(t *testing.T, vaultDir, stem, suffix string) string {
	t.Helper()
	src := filepath.Join(vaultDir, entriesDirName, stem+entryExtAge)
	data, err := os.ReadFile(src) // #nosec G304 -- test fixture path built by us
	if err != nil {
		t.Fatalf("read entry for conflict copy: %v", err)
	}
	dst := filepath.Join(vaultDir, entriesDirName, stem+".conflict-"+suffix+entryExtAge)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write conflict copy: %v", err)
	}
	return dst
}

func TestReconcileEntryConflictsPreservesLosers(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	// Group 1: one entry with two concurrent copies (three candidates total,
	// so the versionAfter comparison loop runs).
	mustWriteEntryCoverage(t, vaultDir, identity, "login.example", map[string]interface{}{"username": "alice"})
	conflictA := writeConflictCopy(t, vaultDir, "login.example", "20260826T101500")
	conflictB := writeConflictCopy(t, vaultDir, "login.example", "20260826T101501")

	// Group 2: undecryptable garbage — candidates that cannot be read must be
	// left untouched instead of dropped.
	garbageStem := "broken.entry"
	garbagePath := filepath.Join(vaultDir, entriesDirName, garbageStem+entryExtAge)
	for _, p := range []string{
		garbagePath,
		filepath.Join(vaultDir, entriesDirName, garbageStem+".conflict-20260826T101500"+entryExtAge),
	} {
		if err := os.WriteFile(p, []byte("not an age file"), 0o600); err != nil {
			t.Fatalf("write garbage entry: %v", err)
		}
	}

	// Group 3: a single-file entry — nothing to reconcile.
	mustWriteEntryCoverage(t, vaultDir, identity, "solo.entry", map[string]interface{}{"username": "bob"})

	if err := reconcileEntryConflicts(vaultDir, identity); err != nil {
		t.Fatalf("reconcileEntryConflicts() error = %v", err)
	}

	// Both original conflict copies must still exist (lossless), and the two
	// losing candidates must each have been preserved as an additional
	// conflict copy.
	for _, p := range []string{conflictA, conflictB, garbagePath} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("original file %s must be preserved: %v", p, err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(vaultDir, entriesDirName, "login.example.conflict-*"+entryExtAge))
	if err != nil {
		t.Fatalf("glob conflict copies: %v", err)
	}
	if len(matches) < 4 {
		t.Fatalf("got %d login.example conflict files, want >= 4 (2 originals + 2 preserved losers)", len(matches))
	}
}

func TestReconcileEntryConflictsNoEntries(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	if err := reconcileEntryConflicts(vaultDir, identity); err != nil {
		t.Fatalf("reconcileEntryConflicts() on empty vault = %v, want nil", err)
	}
}
