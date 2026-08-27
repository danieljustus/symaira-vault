package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
