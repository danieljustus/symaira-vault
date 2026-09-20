package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/testutil"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// TestMigratePseudonymizeKeepsEveryEntry is the regression test for the data
// loss reported in #1088: runPseudonymizeMigration rewrote each entry while the
// config flag was still false, so every write landed back on the entry's own
// plaintext path and the following os.Remove deleted it. The command then
// reported "Migration complete" and exited 0 with an empty vault.
//
// The contract asserted here is the one the command documents: N entries in,
// N entries readable afterwards, none of them left under a plaintext name.
func TestMigratePseudonymizeKeepsEveryEntry(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	logicalPaths := []string{
		"example.one",
		"work/nested/two",
		"deep/a/b/c/three",
	}
	for _, path := range logicalPaths {
		entry := &vaultpkg.Entry{
			Path: path,
			Data: map[string]any{"username": "user-" + path},
		}
		if err := vaultpkg.WriteEntry(vaultDir, path, entry, identity); err != nil {
			t.Fatalf("write entry %s: %v", path, err)
		}
	}

	before := countAgeFiles(t, filepath.Join(vaultDir, "entries"))
	if before != len(logicalPaths) {
		t.Fatalf("fixture wrote %d entry files, want %d", before, len(logicalPaths))
	}

	v := &vaultpkg.Vault{Dir: vaultDir, Identity: identity}
	if err := runPseudonymizeMigration(v); err != nil {
		t.Fatalf("runPseudonymizeMigration: %v", err)
	}

	// Every entry must still be readable under its logical path.
	got, err := vaultpkg.List(vaultDir, "", identity)
	if err != nil {
		t.Fatalf("list after migration: %v", err)
	}
	if len(got) != len(logicalPaths) {
		t.Fatalf("list after migration = %v, want all %d entries", got, len(logicalPaths))
	}
	for _, path := range logicalPaths {
		entry, err := vaultpkg.ReadEntry(vaultDir, path, identity)
		if err != nil {
			t.Fatalf("read entry %s after migration: %v", path, err)
		}
		if entry.Path != path {
			t.Errorf("entry %s: embedded Path = %q, want %q", path, entry.Path, path)
		}
	}

	// No plaintext-named entry file may remain: everything moved under the
	// HMAC-derived layout.
	for _, path := range logicalPaths {
		plain := filepath.Join(vaultDir, "entries", filepath.FromSlash(path)+".age")
		if _, err := os.Stat(plain); !os.IsNotExist(err) {
			t.Errorf("plaintext-named entry file still present: %s", plain)
		}
	}
	if after := countAgeFiles(t, filepath.Join(vaultDir, "entries")); after != len(logicalPaths) {
		t.Fatalf("entry files after migration = %d, want %d", after, len(logicalPaths))
	}

	// The config flag must be set by the command.
	loaded, err := config.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("load config after migration: %v", err)
	}
	if loaded.Vault == nil || !loaded.Vault.PseudonymizePaths {
		t.Fatal("config after migration does not enable pseudonymize_paths")
	}
}

// TestMigratePseudonymizeSecondRunIsNoOp asserts that re-running the migration
// changes nothing. Once every entry lives under its HMAC path, a second walk
// still sees those files but must not hash their derived names again — that
// would orphan the entry under a name nothing else resolves to.
func TestMigratePseudonymizeSecondRunIsNoOp(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	if err := vaultpkg.WriteEntry(vaultDir, "only.entry", &vaultpkg.Entry{
		Path: "only.entry",
		Data: map[string]any{"username": "alice"},
	}, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	v := &vaultpkg.Vault{Dir: vaultDir, Identity: identity}
	if err := runPseudonymizeMigration(v); err != nil {
		t.Fatalf("first migration: %v", err)
	}
	firstFiles := countAgeFiles(t, filepath.Join(vaultDir, "entries"))

	if err := runPseudonymizeMigration(v); err != nil {
		t.Fatalf("second migration: %v", err)
	}
	if secondFiles := countAgeFiles(t, filepath.Join(vaultDir, "entries")); secondFiles != firstFiles {
		t.Fatalf("second run changed entry file count: %d -> %d", firstFiles, secondFiles)
	}

	got, err := vaultpkg.List(vaultDir, "", identity)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0] != "only.entry" {
		t.Fatalf("list after second run = %v, want [only.entry]", got)
	}
}

// TestReadEntryFindsPlaintextNamedFileWhilePseudonymizeEnabled covers the
// damaged-vault state #1088 could leave behind: pseudonymize_paths is already
// true in config.yaml while entries still sit under their plaintext names. The
// derives-name-first read path missed them, so the entries looked lost even
// after the files were restored from git.
func TestReadEntryFindsPlaintextNamedFileWhilePseudonymizeEnabled(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := vaultpkg.Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("init vault: %v", err)
	}

	// Write while the flag is off, so the entry lands at its plaintext name.
	if err := vaultpkg.WriteEntry(vaultDir, "example.one", &vaultpkg.Entry{
		Path: "example.one",
		Data: map[string]any{"username": "alice"},
	}, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	// Now flip the flag without migrating — the state a buggy run leaves.
	loaded, err := config.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Vault == nil {
		loaded.Vault = &config.VaultConfig{}
	}
	loaded.Vault.PseudonymizePaths = true
	if err := loaded.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config: %v", err)
	}

	entry, err := vaultpkg.ReadEntry(vaultDir, "example.one", identity)
	if err != nil {
		t.Fatalf("read entry with pseudonymize_paths enabled: %v", err)
	}
	if entry.Data["username"] != "alice" {
		t.Fatalf("entry data = %#v, want username alice", entry.Data)
	}

	// A regenerated run must still be able to finish the interrupted migration.
	v := &vaultpkg.Vault{Dir: vaultDir, Identity: identity}
	if err := runPseudonymizeMigration(v); err != nil {
		t.Fatalf("resume migration: %v", err)
	}
	if _, err := vaultpkg.ReadEntry(vaultDir, "example.one", identity); err != nil {
		t.Fatalf("read entry after resumed migration: %v", err)
	}
}

func countAgeFiles(t *testing.T, root string) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".age") {
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return count
}
