package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	gogit "github.com/go-git/go-git/v5"

	"github.com/danieljustus/symaira-vault/internal/git"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// TestAutoCommitEntryCommitsManifestWithEntry verifies that an entry write +
// auto-commit captures both the entry and manifest.age in the same commit, so
// committed history is internally consistent and the manifest never drifts
// (issue #799 — previously manifest.age stayed permanently dirty, causing
// false tamper alarms in doctor).
func TestAutoCommitEntryCommitsManifestWithEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: manifest uses cgo age crypto")
	}
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	if _, err := InitWithPassphrase(vaultDir, []byte("test-passphrase"), testConfig(vaultDir)); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := git.Init(vaultDir); err != nil {
		t.Fatalf("git init: %v", err)
	}
	v := &Vault{Dir: vaultDir, Identity: id, Config: testConfig(vaultDir)}

	// Entry write + auto-commit (the real write path used by CRUD commands).
	if err := WriteEntry(vaultDir, "alpha", &Entry{Data: map[string]any{"user": "alice"}}, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if err := v.AutoCommitEntry("Update alpha", "alpha"); err != nil {
		t.Fatalf("AutoCommitEntry: %v", err)
	}

	repo, err := gogit.PlainOpen(vaultDir)
	if err != nil {
		t.Fatalf("open repo: %v", err)
	}
	ref, err := repo.Head()
	if err != nil {
		t.Fatalf("repo.Head(): %v", err)
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		t.Fatalf("CommitObject(): %v", err)
	}

	// Both the entry and the manifest must be part of the SAME commit.
	if _, err := commit.File("entries/alpha.age"); err != nil {
		t.Fatalf("commit missing entries/alpha.age: %v", err)
	}
	manifestFile, err := commit.File(manifestFileName)
	if err != nil {
		t.Fatalf("commit missing manifest.age: %v", err)
	}

	// The committed manifest must match what is on disk (no drift).
	committedManifest, err := manifestFile.Contents()
	if err != nil {
		t.Fatalf("read committed manifest: %v", err)
	}
	diskManifest, err := os.ReadFile(filepath.Join(vaultDir, manifestFileName))
	if err != nil {
		t.Fatalf("read manifest on disk: %v", err)
	}
	if committedManifest != string(diskManifest) {
		t.Error("committed manifest.age differs from manifest.age on disk")
	}

	// No leftover dirty state after the auto-commit.
	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	status, err := w.Status()
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	// Note: status.File() would insert a fake Untracked entry for clean files,
	// so check the map directly.
	if fs, ok := status[manifestFileName]; ok && (fs.Worktree != gogit.Unmodified || fs.Staging != gogit.Unmodified) {
		t.Errorf("manifest.age dirty after auto-commit: %+v", fs)
	}
	if fs, ok := status["entries/alpha.age"]; ok && fs.Worktree != gogit.Unmodified {
		t.Errorf("entries/alpha.age dirty after auto-commit: %+v", fs)
	}

	// A doctor-style integrity check must not flag the written entry as tampered.
	result, err := VerifyManifestIntegrity(vaultDir, id)
	if err != nil {
		t.Fatalf("VerifyManifestIntegrity: %v", err)
	}
	if len(result.Tampered) > 0 {
		t.Errorf("manifest flagged tampered entries after a normal write: %v", result.Tampered)
	}
	if len(result.Missing) > 0 {
		t.Errorf("manifest reports missing entries after a normal write: %v", result.Missing)
	}
}
