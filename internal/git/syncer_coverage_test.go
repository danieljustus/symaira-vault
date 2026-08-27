package git

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSyncerDelegatesCreateGitignore(t *testing.T) {
	dir := t.TempDir()
	if err := (NewSyncer()).CreateGitignore(dir); err != nil {
		t.Fatalf("Syncer.CreateGitignore() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err != nil {
		t.Fatalf("Syncer.CreateGitignore() did not create .gitignore: %v", err)
	}
}

func TestSyncerDelegatesEnsureGitOutside(t *testing.T) {
	dir := t.TempDir()
	externalRoot := t.TempDir()
	t.Setenv("XDG_DATA_HOME", externalRoot)

	inTreeGit := filepath.Join(dir, ".git")
	if err := os.Mkdir(inTreeGit, 0o700); err != nil {
		t.Fatalf("create in-tree git directory: %v", err)
	}
	marker := filepath.Join(inTreeGit, "config")
	if err := os.WriteFile(marker, []byte("[core]\n"), 0o600); err != nil {
		t.Fatalf("seed in-tree git directory: %v", err)
	}

	if err := (NewSyncer()).EnsureGitOutside(dir); err != nil {
		t.Fatalf("Syncer.EnsureGitOutside() error = %v", err)
	}
	if _, err := os.Stat(inTreeGit); !os.IsNotExist(err) {
		t.Fatalf("in-tree .git should be relocated, stat error = %v", err)
	}

	external := ExternalGitDirPath(dir)
	if _, err := os.Stat(filepath.Join(external, "config")); err != nil {
		t.Fatalf("relocated git directory missing config: %v", err)
	}
	if !IsGitExternal(dir) {
		t.Fatal("IsGitExternal() = false after relocation")
	}
}

func TestEnsureGitOutsideEmptyVaultDirIsNoop(t *testing.T) {
	if err := (NewSyncer()).EnsureGitOutside(""); err != nil {
		t.Fatalf("EnsureGitOutside(\"\") error = %v", err)
	}
}

func TestEnsureGitOutsideLeavesGitFileUntouched(t *testing.T) {
	dir := t.TempDir()
	gitFile := filepath.Join(dir, ".git")
	if err := os.WriteFile(gitFile, []byte("gitdir: /some/external/path\n"), 0o600); err != nil {
		t.Fatalf("seed .git pointer file: %v", err)
	}

	if err := (NewSyncer()).EnsureGitOutside(dir); err != nil {
		t.Fatalf("EnsureGitOutside() error = %v", err)
	}
	if _, err := os.Stat(gitFile); err != nil {
		t.Fatalf(".git pointer file should be left untouched: %v", err)
	}
}

func TestEnsureGitOutsideRemovesInTreeWhenExternalExists(t *testing.T) {
	dir := t.TempDir()
	externalRoot := t.TempDir()
	t.Setenv("XDG_DATA_HOME", externalRoot)

	inTreeGit := filepath.Join(dir, ".git")
	if err := os.MkdirAll(inTreeGit, 0o700); err != nil {
		t.Fatalf("create in-tree git directory: %v", err)
	}
	external := ExternalGitDirPath(dir)
	if err := os.MkdirAll(external, 0o700); err != nil {
		t.Fatalf("create external git directory: %v", err)
	}

	if err := (NewSyncer()).EnsureGitOutside(dir); err != nil {
		t.Fatalf("EnsureGitOutside() error = %v", err)
	}
	if _, err := os.Stat(inTreeGit); !os.IsNotExist(err) {
		t.Fatalf("in-tree .git should be removed when external exists, stat error = %v", err)
	}
	if !dirExists(external) {
		t.Fatal("external git directory should be preserved")
	}
}

func TestEnsureGitOutsideParentCreationFailure(t *testing.T) {
	dir := t.TempDir()
	// XDG_DATA_HOME points at a regular file, so the external parent
	// cannot be created and EnsureGitOutside must surface the error.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	t.Setenv("XDG_DATA_HOME", blocker)

	inTreeGit := filepath.Join(dir, ".git")
	if err := os.MkdirAll(inTreeGit, 0o700); err != nil {
		t.Fatalf("create in-tree git directory: %v", err)
	}

	if err := (NewSyncer()).EnsureGitOutside(dir); err == nil {
		t.Fatal("EnsureGitOutside() should fail when the external parent cannot be created")
	}
}
