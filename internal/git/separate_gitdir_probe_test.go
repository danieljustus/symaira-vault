package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/go-git/go-billy/v5/osfs"
)

func TestProbeSeparateGitDir(t *testing.T) {
	// Case 1: git.Init(storage, worktree) where worktree is dirA and storage is dirB
	t.Run("InitWithSeparateStorageAndWorktree", func(t *testing.T) {
		dirA := t.TempDir() // Worktree (e.g. iCloud Drive entries/)
		dirB := t.TempDir() // Git directory (e.g. ~/.local/share/symvault/.git)

		storageFs := osfs.New(dirB)
		worktreeFs := osfs.New(dirA)
		storage := filesystem.NewStorage(storageFs, cache.NewObjectLRUDefault())

		repo, err := gogit.Init(storage, worktreeFs)
		if err != nil {
			t.Fatalf("gogit.Init failed: %v", err)
		}

		// Verify what was created in dirA (.git pointer file)
		dotGitPath := filepath.Join(dirA, ".git")
		dotGitContent, err := os.ReadFile(dotGitPath)
		if err != nil {
			t.Fatalf("failed to read %s: %v", dotGitPath, err)
		}
		t.Logf("dirA/.git content: %q", string(dotGitContent))
		if !strings.HasPrefix(string(dotGitContent), "gitdir: ") {
			t.Errorf("expected .git file to start with 'gitdir: ', got %q", string(dotGitContent))
		}

		// Verify what was created in dirB (config with core.worktree)
		cfgPath := filepath.Join(dirB, "config")
		cfgContent, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("failed to read %s: %v", cfgPath, err)
		}
		t.Logf("dirB/config content:\n%s", string(cfgContent))
		if !strings.Contains(string(cfgContent), "worktree = ") {
			t.Errorf("expected config to contain 'worktree = ', got %s", string(cfgContent))
		}

		// Write a file in worktree dirA
		fileA := filepath.Join(dirA, "entry1.txt")
		if err := os.WriteFile(fileA, []byte("hello world"), 0o600); err != nil {
			t.Fatalf("failed to write file in dirA: %v", err)
		}

		w, err := repo.Worktree()
		if err != nil {
			t.Fatalf("repo.Worktree() failed: %v", err)
		}

		status, err := w.Status()
		if err != nil {
			t.Fatalf("w.Status() failed: %v", err)
		}
		t.Logf("Initial status: %v", status)
		if !status.IsUntracked("entry1.txt") {
			t.Errorf("expected entry1.txt to be untracked, got status: %v", status["entry1.txt"])
		}

		// Add and commit
		if _, err := w.Add("entry1.txt"); err != nil {
			t.Fatalf("w.Add failed: %v", err)
		}

		commitHash, err := w.Commit("Initial commit in separate worktree", &gogit.CommitOptions{
			Author: &object.Signature{
				Name:  "Test Author",
				Email: "test@example.com",
				When:  time.Now(),
			},
		})
		if err != nil {
			t.Fatalf("w.Commit failed: %v", err)
		}
		t.Logf("Committed hash: %s", commitHash.String())

		// Verify commit object exists in storage
		commitObj, err := repo.CommitObject(commitHash)
		if err != nil {
			t.Fatalf("repo.CommitObject failed: %v", err)
		}
		tree, err := commitObj.Tree()
		if err != nil {
			t.Fatalf("commitObj.Tree() failed: %v", err)
		}
		entryFile, err := tree.File("entry1.txt")
		if err != nil {
			t.Fatalf("tree.File('entry1.txt') failed: %v", err)
		}
		entryContent, err := entryFile.Contents()
		if err != nil {
			t.Fatalf("entryFile.Contents() failed: %v", err)
		}
		if entryContent != "hello world" {
			t.Errorf("expected 'hello world', got %q", entryContent)
		}
	})

	// Case 2: PlainOpen(dirA) where dirA has a .git pointer file
	t.Run("PlainOpenWorktreeWithDotGitPointerFile", func(t *testing.T) {
		dirA := t.TempDir()
		dirB := t.TempDir()

		storage := filesystem.NewStorage(osfs.New(dirB), cache.NewObjectLRUDefault())
		_, err := gogit.Init(storage, osfs.New(dirA))
		if err != nil {
			t.Fatalf("Init failed: %v", err)
		}

		// PlainOpen dirA directly
		repoA, err := gogit.PlainOpen(dirA)
		if err != nil {
			t.Fatalf("PlainOpen(dirA) failed: %v", err)
		}

		w, err := repoA.Worktree()
		if err != nil {
			t.Fatalf("repoA.Worktree() failed: %v", err)
		}

		if err := os.WriteFile(filepath.Join(dirA, "entry2.txt"), []byte("second entry"), 0o600); err != nil {
			t.Fatalf("write file failed: %v", err)
		}

		if _, err := w.Add("entry2.txt"); err != nil {
			t.Fatalf("Add failed: %v", err)
		}

		hash, err := w.Commit("Second commit", &gogit.CommitOptions{
			Author: &object.Signature{
				Name:  "Test",
				Email: "test@example.com",
				When:  time.Now(),
			},
		})
		if err != nil {
			t.Fatalf("Commit failed: %v", err)
		}
		t.Logf("PlainOpen commit hash: %s", hash.String())

		// Verify system git CLI also sees the repository when pointed at dirA
		cmd := exec.Command("git", "-C", dirA, "status", "--porcelain")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("system git failed in dirA: %v (%s)", err, string(out))
		}
		t.Logf("system git status in dirA (with .git pointer file): clean = %t", len(strings.TrimSpace(string(out))) == 0)
	})

	// Case 3: Pure separate gitdir without ANY .git file in worktree dirA
	t.Run("PureSeparateGitDirWithoutDotGitFileInWorktree", func(t *testing.T) {
		dirA := t.TempDir() // Worktree with NO .git file
		dirB := t.TempDir() // Git directory (e.g. created via git init --bare or low level storage)

		// 3a. Initialize bare storage in dirB
		storage := filesystem.NewStorage(osfs.New(dirB), cache.NewObjectLRUDefault())
		_, err := gogit.Init(storage, nil) // bare init in dirB
		if err != nil {
			t.Fatalf("bare Init failed: %v", err)
		}

		// Ensure NO .git file in dirA
		dotGitPath := filepath.Join(dirA, ".git")
		if _, err := os.Stat(dotGitPath); !os.IsNotExist(err) {
			t.Fatalf("expected no .git in dirA")
		}

		// 3b. Test gogit.PlainOpen(dirA) -> Should fail because no .git file/dir
		_, err = gogit.PlainOpen(dirA)
		t.Logf("gogit.PlainOpen(dirA without .git file) err: %v (expected ErrRepositoryNotExists)", err)
		if err != gogit.ErrRepositoryNotExists {
			t.Errorf("expected ErrRepositoryNotExists, got: %v", err)
		}

		// 3c. Test gogit.PlainOpen(dirB) -> Opens bare repo, Worktree() fails
		repoB, err := gogit.PlainOpen(dirB)
		if err != nil {
			t.Fatalf("PlainOpen(dirB) failed: %v", err)
		}
		_, err = repoB.Worktree()
		t.Logf("repoB.Worktree() err: %v (expected ErrIsBareRepository)", err)
		if err != gogit.ErrIsBareRepository {
			t.Errorf("expected ErrIsBareRepository, got: %v", err)
		}

		// 3d. Test gogit.Open(storage, osfs.New(dirA)) directly (NO .git file in dirA)
		repoSeparate, err := gogit.Open(storage, osfs.New(dirA))
		if err != nil {
			t.Fatalf("gogit.Open(storage, worktreeFs) failed: %v", err)
		}

		wSeparate, err := repoSeparate.Worktree()
		if err != nil {
			t.Fatalf("repoSeparate.Worktree() failed: %v", err)
		}

		// Write a file in dirA
		if err := os.WriteFile(filepath.Join(dirA, "entry3.txt"), []byte("pure separate"), 0o600); err != nil {
			t.Fatalf("write file failed: %v", err)
		}

		status, err := wSeparate.Status()
		if err != nil {
			t.Fatalf("wSeparate.Status() failed: %v", err)
		}
		t.Logf("wSeparate status: %v", status)
		if !status.IsUntracked("entry3.txt") {
			t.Errorf("expected entry3.txt untracked, got: %v", status["entry3.txt"])
		}

		if _, err := wSeparate.Add("entry3.txt"); err != nil {
			t.Fatalf("wSeparate.Add failed: %v", err)
		}

		commitHash, err := wSeparate.Commit("Commit via gogit.Open with no .git in worktree", &gogit.CommitOptions{
			Author: &object.Signature{
				Name:  "Test",
				Email: "test@example.com",
				When:  time.Now(),
			},
		})
		if err != nil {
			t.Fatalf("wSeparate.Commit failed: %v", err)
		}
		t.Logf("Committed hash via gogit.Open without .git file: %s", commitHash.String())

		// Verify again that NO .git file was created in dirA by status/add/commit
		if _, err := os.Stat(dotGitPath); !os.IsNotExist(err) {
			t.Errorf("expected no .git file created in dirA, but found one")
		}

		// 3e. Test system git CLI fallback for comparison
		cmd := exec.Command("git", "--git-dir="+dirB, "--work-tree="+dirA, "status", "--porcelain")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("system git --git-dir --work-tree failed: %v (%s)", err, string(out))
		}
		t.Logf("system git --git-dir --work-tree output: %q", strings.TrimSpace(string(out)))
	})

	// Case 4: PlainOpenWithOptions - check struct capabilities
	t.Run("PlainOpenWithOptionsCapabilities", func(t *testing.T) {
		t.Logf("PlainOpenOptions only has DetectDotGit and EnableDotGitCommonDir")
	})

	// Case 5: Absolute vs Relative gitdir pointer in .git file
	t.Run("AbsoluteAndRelativeDotGitPointer", func(t *testing.T) {
		dirA := t.TempDir()
		dirB := t.TempDir()

		// Init bare repo in dirB
		storage := filesystem.NewStorage(osfs.New(dirB), cache.NewObjectLRUDefault())
		_, err := gogit.Init(storage, nil)
		if err != nil {
			t.Fatalf("bare Init failed: %v", err)
		}

		// Write absolute path into dirA/.git
		dotGitPath := filepath.Join(dirA, ".git")
		if err := os.WriteFile(dotGitPath, []byte("gitdir: "+dirB+"\n"), 0o600); err != nil {
			t.Fatalf("write .git pointer failed: %v", err)
		}

		// PlainOpen dirA
		repo, err := gogit.PlainOpen(dirA)
		if err != nil {
			t.Fatalf("PlainOpen with absolute gitdir failed: %v", err)
		}
		w, err := repo.Worktree()
		if err != nil {
			t.Fatalf("repo.Worktree() failed: %v", err)
		}

		if err := os.WriteFile(filepath.Join(dirA, "abs_test.txt"), []byte("data"), 0o600); err != nil {
			t.Fatalf("write file failed: %v", err)
		}
		if _, err := w.Add("abs_test.txt"); err != nil {
			t.Fatalf("w.Add failed: %v", err)
		}
		h, err := w.Commit("commit with abs gitdir", &gogit.CommitOptions{
			Author: &object.Signature{
				Name:  "Test",
				Email: "test@example.com",
				When:  time.Now(),
			},
		})
		if err != nil {
			t.Fatalf("w.Commit failed: %v", err)
		}
		t.Logf("Absolute gitdir pointer commit hash: %s", h.String())
	})
}
