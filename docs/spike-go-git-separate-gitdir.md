# Spike: go-git Support for a Separate Git Directory

**Date:** 2026-08-25  
**Issue:** #863  
**Context:** Decision D3 in [ADR 0006](adr/0006-mobile-client-sync-and-agent-reach.md) (vault `entries/` in iCloud Drive while `.git` directory stays outside the synced folder)  
**Author:** Symaira Vault Team / Spike Probe  

---

## 1. Executive Summary

**Question:** Can `go-git` open and operate on a repository whose working tree and `.git` storage directory live at **different filesystem paths**?

**Answer: YES, fully supported natively.**

1. **Native go-git storage abstraction (`gogit.Open`):** `gogit.Open(filesystem.NewStorage(osfs.New(gitDir), cache.NewObjectLRUDefault()), osfs.New(worktreeDir))` operates completely natively with **zero** `.git` files or directories inside the worktree folder (`worktreeDir`). All worktree operations (`repo.Worktree()`, `w.Status()`, `w.Add()`, `w.Commit()`, `repo.Log()`) operate correctly on `worktreeDir` while writing Git objects, refs, and index to `gitDir`.
2. **Git pointer file (`.git` file with `gitdir: <path>`):** If a standard `.git` text pointer file is placed in `worktreeDir`, `gogit.PlainOpen(worktreeDir)` automatically resolves the target storage path and functions transparently.
3. **High-level `PlainOpen` limitations:** `gogit.PlainOpen(gitDir)` on a bare/separated git directory does *not* read `core.worktree` from `.git/config` to discover the worktree (it returns `ErrIsBareRepository` on `repo.Worktree()`). `PlainOpen(worktreeDir)` requires either a `.git` directory or a `.git` pointer file.
4. **Conclusion for D3:** Symaira Vault does **not** need to shell out to `os/exec` for everyday Git operations (status, stage, commit, diff, log) in a separate-git-dir layout. go-git supports it natively in Go via `gogit.Open(storage, worktree)`.

---

## 2. Methodology & Evidence Gathering

### 2.1 Audit of Existing Codebase (`internal/git`)

An audit of `internal/git/` was conducted to identify how go-git and `os/exec` are currently used:
- `internal/git/git_util.go`: Uses `gogit.PlainOpen(vaultDir)` in `openRepo(vaultDir)`. Uses `os/exec` in `gitConfigUser(vaultDir, key)` (`git -C <vaultDir> config --get <key>`).
- `internal/git/git_push.go`: Uses `gogit.Push` for Go-native push, with an `os/exec` fallback for SSH remotes (`pushWithSystemGit` running `git -C <vaultDir> push origin HEAD`) to respect SSH agent, known_hosts, and `~/.ssh/config`.
- `internal/git/git.go`: Uses `gogit.PlainInit(vaultDir, false)` in `Init(vaultDir)` and `repo.Worktree()` for `AutoCommitWithOptions`.

### 2.2 go-git Source Inspection

- **go-git version in `go.mod`:** `github.com/go-git/go-git/v5 v5.19.2`
- **go-billy version:** `github.com/go-git/go-billy/v5 v5.9.0`
- Module cache inspected: `/Users/daniel/go/pkg/mod/github.com/go-git/go-git/v5@v5.19.2`

Key findings from source inspection:

#### Finding 1: `gogit.Open` decouples storage from worktree filesystem
In `repository.go:205-222`:
```go
// Open opens a git repository using the given Storer and worktree filesystem,
// if the given storer is complete empty ErrRepositoryNotExists is returned.
// The worktree can be nil when the repository being opened is bare, if the
// repository is a normal one (not bare) and worktree is nil the err
// ErrWorktreeNotProvided is returned
func Open(s storage.Storer, worktree billy.Filesystem) (*Repository, error) {
	_, err := s.Reference(plumbing.HEAD)
	if err == plumbing.ErrReferenceNotFound {
		return nil, ErrRepositoryNotExists
	}

	cfg, err := s.Config()
	if err != nil {
		return nil, err
	}

	err = verifyExtensions(s, cfg)
	if err != nil {
		return nil, err
	}

	return newRepository(s, worktree), nil
}
```
`gogit.Open` binds any `storage.Storer` (e.g. `filesystem.NewStorage(osfs.New(gitDir), ...)`) to any `billy.Filesystem` (e.g. `osfs.New(worktreeDir)`). It makes no assumptions about where the files live on disk and does not require a `.git` entry in the worktree directory.

#### Finding 2: `gogit.Init` creates `.git` pointer file and sets `core.worktree`
In `repository.go:159-198`:
```go
func createDotGitFile(worktree, storage billy.Filesystem) error {
	path, err := filepath.Rel(worktree.Root(), storage.Root())
	if err != nil {
		path = storage.Root()
	}

	if path == GitDirName {
		// not needed, since the folder is the default place
		return nil
	}

	f, err := worktree.Create(GitDirName)
	if err != nil {
		return err
	}

	defer f.Close()
	_, err = fmt.Fprintf(f, "gitdir: %s\n", path)
	return err
}

func setConfigWorktree(r *Repository, worktree, storage billy.Filesystem) error {
	path, err := filepath.Rel(storage.Root(), worktree.Root())
	if err != nil {
		path = worktree.Root()
	}

	if path == ".." {
		// not needed, since the folder is the default place
		return nil
	}

	cfg, err := r.Config()
	if err != nil {
		return err
	}

	cfg.Core.Worktree = path
	return r.Storer.SetConfig(cfg)
}
```
When `gogit.Init(storage, worktreeFs)` is called with distinct filesystems, go-git:
1. Writes a standard `gitdir: <storage-path>` pointer file into the worktree.
2. Writes `core.worktree = <worktree-path>` into the repository configuration.

#### Finding 3: `PlainOpen` parses `.git` pointer files
In `repository.go:401-426`:
```go
func dotGitFileToOSFilesystem(path string, fs billy.Filesystem) (bfs billy.Filesystem, err error) {
	f, err := fs.Open(GitDirName)
	if err != nil {
		return nil, err
	}
	defer ioutil.CheckClose(f, &err)

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	line := string(b)
	const prefix = "gitdir: "
	if !strings.HasPrefix(line, prefix) {
		return nil, fmt.Errorf(".git file has no %s prefix", prefix)
	}

	gitdir := strings.Split(line[len(prefix):], "\n")[0]
	gitdir = strings.TrimSpace(gitdir)
	if filepath.IsAbs(gitdir) {
		return osfs.New(gitdir), nil
	}

	return osfs.New(fs.Join(path, gitdir)), nil
}
```
`PlainOpen` supports both relative and absolute paths in `.git` pointer files.

#### Finding 4: `PlainOpenOptions` capability check
In `options.go:809-818`:
```go
type PlainOpenOptions struct {
	// DetectDotGit defines whether parent directories should be
	// walked until a .git directory or file is found.
	DetectDotGit bool
	// Enable .git/commondir support
	EnableDotGitCommonDir bool
}
```
`PlainOpenOptions` does not accept a custom worktree path or gitdir path override. For arbitrary separate paths without a `.git` pointer file, `gogit.Open(storage, worktree)` must be used.

---

## 3. Executed Code Probe (`internal/git/separate_gitdir_probe_test.go`)

A test probe was implemented and executed against Go `1.26.6` and `go-git v5.19.2`.

### Probe Test Suite Results

```text
=== RUN   TestProbeSeparateGitDir
=== RUN   TestProbeSeparateGitDir/InitWithSeparateStorageAndWorktree
    separate_gitdir_probe_test.go:39: dirA/.git content: "gitdir: ../002\n"
    separate_gitdir_probe_test.go:50: dirB/config content:
        [core]
        	bare = false
        	worktree = ../001
    separate_gitdir_probe_test.go:70: Initial status: ?? entry1.txt
    separate_gitdir_probe_test.go:90: Committed hash: acceeb5e01a7be07255ef0d616972a09aab0e945
=== RUN   TestProbeSeparateGitDir/PlainOpenWorktreeWithDotGitPointerFile
    separate_gitdir_probe_test.go:154: PlainOpen commit hash: 9678efee259cc17dfbd4a15aa15d623169a8b20b
    separate_gitdir_probe_test.go:162: system git status in dirA (with .git pointer file): clean = true
=== RUN   TestProbeSeparateGitDir/PureSeparateGitDirWithoutDotGitFileInWorktree
    separate_gitdir_probe_test.go:185: gogit.PlainOpen(dirA without .git file) err: repository does not exist (expected ErrRepositoryNotExists)
    separate_gitdir_probe_test.go:196: repoB.Worktree() err: worktree not available in a bare repository (expected ErrIsBareRepository)
    separate_gitdir_probe_test.go:221: wSeparate status: ?? entry3.txt
    separate_gitdir_probe_test.go:240: Committed hash via gogit.Open without .git file: aafa522fb9506881df6fe32345157200eddc4da5
    separate_gitdir_probe_test.go:253: system git --git-dir --work-tree output: ""
=== RUN   TestProbeSeparateGitDir/PlainOpenWithOptionsCapabilities
    separate_gitdir_probe_test.go:258: PlainOpenOptions only has DetectDotGit and EnableDotGitCommonDir
=== RUN   TestProbeSeparateGitDir/AbsoluteAndRelativeDotGitPointer
    separate_gitdir_probe_test.go:305: Absolute gitdir pointer commit hash: 60ead44ba4032fb293c2f48645388c4ec979c380
--- PASS: TestProbeSeparateGitDir (0.04s)
```

---

## 4. Analysis Matrix

| Approach | Working Tree (e.g. iCloud `entries/`) | Git Directory (e.g. `~/.local/share/symvault/.git`) | go-git API | System `git` CLI Compatibility | Assessment |
|---|---|---|---|---|---|
| **A. Pure Separate (No `.git` in worktree)** | Only files/folders (no `.git` file or dir) | Standalone git directory | `gogit.Open(storage, osfs.New(wtDir))` | `git --git-dir=... --work-tree=...` | **Optimal for D3.** Zero git metadata in iCloud folder. No risk of cloud sync corruption or unwanted file churn in iCloud. |
| **B. Pointer File (`.git` file)** | Contains `gitdir: <path>` text file (~20 bytes) | Standalone git directory | `gogit.PlainOpen(wtDir)` | `git -C <wtDir>` | **Viable.** Uses standard `PlainOpen`, but introduces a small text file into the iCloud synced directory. |
| **C. `PlainOpen` on Git Directory** | Any path | Bare git directory | `gogit.PlainOpen(gitDir)` | `git -C <gitDir>` | **Unsupported.** `repo.Worktree()` fails with `ErrIsBareRepository` because `PlainOpen` ignores `core.worktree`. |

---

## 5. Implications for Decision D3 (ADR 0006) Layout

In [ADR 0006](adr/0006-mobile-client-sync-and-agent-reach.md), Decision D3 states:
> *".git must not live inside the iCloud folder. A git repository inside iCloud Drive is a known failure mode. The working tree can be in iCloud while the git directory is not, via a separate-git-dir layout; whether go-git supports that cleanly is an open question."*

Based on the spike evidence:

1. **iCloud Cleanliness:** Approach A (Pure Separate) allows the iCloud Drive folder to contain **strictly vault data** (e.g. encrypted `.age` entries and `manifest.json`), with **no `.git` file or directory whatsoever** inside iCloud Drive.
2. **Native Performance & Safety:** On macOS, the Go binary can perform all operations (`Init`, `Status`, `Add`, `Commit`, `Log`) in-process using go-git without spawning child processes.
3. **System Git Compatibility:** When `pushWithSystemGit` or user-configured hooks run, passing `--git-dir=<gitDir> --work-tree=<worktreeDir>` works identically to standard Git repositories.
4. **Mobile (iOS) Safety:** The iOS app (which extracts `internal/crypto` and a headless core without go-git per D2) only interacts with the raw `.age` files and `manifest.json` in the iCloud container, remaining completely unaware of Git.

---

## 6. Recommended Implementation for D3

When implementing the D3 layout in Symaira Vault:

1. **Vault Git Initialisation:**
   ```go
   storage := filesystem.NewStorage(osfs.New(gitDirPath), cache.NewObjectLRUDefault())
   repo, err := gogit.Init(storage, nil) // bare init in separate git directory
   ```
2. **Repository Opening:**
   Enhance `internal/git/git_util.go` to support opening with an explicit git directory:
   ```go
   func OpenRepoWithGitDir(worktreeDir, gitDirPath string) (*gogit.Repository, error) {
       if gitDirPath == "" {
           return gogit.PlainOpen(worktreeDir)
       }
       storage := filesystem.NewStorage(osfs.New(gitDirPath), cache.NewObjectLRUDefault())
       return gogit.Open(storage, osfs.New(worktreeDir))
   }
   ```
3. **System Git Invocations:**
   Update `pushWithSystemGit` and `gitConfigUser` to pass `--git-dir` and `--work-tree` when a separate git directory path is configured:
   ```go
   cmd := exec.CommandContext(ctx, "git", "--git-dir="+gitDir, "--work-tree="+vaultDir, "push", "origin", "HEAD")
   ```

---

## 7. Permanent Regression Test

The probe test has been committed as a permanent regression test at [internal/git/separate_gitdir_probe_test.go](file:///Users/daniel/Dev/Symaira%20Dev/symaira-vault/.worktrees/spike-git-dir/internal/git/separate_gitdir_probe_test.go) to guarantee that future updates to `go-git` preserve separate-git-dir compatibility.
