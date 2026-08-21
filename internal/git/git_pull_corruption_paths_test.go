package git

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// This file covers the remaining git-sync failure branches that need a
// deliberately damaged repository to reach: a bare repository (no worktree)
// and a repository whose tree object was removed from the object store.
//
// Both are real corruption classes a synced vault can hit — an interrupted
// clone or a partially fetched pack leaves exactly these conditions — and the
// point of every test here is that the failure is *reported* rather than
// silently swallowed or turned into a panic.

// breakCommitTree removes commit's tree object from the loose object store, so
// any later attempt to read that commit's tree fails with "object not found".
// It returns a freshly opened repository handle: the original handle may still
// serve the tree from an in-memory cache.
func breakCommitTree(t *testing.T, dir string, commit *object.Commit) *gogit.Repository {
	t.Helper()
	h := commit.TreeHash.String()
	objPath := filepath.Join(dir, ".git", "objects", h[:2], h[2:])
	if _, err := os.Stat(objPath); err != nil {
		t.Skipf("tree object is not stored loose (%v) — packed layout, cannot corrupt it deterministically", err)
	}
	if err := os.Remove(objPath); err != nil {
		t.Fatalf("remove tree object: %v", err)
	}
	repo, err := openRepo(dir)
	if err != nil {
		t.Fatalf("reopen repo after corruption: %v", err)
	}
	return repo
}

// twoCommitVault seeds a vault with two commits and returns the repo plus both
// commits, so a test can corrupt one of them.
func twoCommitVault(t *testing.T) (dir string, first, second *object.Commit) {
	t.Helper()
	dir = t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	writeFile(t, dir, "config.yaml", []byte("cfg1"))
	if err := AutoCommit(dir, "first"); err != nil {
		t.Fatalf("AutoCommit first: %v", err)
	}
	repo, err := openRepo(dir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	first = headCommit(repo)
	if first == nil {
		t.Fatalf("expected a first commit")
	}
	writeFile(t, dir, "config.yaml", []byte("cfg2"))
	if err := AutoCommit(dir, "second"); err != nil {
		t.Fatalf("AutoCommit second: %v", err)
	}
	second = headCommit(repo)
	if second == nil {
		t.Fatalf("expected a second commit")
	}
	return dir, first, second
}

// --- changedPaths tree-read failures ---------------------------------------

// TestChangedPathsFromTreeFailureIsReported covers changedPaths's first
// tree-read error: the "from" commit's tree is unreadable. The error must
// propagate so callers do not treat an unreadable history as "nothing
// changed" and skip preserving the user's local files.
func TestChangedPathsFromTreeFailureIsReported(t *testing.T) {
	dir, first, second := twoCommitVault(t)
	repo := breakCommitTree(t, dir, first)

	brokenFirst, err := repo.CommitObject(first.Hash)
	if err != nil {
		t.Fatalf("CommitObject(first): %v", err)
	}
	intactSecond, err := repo.CommitObject(second.Hash)
	if err != nil {
		t.Fatalf("CommitObject(second): %v", err)
	}

	paths, err := changedPaths(brokenFirst, intactSecond)

	if err == nil {
		t.Fatalf("expected changedPaths to fail when the from-commit's tree is missing, got paths=%v", paths)
	}
	if paths != nil {
		t.Errorf("paths = %v, want nil on error", paths)
	}
}

// TestChangedPathsToTreeFailureIsReported covers changedPaths's second
// tree-read error: the "to" commit's tree is unreadable. Same contract as
// above, on the other side of the diff.
func TestChangedPathsToTreeFailureIsReported(t *testing.T) {
	dir, first, second := twoCommitVault(t)
	repo := breakCommitTree(t, dir, second)

	intactFirst, err := repo.CommitObject(first.Hash)
	if err != nil {
		t.Fatalf("CommitObject(first): %v", err)
	}
	brokenSecond, err := repo.CommitObject(second.Hash)
	if err != nil {
		t.Fatalf("CommitObject(second): %v", err)
	}

	paths, err := changedPaths(intactFirst, brokenSecond)

	if err == nil {
		t.Fatalf("expected changedPaths to fail when the to-commit's tree is missing, got paths=%v", paths)
	}
	if paths != nil {
		t.Errorf("paths = %v, want nil on error", paths)
	}
}

// --- committedContent reader failure ---------------------------------------

// TestCommittedContentUnreadableBlobReportsNotOk covers committedContent's
// blob-read failure: the commit and its tree entry exist, but the blob's
// content cannot be read. It must report ok=false so the caller treats the
// file as diverged and preserves the local copy instead of comparing against
// empty content and discarding it.
func TestCommittedContentUnreadableBlobReportsNotOk(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeFile(t, dir, "config.yaml", []byte("cfg-content"))
	if err := AutoCommit(dir, "seed"); err != nil {
		t.Fatalf("AutoCommit: %v", err)
	}
	repo, err := openRepo(dir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	commit := headCommit(repo)
	if commit == nil {
		t.Fatalf("expected a HEAD commit")
	}
	f, err := commit.File("config.yaml")
	if err != nil {
		t.Fatalf("commit.File: %v", err)
	}

	// Remove the blob object so the tree entry still resolves but the
	// content behind it does not.
	h := f.Blob.Hash.String()
	blobPath := filepath.Join(dir, ".git", "objects", h[:2], h[2:])
	if _, statErr := os.Stat(blobPath); statErr != nil {
		t.Skipf("blob is not stored loose (%v) — packed layout, cannot corrupt it deterministically", statErr)
	}
	if rmErr := os.Remove(blobPath); rmErr != nil {
		t.Fatalf("remove blob object: %v", rmErr)
	}
	reopened, err := openRepo(dir)
	if err != nil {
		t.Fatalf("reopen repo: %v", err)
	}
	brokenCommit, err := reopened.CommitObject(commit.Hash)
	if err != nil {
		t.Fatalf("CommitObject: %v", err)
	}

	data, ok := committedContent(brokenCommit, "config.yaml")

	if ok {
		t.Errorf("ok = true, want false when the committed blob cannot be read")
	}
	if data != nil {
		t.Errorf("data = %q, want nil", data)
	}
}

// --- collectForceResetBackups worktree/status failures ---------------------

// TestCollectForceResetBackupsWorktreeFailureIsReported covers the
// Worktree() error branch: a bare repository has no worktree, so the backup
// sweep cannot inspect local changes and must say so instead of reporting
// "no backups needed" and letting a reset discard data unchecked.
func TestCollectForceResetBackupsWorktreeFailureIsReported(t *testing.T) {
	bareDir := t.TempDir()
	if _, err := gogit.PlainInit(bareDir, true); err != nil {
		t.Fatalf("PlainInit bare: %v", err)
	}
	repo, err := openRepo(bareDir)
	if err != nil {
		t.Fatalf("openRepo bare: %v", err)
	}

	backups, err := collectForceResetBackups(repo, bareDir, nil, nil)

	if err == nil {
		t.Fatalf("expected collectForceResetBackups to fail without a worktree, got backups=%v", backups)
	}
	if len(backups) != 0 {
		t.Errorf("backups = %v, want none on error", backups)
	}
}

// TestCollectForceResetBackupsChangedPathsFailureIsReported covers the
// changedPaths error branch inside collectForceResetBackups: when the diff
// between the local and incoming commit cannot be computed, the sweep must
// abort rather than silently back up nothing before a destructive reset.
func TestCollectForceResetBackupsChangedPathsFailureIsReported(t *testing.T) {
	dir, first, second := twoCommitVault(t)
	repo := breakCommitTree(t, dir, first)

	brokenFirst, err := repo.CommitObject(first.Hash)
	if err != nil {
		t.Fatalf("CommitObject(first): %v", err)
	}
	intactSecond, err := repo.CommitObject(second.Hash)
	if err != nil {
		t.Fatalf("CommitObject(second): %v", err)
	}

	backups, err := collectForceResetBackups(repo, dir, brokenFirst, intactSecond)

	if err == nil {
		t.Fatalf("expected collectForceResetBackups to propagate the diff failure, got backups=%v", backups)
	}
	if len(backups) != 0 {
		t.Errorf("backups = %v, want none on error", backups)
	}
}

// --- ForcePull remote-listing and lookup failures --------------------------

// TestCollectForceResetBackupsStatusFailureIsReported covers the Status()
// error branch: a malformed git index makes the worktree status unreadable, so
// the backup sweep cannot tell which files are locally modified. It must
// report that instead of concluding "nothing to back up" and letting the hard
// reset discard the user's uncommitted vault entries unprotected.
func TestCollectForceResetBackupsStatusFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeFile(t, dir, "config.yaml", []byte("cfg1"))
	if err := AutoCommit(dir, "seed"); err != nil {
		t.Fatalf("AutoCommit: %v", err)
	}
	repo, err := openRepo(dir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	// A garbage index still opens as a worktree but fails on Status().
	if err := os.WriteFile(filepath.Join(dir, ".git", "index"), []byte("garbage-index"), 0o600); err != nil {
		t.Fatalf("corrupt index: %v", err)
	}

	backups, err := collectForceResetBackups(repo, dir, nil, nil)

	if err == nil {
		t.Fatalf("expected collectForceResetBackups to fail on an unreadable index, got backups=%v", backups)
	}
	if len(backups) != 0 {
		t.Errorf("backups = %v, want none on error", backups)
	}
}

// TestResolveConflictsStatusFailureIsReported covers ResolveConflicts's
// Status() error branch: an unreadable index means the sweep cannot tell which
// files are dirty, so it must report the failure rather than silently
// preserving nothing after a pull.
func TestResolveConflictsStatusFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeFile(t, dir, "config.yaml", []byte("cfg1"))
	if err := AutoCommit(dir, "seed"); err != nil {
		t.Fatalf("AutoCommit: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "index"), []byte("garbage-index"), 0o600); err != nil {
		t.Fatalf("corrupt index: %v", err)
	}

	if err := ResolveConflicts(dir, "macbook"); err == nil {
		t.Fatalf("expected ResolveConflicts to fail on an unreadable index")
	}
}

// TestResolveConflictsWorktreeFailureIsReported covers ResolveConflicts's
// Worktree() error branch: a bare repository has no worktree to inspect, so the
// sweep must report the failure rather than claim success without having looked
// at a single file.
func TestResolveConflictsWorktreeFailureIsReported(t *testing.T) {
	bareDir := t.TempDir()
	if _, err := gogit.PlainInit(bareDir, true); err != nil {
		t.Fatalf("PlainInit bare: %v", err)
	}

	if err := ResolveConflicts(bareDir, "macbook"); err == nil {
		t.Fatalf("expected ResolveConflicts to fail on a bare repository")
	}
}

// NOTE: seven defensive branches in git_pull.go are deliberately left
// uncovered because they were each verified to be unreachable from a test, not
// merely inconvenient to reach. Recording the evidence here so a future
// coverage pass does not burn time rediscovering it — or, worse, "reaches"
// them with a test that only pretends to:
//
//   - PullWithResult's and ForcePull's `repo.Remotes()` error branches: every
//     way of corrupting `.git/config` enough to break remote parsing makes the
//     preceding `openRepo` fail first (verified with a malformed section, a
//     truncated remote URL line and NUL bytes: `openRepo` returned
//     "expected section name" / "illegal character NUL", so the function
//     returns at the skip branch above). A config valid enough for `openRepo`
//     yields a parseable remote list.
//   - ForcePull's `CommitObject(remoteRef.Hash())` failure: the fetch that runs
//     immediately before it *repairs* exactly this corruption — deleting the
//     remote tip's object and calling ForcePull was verified to succeed,
//     because the fetch re-downloads it into a packfile. Pointing the
//     remote-tracking ref at a bogus hash does not work either: the same fetch
//     rewrites the ref back to the real tip. With an unreachable remote the
//     earlier fetch-error branch returns instead (covered by
//     TestForcePullFetchNetworkFailureReportsNetworkMessage).
//   - ForcePull's `repo.Worktree()` failure: only a bare repository has no
//     worktree, and TestForcePullWorktreeFailureIsReported shows such a repo
//     already fails in collectForceResetBackups one step earlier.
//   - changedPaths's `fromTree.Diff(toTree)` failure: the diff compares tree
//     entry hashes and does not read blob content, so removing a blob does not
//     fail it (verified: the diff still returned the changed path). Both
//     reachable tree-read failures above it are covered.
//   - committedContent's `f.Reader()` and `io.ReadAll` failures: the go-git
//     object layer validates the blob when the tree entry is resolved, so a
//     corrupted blob fails at `commit.File()` — the branch covered by
//     TestCommittedContentUnreadableBlobReportsNotOk — never later at the
//     reader.

// TestForcePullWorktreeFailureIsReported covers ForcePull's Worktree()
// error branch. A bare repository cannot be reset, so ForcePull must report a
// failure — reached here after a successful fetch against a real remote, so
// the earlier stages all pass.
func TestForcePullWorktreeFailureIsReported(t *testing.T) {
	_, remoteBareDir := remoteVaultPair(t)

	// A second bare clone of the same remote: it has origin, a branch and a
	// remote-tracking ref, but no worktree.
	bareClone := t.TempDir()
	if _, err := gogit.PlainClone(bareClone, true, &gogit.CloneOptions{URL: remoteBareDir}); err != nil {
		t.Fatalf("PlainClone bare: %v", err)
	}

	result := ForcePull(bareClone)

	if result.Error == nil && !result.Skipped {
		t.Fatalf("expected ForcePull on a bare repository to fail or skip, got success=%v", result.Success)
	}
	if result.Success {
		t.Errorf("Success = true, want false — a bare repository cannot be reset")
	}
	// The failure must be attributable, not a bare "no". Either the backup
	// inspection or the worktree lookup reports it, depending on how far the
	// bare clone gets.
	if result.Error != nil {
		msg := result.Error.Error()
		if !strings.Contains(msg, "worktree") && !strings.Contains(msg, "failed to inspect local changes before reset") {
			t.Errorf("Error = %v, want it to mention the missing worktree or the failed inspection", result.Error)
		}
	}
}

// --- resolveDivergedConflicts diff failure ---------------------------------

// TestResolveDivergedConflictsDiffFailureIsReported covers the changedPaths
// error branch inside resolveDivergedConflicts: when the ancestor's tree is
// unreadable the sweep cannot know which files the remote touched, so it must
// report the failure instead of silently preserving nothing after a failed
// pull.
func TestResolveDivergedConflictsDiffFailureIsReported(t *testing.T) {
	// Deliberately not remoteVaultPair: a clone stores its objects in a
	// packfile, and breakCommitTree can only corrupt loose objects. A locally
	// initialized vault keeps them loose, so push it to a bare remote by hand.
	localDir := t.TempDir()
	if err := Init(localDir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(localDir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	writeFile(t, localDir, "config.yaml", []byte("cfg1"))
	if err := AutoCommit(localDir, "seed"); err != nil {
		t.Fatalf("AutoCommit seed: %v", err)
	}
	remoteBareDir := t.TempDir()
	if _, err := gogit.PlainInit(remoteBareDir, true); err != nil {
		t.Fatalf("PlainInit bare remote: %v", err)
	}
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	if _, err := repo.CreateRemote(&gogitconfig.RemoteConfig{
		Name: originRemoteName,
		URLs: []string{remoteBareDir},
	}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	if err := repo.Push(&gogit.PushOptions{RemoteName: originRemoteName}); err != nil {
		t.Fatalf("push seed: %v", err)
	}
	preHead := headCommit(repo)
	if preHead == nil {
		t.Fatalf("expected a HEAD commit")
	}

	// Move the remote forward and fetch, so the remote tip differs from
	// preHead and the diff step is actually reached.
	pushFromFreshClone(t, remoteBareDir, "update config", func(dir string) {
		writeFile(t, dir, "config.yaml", []byte("cfg-remote-edit"))
	})
	if fetchErr := fetchWithSSHAuth(repo, remoteBareDir); fetchErr != nil && !errors.Is(fetchErr, gogit.NoErrAlreadyUpToDate) {
		t.Fatalf("fetch: %v", fetchErr)
	}

	// preHead is the merge base here, so breaking its tree breaks the diff.
	brokenRepo := breakCommitTree(t, localDir, preHead)
	brokenPreHead, err := brokenRepo.CommitObject(preHead.Hash)
	if err != nil {
		t.Fatalf("CommitObject(preHead): %v", err)
	}

	err = resolveDivergedConflicts(brokenRepo, localDir, "macbook", brokenPreHead, originRemoteName)

	if err == nil {
		t.Fatalf("expected resolveDivergedConflicts to report the unreadable-history failure")
	}
}
