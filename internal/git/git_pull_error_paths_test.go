package git

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

// This file covers the error and guard branches of the git-sync pull path that
// the happy-path tests never reach: ForcePull's early bail-outs, the
// conflict-candidate guards, and the small helpers ResolveConflicts and
// resolveDivergedConflicts depend on. Every test asserts the observable
// outcome (returned error, skip flag, whether a conflict copy exists on disk),
// never just that a line executed.

// --- fetchWithSSHAuth -------------------------------------------------------

// TestFetchWithSSHAuthWithSSHURLStillFetchesConfiguredRemote covers the
// isSSHURL branch of fetchWithSSHAuth. The remoteURL argument only decides
// whether SSH auth is attached; the fetch itself always runs against the
// configured "origin". Passing an ssh:// URL while origin points at a local
// bare repo therefore exercises the auth branch without any network access,
// and must not break an otherwise valid fetch.
func TestFetchWithSSHAuthWithSSHURLStillFetchesConfiguredRemote(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}

	err = fetchWithSSHAuth(repo, "ssh://git@example.com/vault.git")

	// The clone is current, so an up-to-date fetch is the expected outcome.
	// Anything other than nil / NoErrAlreadyUpToDate would mean the SSH-auth
	// branch broke a fetch that works without it.
	if err != nil && !errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		t.Errorf("fetchWithSSHAuth with an ssh URL = %v, want nil or NoErrAlreadyUpToDate", err)
	}
}

// --- PullWithResult ---------------------------------------------------------

// TestPullWithResultOfflineRemoteReportsNetworkMessage covers
// PullWithResult's offline-classification branch: a pull against an
// unreachable remote must surface the actionable connectivity message rather
// than a raw transport error.
func TestPullWithResultOfflineRemoteReportsNetworkMessage(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	if err := repo.DeleteRemote(originRemoteName); err != nil {
		t.Fatalf("DeleteRemote: %v", err)
	}
	// Port 1 is reserved and nothing listens on it, so the pull fails fast
	// with "connection refused" — an offline-classified error.
	if _, err := repo.CreateRemote(&gogitconfig.RemoteConfig{
		Name: originRemoteName,
		URLs: []string{"http://127.0.0.1:1/unreachable.git"},
	}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}

	result := PullWithResult(localDir)

	if result.Error == nil {
		t.Fatalf("expected PullWithResult to report a network failure, got success")
	}
	if !strings.Contains(result.Error.Error(), errNetworkMessage) {
		t.Errorf("Error = %v, want it to contain %q", result.Error, errNetworkMessage)
	}
	if result.Success {
		t.Errorf("Success = true, want false for an unreachable remote")
	}
}

// --- ForcePull early bail-outs ---------------------------------------------

// TestForcePullOnNonRepositoryIsSkipped covers ForcePull's openRepo failure
// branch: a directory that is not a git repository is skipped, not reported
// as an error, so a vault without git sync configured stays usable.
func TestForcePullOnNonRepositoryIsSkipped(t *testing.T) {
	result := ForcePull(t.TempDir())

	if !result.Skipped {
		t.Errorf("Skipped = false, want true for a non-repository directory")
	}
	if result.Error != nil {
		t.Errorf("Error = %v, want nil (a missing repo is a skip, not a failure)", result.Error)
	}
	if result.Success {
		t.Errorf("Success = true, want false")
	}
}

// TestForcePullWithoutOriginRemoteIsSkipped covers ForcePull's
// "no origin remote" branch: a git repository that was never given a remote
// has nothing to reset to and must be skipped rather than failing.
func TestForcePullWithoutOriginRemoteIsSkipped(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	writeFile(t, dir, "config.yaml", []byte("cfg1"))
	if err := AutoCommit(dir, "initial"); err != nil {
		t.Fatalf("AutoCommit: %v", err)
	}

	result := ForcePull(dir)

	if !result.Skipped {
		t.Errorf("Skipped = false, want true when no origin remote is configured")
	}
	if result.HasRemote {
		t.Errorf("HasRemote = true, want false")
	}
	if result.Error != nil {
		t.Errorf("Error = %v, want nil", result.Error)
	}
}

// TestForcePullIgnoresStagedOnlyChangeForBackup covers
// collectForceResetBackups's staged-entry guard: the backup sweep only
// snapshots files that are modified in the worktree but clean in the index.
// A staged change is deliberately skipped, so no conflict copy appears for it.
//
// This documents current behavior rather than endorsing it: a staged change
// is still discarded by the hard reset, so it is preserved only by git's own
// index, not by a conflict copy.
func TestForcePullIgnoresStagedOnlyChangeForBackup(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)
	writeFile(t, localDir, "config.yaml", []byte("cfg1-staged-edit"))
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := w.Add("config.yaml"); err != nil {
		t.Fatalf("stage config.yaml: %v", err)
	}
	pushFromFreshClone(t, remoteBareDir, "add b", func(dir string) {
		writeFile(t, dir, "entries/b.age", []byte("new-entry"))
	})

	result := ForcePull(localDir)

	if result.Error != nil {
		t.Fatalf("ForcePull: unexpected error %v", result.Error)
	}
	if _, err := os.Stat(conflictCopyPath(localDir, "config.yaml")); !os.IsNotExist(err) {
		t.Errorf("unexpected conflict copy for a staged-only change (stat error = %v)", err)
	}
}

// --- isConflictCandidatePath ------------------------------------------------

// TestIsConflictCandidatePath covers the guard that decides which paths are
// ever snapshotted as a conflict copy, including the two rejection branches
// the happy path never reaches: an existing conflict copy and a protected
// runtime or identity file.
func TestIsConflictCandidatePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"vault entry", "entries/a.age", true},
		{"config", "config.yaml", true},
		{"unrelated extension", "notes.txt", false},
		{"existing conflict copy", "entries/a" + ConflictMarker + "macbook.age", false},
		{"config conflict copy", "config" + ConflictMarker + "macbook.yaml", false},
		{"identity key", "identity.age", false},
		{"protected runtime token", "mcp-token", false},
		{"protected runtime tokens file", "mcp-tokens.json", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isConflictCandidatePath(tc.path); got != tc.want {
				t.Errorf("isConflictCandidatePath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// --- preserveConflictCandidate / writeConflictCopy --------------------------

// TestPreserveConflictCandidateSkipsNonCandidate asserts the guard short-
// circuits before touching the filesystem: a non-candidate path writes
// nothing and reports no error.
func TestPreserveConflictCandidateSkipsNonCandidate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "notes.txt", []byte("plain note"))

	if err := preserveConflictCandidate(dir, "macbook", "notes.txt", nil); err != nil {
		t.Fatalf("preserveConflictCandidate: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "notes"+ConflictMarker+"macbook.txt")); !os.IsNotExist(err) {
		t.Errorf("wrote a conflict copy for a non-candidate path (stat error = %v)", err)
	}
}

// TestPreserveConflictCandidateWrapsWriteFailure covers the error-wrapping
// branch: when the conflict copy cannot be written, the failure must name the
// conflict file so the user knows which entry was not preserved.
func TestPreserveConflictCandidateWrapsWriteFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", []byte("cfg-local-edit"))
	// A directory occupying the conflict-copy path makes the write fail.
	if err := os.MkdirAll(filepath.Join(dir, "config"+ConflictMarker+"macbook.yaml"), 0o755); err != nil {
		t.Fatalf("pre-create colliding directory: %v", err)
	}

	err := preserveConflictCandidate(dir, "macbook", "config.yaml", nil)

	if err == nil {
		t.Fatalf("expected preserveConflictCandidate to fail when the conflict path is occupied")
	}
	if !strings.Contains(err.Error(), "config"+ConflictMarker+"macbook.yaml") {
		t.Errorf("error = %v, want it to name the conflict file", err)
	}
}

// TestWriteConflictCopyMissingSourceIsSkipped covers writeConflictCopy's
// not-exist branch: a file that vanished from the worktree has nothing to
// snapshot and must not abort the sweep over the remaining files.
func TestWriteConflictCopyMissingSourceIsSkipped(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "gone"+ConflictMarker+"macbook.age")

	if err := writeConflictCopy(filepath.Join(dir, "gone.age"), dst, nil, "gone.age"); err != nil {
		t.Fatalf("writeConflictCopy for a missing source = %v, want nil", err)
	}

	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("wrote a conflict copy although the source does not exist (stat error = %v)", err)
	}
}

// TestWriteConflictCopyUnreadableSourceReturnsError covers
// writeConflictCopy's non-not-exist read-error branch: a read failure other
// than "missing" must surface, because silently skipping it would drop a file
// the user still has on disk.
func TestWriteConflictCopyUnreadableSourceReturnsError(t *testing.T) {
	dir := t.TempDir()
	// A directory in place of the source file makes ReadFile fail with a
	// non-not-exist error.
	src := filepath.Join(dir, "entry.age")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	dst := filepath.Join(dir, "entry"+ConflictMarker+"macbook.age")

	err := writeConflictCopy(src, dst, nil, "entry.age")

	if err == nil {
		t.Fatalf("expected writeConflictCopy to return the read error for an unreadable source")
	}
	if os.IsNotExist(err) {
		t.Errorf("error = %v, want a read error rather than not-exist", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Errorf("wrote a conflict copy despite the read failure (stat error = %v)", statErr)
	}
}

// --- headCommit / committedContent -----------------------------------------

// TestHeadCommitReturnsNilWhenHeadIsNotACommit covers headCommit's
// CommitObject failure branch: HEAD resolving to an object that is not a
// commit must yield nil instead of panicking, so callers fall back to
// "no baseline" rather than crashing.
func TestHeadCommitReturnsNilWhenHeadIsNotACommit(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		t.Fatalf("CommitObject: %v", err)
	}
	// Point the current branch at the commit's tree: a valid object that is
	// not a commit.
	if err := repo.Storer.SetReference(plumbing.NewHashReference(head.Name(), commit.TreeHash)); err != nil {
		t.Fatalf("SetReference to tree hash: %v", err)
	}

	if got := headCommit(repo); got != nil {
		t.Errorf("headCommit = %v, want nil when HEAD is not a commit", got.Hash)
	}
}

// TestCommittedContent covers the two reachable "cannot read" branches of
// committedContent: a nil baseline commit and a path the commit does not
// contain. Both must report ok=false so callers treat the file as diverged
// instead of comparing against empty content.
func TestCommittedContent(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	head := headCommit(repo)
	if head == nil {
		t.Fatalf("expected a HEAD commit in the seeded clone")
	}

	t.Run("nil commit", func(t *testing.T) {
		data, ok := committedContent(nil, "config.yaml")
		if ok {
			t.Errorf("ok = true, want false for a nil commit")
		}
		if data != nil {
			t.Errorf("data = %q, want nil", data)
		}
	})

	t.Run("path not in commit", func(t *testing.T) {
		data, ok := committedContent(head, "entries/never-committed.age")
		if ok {
			t.Errorf("ok = true, want false for a path the commit does not contain")
		}
		if data != nil {
			t.Errorf("data = %q, want nil", data)
		}
	})

	t.Run("committed path is readable", func(t *testing.T) {
		data, ok := committedContent(head, "config.yaml")
		if !ok {
			t.Fatalf("ok = false, want true for a committed path")
		}
		if string(data) != "cfg1" {
			t.Errorf("data = %q, want %q", data, "cfg1")
		}
	})
}

// --- changedPaths -----------------------------------------------------------

// TestChangedPathsIncludesDeletedFile covers changedPaths's From-name
// fallback: a deletion has an empty To name, so the path must be taken from
// the From side. Without that fallback a file deleted on the remote would be
// missing from the change set and never preserved.
func TestChangedPathsIncludesDeletedFile(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	writeFile(t, dir, "entries/a.age", []byte("v1"))
	writeFile(t, dir, "config.yaml", []byte("cfg1"))
	if err := AutoCommit(dir, "initial"); err != nil {
		t.Fatalf("AutoCommit initial: %v", err)
	}
	repo, err := openRepo(dir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	before := headCommit(repo)
	if before == nil {
		t.Fatalf("expected an initial commit")
	}

	if err := os.Remove(filepath.Join(dir, "entries/a.age")); err != nil {
		t.Fatalf("remove entry: %v", err)
	}
	if err := AutoCommit(dir, "delete entry"); err != nil {
		t.Fatalf("AutoCommit delete: %v", err)
	}
	after := headCommit(repo)
	if after == nil {
		t.Fatalf("expected a commit after the deletion")
	}

	paths, err := changedPaths(before, after)
	if err != nil {
		t.Fatalf("changedPaths: %v", err)
	}

	var found bool
	for _, p := range paths {
		if p == "entries/a.age" {
			found = true
		}
		if p == "" {
			t.Errorf("changedPaths returned an empty path: %q", paths)
		}
	}
	if !found {
		t.Errorf("changedPaths = %q, want it to include the deleted entries/a.age", paths)
	}
}

// --- ResolveConflicts / resolveDivergedConflicts ---------------------------

// TestResolveConflictsPropagatesPreserveFailure covers ResolveConflicts's
// error-propagation branch: when a dirty candidate cannot be preserved the
// sweep must report it instead of returning success, otherwise the caller
// believes the local version was saved when it was not.
func TestResolveConflictsPropagatesPreserveFailure(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))
	device := DeviceIdentity(localDir)
	if err := os.MkdirAll(conflictCopyPath(localDir, "config.yaml"), 0o755); err != nil {
		t.Fatalf("pre-create colliding directory: %v", err)
	}

	err := ResolveConflicts(localDir, device)

	if err == nil {
		t.Fatalf("expected ResolveConflicts to fail when a conflict copy cannot be written")
	}
	if !strings.Contains(err.Error(), "config") {
		t.Errorf("error = %v, want it to name the affected file", err)
	}
}

// TestResolveConflictsOnNonRepositoryIsNoop asserts the openRepo guard: a
// directory without git returns nil, so the CLI keeps working on a vault that
// never enabled sync.
func TestResolveConflictsOnNonRepositoryIsNoop(t *testing.T) {
	if err := ResolveConflicts(t.TempDir(), "macbook"); err != nil {
		t.Errorf("ResolveConflicts on a non-repository = %v, want nil", err)
	}
}

// TestResolveDivergedConflictsDetachedHeadIsNoop covers the head-resolution
// guard: without a branch there is no remote-tracking ref to compare against,
// so the sweep must do nothing rather than guess a baseline.
func TestResolveDivergedConflictsDetachedHeadIsNoop(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	preHead := headCommit(repo)
	if preHead == nil {
		t.Fatalf("expected a HEAD commit")
	}
	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := w.Checkout(&gogit.CheckoutOptions{Hash: preHead.Hash}); err != nil {
		t.Fatalf("detach HEAD: %v", err)
	}
	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))

	if err := resolveDivergedConflicts(repo, localDir, "macbook", preHead, originRemoteName); err != nil {
		t.Errorf("resolveDivergedConflicts on a detached HEAD = %v, want nil", err)
	}
	if _, err := os.Stat(conflictCopyPath(localDir, "config.yaml")); !os.IsNotExist(err) {
		t.Errorf("wrote a conflict copy despite a detached HEAD (stat error = %v)", err)
	}
}

// TestResolveDivergedConflictsNilPreHeadIsNoop covers the nil-baseline guard:
// without a "before" snapshot there is nothing to compare, so no conflict copy
// may be invented.
func TestResolveDivergedConflictsNilPreHeadIsNoop(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))

	if err := resolveDivergedConflicts(repo, localDir, "macbook", nil, originRemoteName); err != nil {
		t.Errorf("resolveDivergedConflicts with a nil preHead = %v, want nil", err)
	}
	if _, err := os.Stat(conflictCopyPath(localDir, "config.yaml")); !os.IsNotExist(err) {
		t.Errorf("wrote a conflict copy without a baseline commit (stat error = %v)", err)
	}
}

// TestResolveDivergedConflictsMissingRemoteRefIsNoop covers the
// remote-tracking-ref guard: a branch the remote does not know cannot be
// compared, so the sweep stays silent instead of erroring.
func TestResolveDivergedConflictsMissingRemoteRefIsNoop(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	preHead := headCommit(repo)
	if preHead == nil {
		t.Fatalf("expected a HEAD commit")
	}
	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := w.Checkout(&gogit.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName("local-only-branch"),
		Hash:   preHead.Hash,
		Create: true,
	}); err != nil {
		t.Fatalf("create local-only branch: %v", err)
	}
	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))

	if err := resolveDivergedConflicts(repo, localDir, "macbook", preHead, originRemoteName); err != nil {
		t.Errorf("resolveDivergedConflicts without a remote-tracking ref = %v, want nil", err)
	}
	if _, err := os.Stat(conflictCopyPath(localDir, "config.yaml")); !os.IsNotExist(err) {
		t.Errorf("wrote a conflict copy for a branch the remote does not have (stat error = %v)", err)
	}
}

// TestResolveDivergedConflictsRemoteEqualToPreHeadIsNoop covers the
// "remote did not move" guard, which is the core of the #831 fix: when the
// remote tip equals the pre-pull HEAD the remote changed nothing, so a merely
// dirty local file is not a conflict and must be left alone.
func TestResolveDivergedConflictsRemoteEqualToPreHeadIsNoop(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	preHead := headCommit(repo)
	if preHead == nil {
		t.Fatalf("expected a HEAD commit")
	}
	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))

	if err := resolveDivergedConflicts(repo, localDir, "macbook", preHead, originRemoteName); err != nil {
		t.Errorf("resolveDivergedConflicts with an unmoved remote = %v, want nil", err)
	}
	if _, err := os.Stat(conflictCopyPath(localDir, "config.yaml")); !os.IsNotExist(err) {
		t.Errorf("wrote a conflict copy although the remote never moved (stat error = %v)", err)
	}
}

// TestResolveDivergedConflictsPropagatesPreserveFailure covers the
// error-propagation branch inside the changed-path loop: when a genuinely
// diverged file cannot be preserved, the failure must reach the caller.
func TestResolveDivergedConflictsPropagatesPreserveFailure(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	preHead := headCommit(repo)
	if preHead == nil {
		t.Fatalf("expected a HEAD commit")
	}
	// The remote changes config.yaml, so it is genuinely part of the
	// diverged change set...
	pushFromFreshClone(t, remoteBareDir, "update config", func(dir string) {
		writeFile(t, dir, "config.yaml", []byte("cfg-remote-edit"))
	})
	if err := fetchWithSSHAuth(repo, remoteBareDir); err != nil && !errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		t.Fatalf("fetch: %v", err)
	}
	// ...and locally it diverges too, while its conflict-copy destination is
	// blocked by a directory.
	writeFile(t, localDir, "config.yaml", []byte("cfg-local-edit"))
	device := DeviceIdentity(localDir)
	if err := os.MkdirAll(conflictCopyPath(localDir, "config.yaml"), 0o755); err != nil {
		t.Fatalf("pre-create colliding directory: %v", err)
	}

	err = resolveDivergedConflicts(repo, localDir, device, preHead, originRemoteName)

	if err == nil {
		t.Fatalf("expected resolveDivergedConflicts to propagate the write failure")
	}
	if !strings.Contains(err.Error(), "config") {
		t.Errorf("error = %v, want it to name the affected file", err)
	}
}
