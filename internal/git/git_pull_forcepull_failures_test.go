package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

// TestForcePullFetchNetworkFailureReportsNetworkMessage covers ForcePull's
// fetch-failure branch when the underlying error is classified as an offline
// / connectivity problem by IsOfflineError.
func TestForcePullFetchNetworkFailureReportsNetworkMessage(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	if err := repo.DeleteRemote(originRemoteName); err != nil {
		t.Fatalf("DeleteRemote: %v", err)
	}
	// Port 1 is a reserved port nothing listens on locally, so the fetch
	// fails fast with "connection refused" — a network-classified error.
	if _, err := repo.CreateRemote(&gogitconfig.RemoteConfig{
		Name: originRemoteName,
		URLs: []string{"http://127.0.0.1:1/unreachable.git"},
	}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}

	result := ForcePull(localDir)
	if result.Error == nil {
		t.Fatalf("expected ForcePull to report a fetch failure, got success")
	}
	if !strings.Contains(result.Error.Error(), errNetworkMessage) {
		t.Errorf("Error = %v, want it to contain %q", result.Error, errNetworkMessage)
	}
}

// TestForcePullFetchGenericFailureReportsFetchFailed covers ForcePull's
// fetch-failure branch when the underlying error is not offline-classified
// (e.g. the remote path exists but is not a git repository at all).
func TestForcePullFetchGenericFailureReportsFetchFailed(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	notARepo := t.TempDir()
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	if err := repo.DeleteRemote(originRemoteName); err != nil {
		t.Fatalf("DeleteRemote: %v", err)
	}
	if _, err := repo.CreateRemote(&gogitconfig.RemoteConfig{
		Name: originRemoteName,
		URLs: []string{notARepo},
	}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}

	result := ForcePull(localDir)
	if result.Error == nil {
		t.Fatalf("expected ForcePull to report a fetch failure, got success")
	}
	if !strings.Contains(result.Error.Error(), "fetch failed") {
		t.Errorf("Error = %v, want it to contain %q", result.Error, "fetch failed")
	}
}

// TestForcePullDetachedHeadCannotResolveBranch covers the branch-resolution
// failure: ForcePull requires HEAD to point at a branch (so it knows which
// remote-tracking ref to reset to), and must report a clear error instead of
// panicking when the local repo is in a detached-HEAD state.
func TestForcePullDetachedHeadCannotResolveBranch(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := w.Checkout(&gogit.CheckoutOptions{Hash: head.Hash()}); err != nil {
		t.Fatalf("detach HEAD: %v", err)
	}

	result := ForcePull(localDir)
	if result.Error == nil {
		t.Fatalf("expected ForcePull to fail on a detached HEAD, got success")
	}
	if !strings.Contains(result.Error.Error(), "could not resolve local branch") {
		t.Errorf("Error = %v, want it to mention branch resolution", result.Error)
	}
}

// TestForcePullMissingRemoteTrackingRefIsReported covers the case where the
// local branch has no corresponding remote-tracking ref (e.g. a branch that
// was never pushed) — ForcePull cannot know what to reset to.
func TestForcePullMissingRemoteTrackingRefIsReported(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	repo, err := openRepo(localDir)
	if err != nil {
		t.Fatalf("openRepo: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	localOnlyBranch := plumbing.NewBranchReferenceName("local-only-branch")
	if err := w.Checkout(&gogit.CheckoutOptions{Branch: localOnlyBranch, Hash: head.Hash(), Create: true}); err != nil {
		t.Fatalf("checkout new branch: %v", err)
	}

	result := ForcePull(localDir)
	if result.Error == nil {
		t.Fatalf("expected ForcePull to fail for a branch with no remote-tracking ref, got success")
	}
	if !strings.Contains(result.Error.Error(), "remote branch not found") {
		t.Errorf("Error = %v, want it to mention the missing remote branch", result.Error)
	}
}

// TestForcePullResetFailureIsReported covers the reset-failure branch: the
// fetch and every lookup before it succeed, but the actual hard reset fails
// because a local directory occupies the path a tracked file needs to be
// written to. "notes.txt" is deliberately not a conflict-candidate path (no
// .age suffix, not config.yaml) so this test isolates the reset failure from
// collectForceResetBackups's own error handling.
func TestForcePullResetFailureIsReported(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)
	pushFromFreshClone(t, remoteBareDir, "add notes", func(dir string) {
		writeFile(t, dir, "notes.txt", []byte("plain note"))
	})
	if err := os.MkdirAll(filepath.Join(localDir, "notes.txt"), 0o755); err != nil {
		t.Fatalf("pre-create colliding directory: %v", err)
	}

	result := ForcePull(localDir)
	if result.Error == nil {
		t.Fatalf("expected ForcePull to report a reset failure, got success")
	}
	if !strings.Contains(result.Error.Error(), "reset failed") {
		t.Errorf("Error = %v, want it to mention the reset failure", result.Error)
	}
}

// TestForcePullCollectBackupsReadErrorIsReported covers
// collectForceResetBackups's own error return when reading a candidate
// file's current content fails for a reason other than "does not exist" —
// here because a local directory occupies the candidate file's path.
func TestForcePullCollectBackupsReadErrorIsReported(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)
	pushFromFreshClone(t, remoteBareDir, "add b", func(dir string) {
		writeFile(t, dir, "entries/b.age", []byte("new-entry"))
	})
	if err := os.MkdirAll(filepath.Join(localDir, "entries", "b.age"), 0o755); err != nil {
		t.Fatalf("pre-create colliding directory: %v", err)
	}

	result := ForcePull(localDir)
	if result.Error == nil {
		t.Fatalf("expected ForcePull to report a failure inspecting local changes, got success")
	}
	if !strings.Contains(result.Error.Error(), "failed to inspect local changes before reset") {
		t.Errorf("Error = %v, want it to mention the inspection failure", result.Error)
	}
}

// TestForcePullBackupWriteFailureIsReported covers the case where the reset
// itself succeeds but writing the discarded local version as a conflict copy
// fails — here because a local directory occupies the exact conflict-copy
// path. This also exercises writeForceResetBackups's own WriteFile error
// return.
func TestForcePullBackupWriteFailureIsReported(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)
	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))
	pushFromFreshClone(t, remoteBareDir, "add b", func(dir string) {
		writeFile(t, dir, "entries/b.age", []byte("new-entry"))
	})
	if err := os.MkdirAll(conflictCopyPath(localDir, "config.yaml"), 0o755); err != nil {
		t.Fatalf("pre-create colliding directory: %v", err)
	}

	result := ForcePull(localDir)
	if result.Error == nil {
		t.Fatalf("expected ForcePull to report a backup-write failure, got success")
	}
	if !strings.Contains(result.Error.Error(), "reset succeeded but failed to back up discarded local changes") {
		t.Errorf("Error = %v, want it to mention the backup-write failure", result.Error)
	}

	// The reset itself must still have gone through: the local edit is gone,
	// even though the backup could not be written.
	data, err := os.ReadFile(filepath.Join(localDir, "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	if string(data) != "cfg1" {
		t.Errorf("config.yaml = %q, want %q (reset should have discarded the local edit)", data, "cfg1")
	}
}

// TestWriteForceResetBackupsSkipsIdenticalExistingConflictCopy covers
// writeForceResetBackups's own idempotency skip: when a conflict copy for a
// path already exists on disk with the exact bytes about to be written, it
// must not be rewritten. Exercised directly against writeForceResetBackups
// rather than through ForcePull: ForcePull's own gogit.HardReset step always
// clears untracked files (including any previous conflict copy) before
// writeForceResetBackups runs, so this skip is unreachable through ForcePull
// itself — it only protects a direct or future caller.
func TestWriteForceResetBackupsSkipsIdenticalExistingConflictCopy(t *testing.T) {
	dir := t.TempDir()
	device := DeviceIdentity(dir)
	backups := []forceResetBackup{{path: "config.yaml", data: []byte("cfg1-local-edit")}}

	if err := writeForceResetBackups(dir, device, backups); err != nil {
		t.Fatalf("first write: %v", err)
	}
	copyPath := conflictCopyPath(dir, "config.yaml")
	before, err := os.Stat(copyPath)
	if err != nil {
		t.Fatalf("expected a conflict copy after the first write: %v", err)
	}

	if err := writeForceResetBackups(dir, device, backups); err != nil {
		t.Fatalf("second write (identical content): %v", err)
	}

	data, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("read conflict copy: %v", err)
	}
	if string(data) != "cfg1-local-edit" {
		t.Errorf("conflict copy content = %q, want %q", data, "cfg1-local-edit")
	}
	after, err := os.Stat(copyPath)
	if err != nil {
		t.Fatalf("stat conflict copy after second write: %v", err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("conflict copy mtime changed (%v -> %v) although its content was identical — it should not have been rewritten", before.ModTime(), after.ModTime())
	}
}

// TestForcePullSkipsBackupWhenLocalContentAlreadyMatchesRemote covers
// collectForceResetBackups's dedup skip: a candidate path can be part of the
// preHead..remoteCommit diff (so it enters the loop) while the current disk
// content already matches remoteCommit's version — e.g. another device
// already pushed the same content the local copy was independently edited
// to. No backup is needed since there is nothing local to preserve.
func TestForcePullSkipsBackupWhenLocalContentAlreadyMatchesRemote(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)
	writeFile(t, localDir, "config.yaml", []byte("cfg2"))
	pushFromFreshClone(t, remoteBareDir, "update config", func(dir string) {
		writeFile(t, dir, "config.yaml", []byte("cfg2"))
	})

	result := ForcePull(localDir)
	if result.Error != nil {
		t.Fatalf("ForcePull: unexpected error %v", result.Error)
	}

	if _, err := os.Stat(conflictCopyPath(localDir, "config.yaml")); !os.IsNotExist(err) {
		t.Errorf("unexpected backup copy for config.yaml although local content already matched the incoming remote version (stat error = %v)", err)
	}
}
