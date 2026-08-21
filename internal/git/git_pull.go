package git

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func pullWithSSHAuth(w *gogit.Worktree, remoteURL string) error {
	opts := &gogit.PullOptions{RemoteName: originRemoteName}
	if isSSHURL(remoteURL) {
		auth, err := getSSHAuth()
		if err == nil {
			opts.Auth = auth
		}
	}
	return w.Pull(opts)
}

func fetchWithSSHAuth(repo *gogit.Repository, remoteURL string) error {
	opts := &gogit.FetchOptions{RemoteName: originRemoteName}
	if isSSHURL(remoteURL) {
		auth, err := getSSHAuth()
		if err == nil {
			opts.Auth = auth
		}
	}
	return repo.Fetch(opts)
}

func Pull(vaultDir string) error {
	result := PullWithResult(vaultDir)
	if result.Error != nil && !result.Skipped {
		return result.Error
	}
	return nil
}

// PullWithResult pulls from origin and returns detailed result.
func PullWithResult(vaultDir string) PullResult {
	result := PullResult{Success: false, Skipped: false}

	repo, err := openRepo(vaultDir)
	if err != nil {
		result.Skipped = true
		return result
	}

	w, err := repo.Worktree()
	if err != nil {
		result.Skipped = true
		return result
	}

	remotes, listErr := repo.Remotes()
	if listErr != nil {
		result.Error = &PushError{Message: errFailedListRemotes, Cause: listErr}
		return result
	}

	var originRemote *gogit.Remote
	for _, r := range remotes {
		if r.Config().Name == originRemoteName {
			originRemote = r
			result.HasRemote = true
			if len(r.Config().URLs) > 0 {
				result.RemoteURL = r.Config().URLs[0]
			}
			break
		}
	}

	if originRemote == nil {
		result.Skipped = true
		return result
	}

	// Captured before the pull attempt: a failed pull can still advance the
	// local branch ref as a side effect of go-git's internal fetch-then-merge
	// sequence (Pull moves HEAD before Reset checks for unstaged changes), so
	// HEAD read after the fact is not a reliable "before" snapshot.
	preHead := headCommit(repo)

	pullErr := pullWithSSHAuth(w, originRemote.Config().URLs[0])
	if pullErr == nil {
		result.Success = true
		result.Updated = true
		return result
	}
	if errors.Is(pullErr, gogit.NoErrAlreadyUpToDate) {
		result.Success = true
		return result
	}

	if errors.Is(pullErr, gogit.ErrRemoteNotFound) || errors.Is(pullErr, gogit.ErrRepositoryNotExists) {
		result.Skipped = true
		return result
	}

	if IsOfflineError(pullErr) {
		result.Error = &PushError{
			Message: errNetworkMessage,
			Cause:   pullErr,
		}
		return result
	}

	errStr := pullErr.Error()
	if strings.Contains(errStr, "authentication") || strings.Contains(errStr, "credentials") ||
		strings.Contains(errStr, "error: 401") || strings.Contains(errStr, "error: 403") {
		result.Error = &PushError{
			Message: "authentication failed - please check your credentials",
			Cause:   pullErr,
		}
		return result
	}

	deviceName := DeviceIdentity(vaultDir)
	resolveErr := resolveDivergedConflicts(repo, vaultDir, deviceName, preHead, originRemoteName)
	if resolveErr == nil {
		w2, wtErr := repo.Worktree()
		if wtErr == nil {
			if s, _ := w2.Status(); s != nil {
				for path := range s {
					if strings.Contains(path, ConflictMarker) {
						result.Conflicts = append(result.Conflicts, path)
					}
				}
			}
		}
	}

	result.Error = &PushError{
		Message: classifyPullFailure(pullErr),
		Cause:   pullErr,
	}
	return result
}

// ForcePull fetches from origin and hard-resets the local branch to match the
// fetched remote-tracking branch, discarding any local commits and
// uncommitted working-tree changes. Unlike PullWithResult it never attempts a
// merge, so a diverged history or a dirty worktree cannot make it fail the
// way an ordinary pull does.
func ForcePull(vaultDir string) PullResult {
	result := PullResult{Success: false, Skipped: false}

	repo, err := openRepo(vaultDir)
	if err != nil {
		result.Skipped = true
		return result
	}

	remotes, listErr := repo.Remotes()
	if listErr != nil {
		result.Error = &PushError{Message: errFailedListRemotes, Cause: listErr}
		return result
	}

	var originRemote *gogit.Remote
	for _, r := range remotes {
		if r.Config().Name == originRemoteName {
			originRemote = r
			result.HasRemote = true
			if len(r.Config().URLs) > 0 {
				result.RemoteURL = r.Config().URLs[0]
			}
			break
		}
	}
	if originRemote == nil {
		result.Skipped = true
		return result
	}

	preHead := headCommit(repo)

	fetchErr := fetchWithSSHAuth(repo, originRemote.Config().URLs[0])
	if fetchErr != nil && !errors.Is(fetchErr, gogit.NoErrAlreadyUpToDate) {
		if IsOfflineError(fetchErr) {
			result.Error = &PushError{
				Message: errNetworkMessage,
				Cause:   fetchErr,
			}
			return result
		}
		result.Error = &PushError{Message: "fetch failed", Cause: fetchErr}
		return result
	}

	head, err := repo.Head()
	if err != nil || !head.Name().IsBranch() {
		result.Error = &PushError{Message: "could not resolve local branch", Cause: err}
		return result
	}

	remoteRef, err := repo.Reference(plumbing.NewRemoteReferenceName(originRemoteName, head.Name().Short()), true)
	if err != nil {
		result.Error = &PushError{Message: "remote branch not found", Cause: err}
		return result
	}

	remoteCommit, err := repo.CommitObject(remoteRef.Hash())
	if err != nil {
		result.Error = &PushError{Message: "remote branch not found", Cause: err}
		return result
	}

	backups, err := collectForceResetBackups(repo, vaultDir, preHead, remoteCommit)
	if err != nil {
		result.Error = &PushError{Message: "failed to inspect local changes before reset", Cause: err}
		return result
	}

	w, err := repo.Worktree()
	if err != nil {
		result.Error = &PushError{Message: "could not open worktree", Cause: err}
		return result
	}

	if err := w.Reset(&gogit.ResetOptions{Commit: remoteRef.Hash(), Mode: gogit.HardReset}); err != nil {
		result.Error = &PushError{Message: "reset failed", Cause: err}
		return result
	}

	if err := writeForceResetBackups(vaultDir, DeviceIdentity(vaultDir), backups); err != nil {
		result.Error = &PushError{Message: "reset succeeded but failed to back up discarded local changes", Cause: err}
		return result
	}

	result.Success = true
	if preHead == nil || preHead.Hash != remoteRef.Hash() {
		result.Updated = true
	}
	return result
}

// backupBeforeForceReset preserves the current local version of every tracked
// vault file a hard reset to remoteCommit is about to discard or overwrite —
// both a local commit the remote never received (compared against preHead)
// and a worktree edit that was never committed. It reuses the same
// conflict-copy mechanism and naming as an ordinary failed pull (see
// resolveDivergedConflicts), so ForcePull discards git history but never
// silently destroys unrecoverable vault data: anything that actually differs
// from the post-reset content survives as a
// "<name>.conflict-<device-id>.<ext>" copy the user can recover by hand.
// forceResetBackup is a snapshot of one file's local content, captured
// before a hard reset discards it, together with the repo-relative path it
// belongs to.
type forceResetBackup struct {
	path string
	data []byte
}

// collectForceResetBackups reads the current local content of every tracked
// vault file remoteCommit is about to discard or overwrite — both a local
// commit the remote never received (compared against preHead) and a
// worktree edit that was never committed — skipping any file whose content
// already matches the post-reset state. It must run *before* the hard
// reset: go-git's HardReset removes every worktree file that is not part of
// the target tree, tracked or not, so a conflict copy written before
// resetting would just be deleted again by the same call.
func collectForceResetBackups(repo *gogit.Repository, vaultDir string, preHead, remoteCommit *object.Commit) ([]forceResetBackup, error) {
	paths := make(map[string]bool)
	if preHead != nil {
		changed, err := changedPaths(preHead, remoteCommit)
		if err != nil {
			return nil, err
		}
		for _, p := range changed {
			paths[p] = true
		}
	}

	w, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	status, err := w.Status()
	if err != nil {
		return nil, err
	}
	for path, fileStatus := range status {
		if fileStatus.Staging != gogit.Unmodified || fileStatus.Worktree == gogit.Unmodified {
			continue
		}
		paths[path] = true
	}

	var backups []forceResetBackup
	for path := range paths {
		if !isConflictCandidatePath(path) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(vaultDir, path)) //#nosec G304 -- path derived from git status/diff inside the vault dir
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if committed, ok := committedContent(remoteCommit, path); ok && bytes.Equal(committed, data) {
			continue
		}
		backups = append(backups, forceResetBackup{path: path, data: data})
	}
	return backups, nil
}

// writeForceResetBackups writes the snapshots collected by
// collectForceResetBackups as conflict copies. Must run *after* the hard
// reset has completed (see collectForceResetBackups). Skips a copy whose
// destination already holds identical bytes, the same idempotency rule
// writeConflictCopy applies for an ordinary failed pull.
func writeForceResetBackups(vaultDir, deviceName string, backups []forceResetBackup) error {
	if len(backups) == 0 {
		return nil
	}
	renameConflictsForDevice(vaultDir, deviceName)
	for _, b := range backups {
		ext := filepath.Ext(b.path)
		base := strings.TrimSuffix(b.path, ext)
		conflictName := base + ConflictMarker + deviceName + ext
		conflictPath := filepath.Join(vaultDir, conflictName)
		if existing, err := os.ReadFile(conflictPath); err == nil && bytes.Equal(existing, b.data) { //#nosec G304 -- conflict path derived from the same candidate path
			continue
		}
		if err := os.WriteFile(conflictPath, b.data, 0o600); err != nil {
			return fmt.Errorf("save conflict file %s: %w", conflictName, err)
		}
	}
	return nil
}

// classifyPullFailure turns a pull error into a short, actionable cause. A
// dirty worktree or a diverged history are not by themselves proof of a
// merge conflict (see resolveDivergedConflicts) — this only labels *why*
// the pull itself could not proceed.
func classifyPullFailure(err error) string {
	switch {
	case errors.Is(err, gogit.ErrNonFastForwardUpdate):
		return "pull failed: local and remote history have diverged"
	case errors.Is(err, gogit.ErrUnstagedChanges), errors.Is(err, gogit.ErrWorktreeNotClean):
		return "pull failed: local changes would be overwritten by the incoming update"
	default:
		return "pull failed"
	}
}

// Sync performs a pull followed by an optional push. When force is true, the
// pull is a ForcePull that discards local changes instead of merging.
func Sync(vaultDir string, pushAfter bool, force bool) SyncResult {
	pull := PullWithResult
	if force {
		pull = ForcePull
	}
	result := SyncResult{
		PullResult:  pull(vaultDir),
		PushDone:    false,
		PushSuccess: false,
	}
	if pushAfter && result.Success && result.HasRemote {
		pushResult := PushWithResult(vaultDir)
		result.PushDone = true
		result.PushSuccess = pushResult.Success
	}
	return result
}

// ResolveConflicts handles conflicts after a pull.
func ResolveConflicts(vaultDir string, deviceName string) error {
	// Migrate conflict files that were created under an older hostname-based
	// name of this device so a single device does not leave duplicates behind.
	renameConflictsForDevice(vaultDir, deviceName)
	repo, err := openRepo(vaultDir)
	if err != nil {
		return nil
	}
	w, err := repo.Worktree()
	if err != nil {
		return err
	}
	status, err := w.Status()
	if err != nil {
		return err
	}
	head := headCommit(repo)
	for path, fileStatus := range status {
		if fileStatus.Staging != gogit.Unmodified || fileStatus.Worktree == gogit.Unmodified {
			continue
		}
		if err := preserveConflictCandidate(vaultDir, deviceName, path, head); err != nil {
			return err
		}
	}
	return nil
}

// isConflictCandidatePath reports whether path is one this package ever
// snapshots as a conflict copy: a tracked vault entry or config.yaml, never
// an already-written conflict copy or a protected runtime file.
func isConflictCandidatePath(path string) bool {
	if !strings.HasSuffix(path, ".age") && path != "config.yaml" {
		return false
	}
	if strings.Contains(path, ConflictMarker) {
		return false
	}
	if path == "identity.age" || isProtectedRuntimePath(path) {
		return false
	}
	return true
}

// preserveConflictCandidate writes a conflict copy for path, comparing its
// current on-disk content against baseline to decide whether it actually
// diverged (see writeConflictCopy). Non-candidate paths are silently skipped.
func preserveConflictCandidate(vaultDir, deviceName, path string, baseline *object.Commit) error {
	if !isConflictCandidatePath(path) {
		return nil
	}
	fullPath := filepath.Join(vaultDir, path)
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	conflictName := base + ConflictMarker + deviceName + ext
	conflictPath := filepath.Join(vaultDir, conflictName)
	if err := writeConflictCopy(fullPath, conflictPath, baseline, path); err != nil {
		return fmt.Errorf("save conflict file %s: %w", conflictName, err)
	}
	return nil
}

// resolveDivergedConflicts is the failure-path counterpart to ResolveConflicts:
// it only preserves a file when the fetched remote tip genuinely changed that
// path since the two histories' common ancestor. A file that merely happens
// to be dirty in the worktree — but that the remote never touched — is left
// alone even though the pull failed, because that dirt did not cause the
// failure and is not a conflict (see issue #831).
//
// go-git's own fetch step, run internally by Pull before it attempts any
// merge, updates the "<remoteName>/<branch>" remote-tracking ref regardless
// of whether the merge itself succeeds — that is what makes this comparison
// possible without a second network round trip. preHead must be the local
// HEAD captured *before* Pull was called: a failed pull can still advance
// the local branch ref as a side effect (Pull moves HEAD before Reset checks
// for unstaged changes), so HEAD read after the fact cannot serve as the
// "before" snapshot.
func resolveDivergedConflicts(repo *gogit.Repository, vaultDir, deviceName string, preHead *object.Commit, remoteName string) error {
	renameConflictsForDevice(vaultDir, deviceName)

	if preHead == nil {
		return nil
	}
	head, err := repo.Head()
	if err != nil || !head.Name().IsBranch() {
		return nil
	}
	remoteRef, err := repo.Reference(plumbing.NewRemoteReferenceName(remoteName, head.Name().Short()), true)
	if err != nil {
		return nil
	}
	remoteHead, err := repo.CommitObject(remoteRef.Hash())
	if err != nil || remoteHead.Hash == preHead.Hash {
		return nil
	}

	ancestor := preHead
	if bases, mbErr := preHead.MergeBase(remoteHead); mbErr == nil && len(bases) > 0 {
		ancestor = bases[0]
	}

	changed, err := changedPaths(ancestor, remoteHead)
	if err != nil {
		return err
	}
	for _, path := range changed {
		if err := preserveConflictCandidate(vaultDir, deviceName, path, ancestor); err != nil {
			return err
		}
	}
	return nil
}

// changedPaths returns the file paths whose content differs between two
// commits' trees, deduplicated (a rename touches both a From and a To entry).
func changedPaths(from, to *object.Commit) ([]string, error) {
	fromTree, err := from.Tree()
	if err != nil {
		return nil, err
	}
	toTree, err := to.Tree()
	if err != nil {
		return nil, err
	}
	changes, err := fromTree.Diff(toTree)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(changes))
	paths := make([]string, 0, len(changes))
	for _, ch := range changes {
		name := ch.To.Name
		if name == "" {
			name = ch.From.Name
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		paths = append(paths, name)
	}
	return paths, nil
}

// writeConflictCopy preserves the working-tree content of src as a conflict
// copy at dst — but only when that copy would actually carry information.
// A conflict copy exists to keep the local version of a file that diverged
// from the shared history; writing one whose content is already on disk tells
// the user nothing and only churns the vault. Two cases are therefore skipped:
//
//   - src is byte-identical to the version recorded in HEAD. There is no local
//     divergence to preserve, so there is no conflict — git's status can still
//     report the file as modified (a mode change, a stale index entry), which
//     is how a vault ended up with a fresh conflict copy on every single CLI
//     invocation.
//   - dst already holds byte-identical content. Rewriting it would recreate
//     the same bytes under the same name and only move the mtime.
//
// A file that no longer exists in the working tree is skipped as well: there
// is nothing to snapshot, and failing here would abort the whole sweep and
// leave the remaining files unprotected.
func writeConflictCopy(src, dst string, head *object.Commit, repoPath string) error {
	data, err := os.ReadFile(src) //#nosec G304 -- path derived from git status inside the vault dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if committed, ok := committedContent(head, repoPath); ok && bytes.Equal(committed, data) {
		return nil
	}
	// Read separately rather than in the if-init clause: gosec does not
	// associate a //#nosec annotation with a call inside an init statement.
	existing, err := os.ReadFile(dst) //#nosec G304 -- conflict path derived from the same git status entry
	if err == nil && bytes.Equal(existing, data) {
		return nil
	}
	return os.WriteFile(dst, data, 0o600)
}

// headCommit returns the commit HEAD points at, or nil when the repository has
// no commits yet (or HEAD cannot be resolved).
func headCommit(repo *gogit.Repository) *object.Commit {
	ref, err := repo.Head()
	if err != nil {
		return nil
	}
	commit, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return nil
	}
	return commit
}

// committedContent returns the content that repoPath (a slash-separated path
// relative to the repository root) has in commit, and whether it could be read.
func committedContent(commit *object.Commit, repoPath string) ([]byte, bool) {
	if commit == nil {
		return nil, false
	}
	f, err := commit.File(repoPath)
	if err != nil {
		return nil, false
	}
	reader, err := f.Reader()
	if err != nil {
		return nil, false
	}
	defer func() { _ = reader.Close() }()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, false
	}
	return data, true
}

// LastSyncTime returns the time of the last sync operation.
func LastSyncTime(vaultDir string) (time.Time, error) {
	markerPath := filepath.Join(vaultDir, ".git", "symvault-last-sync")
	data, err := os.ReadFile(markerPath) //#nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return time.Time{}, nil
	}
	return t, nil
}

// SetLastSyncTime writes the current time as the last sync timestamp.
func SetLastSyncTime(vaultDir string) error {
	markerPath := filepath.Join(vaultDir, ".git", "symvault-last-sync")
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(markerPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
}

// ShouldAutoPull checks if an auto-pull should be performed.
func ShouldAutoPull(vaultDir string, interval time.Duration) bool {
	t, err := LastSyncTime(vaultDir)
	if err != nil || t.IsZero() {
		return true
	}
	return time.Since(t) > interval
}
