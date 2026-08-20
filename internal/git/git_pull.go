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
	"github.com/go-git/go-git/v5/plumbing/object"
)

func pullWithSSHAuth(w *gogit.Worktree, remoteURL string) error {
	opts := &gogit.PullOptions{RemoteName: "origin"}
	if isSSHURL(remoteURL) {
		auth, err := getSSHAuth()
		if err == nil {
			opts.Auth = auth
		}
	}
	return w.Pull(opts)
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
		result.Error = &PushError{Message: "failed to list remotes", Cause: listErr}
		return result
	}

	var originRemote *gogit.Remote
	for _, r := range remotes {
		if r.Config().Name == "origin" {
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

	pullErr := pullWithSSHAuth(w, originRemote.Config().URLs[0])
	if pullErr == nil || errors.Is(pullErr, gogit.NoErrAlreadyUpToDate) {
		result.Success = true
		return result
	}

	if errors.Is(pullErr, gogit.ErrRemoteNotFound) || errors.Is(pullErr, gogit.ErrRepositoryNotExists) {
		result.Skipped = true
		return result
	}

	if IsOfflineError(pullErr) {
		result.Error = &PushError{
			Message: "network error - please check your connection",
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
	resolveErr := ResolveConflicts(vaultDir, deviceName)
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
		Message: "pull failed",
		Cause:   pullErr,
	}
	return result
}

// Sync performs a pull followed by an optional push.
func Sync(vaultDir string, pushAfter bool) SyncResult {
	result := SyncResult{
		PullResult:  PullWithResult(vaultDir),
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
		if !strings.HasSuffix(path, ".age") && path != "config.yaml" {
			continue
		}
		if strings.Contains(path, ConflictMarker) {
			continue
		}
		fullPath := filepath.Join(vaultDir, path)
		if path == "identity.age" || isProtectedRuntimePath(path) {
			continue
		}
		ext := filepath.Ext(path)
		base := strings.TrimSuffix(path, ext)
		conflictName := base + ConflictMarker + deviceName + ext
		conflictPath := filepath.Join(vaultDir, conflictName)
		if err := writeConflictCopy(fullPath, conflictPath, head, path); err != nil {
			return fmt.Errorf("save conflict file %s: %w", conflictName, err)
		}
	}
	return nil
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
	if existing, err := os.ReadFile(dst); err == nil && bytes.Equal(existing, data) { //#nosec G304 -- conflict path derived from the same git status entry
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
