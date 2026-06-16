package git

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
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

	if isOfflineError(pullErr) {
		result.Error = &PushError{
			Message: "network error - please check your connection",
			Cause:   pullErr,
		}
		return result
	}

	errStr := pullErr.Error()
	if strings.Contains(errStr, "authentication") || strings.Contains(errStr, "credentials") ||
		strings.Contains(errStr, "401") || strings.Contains(errStr, "403") {
		result.Error = &PushError{
			Message: "authentication failed - please check your credentials",
			Cause:   pullErr,
		}
		return result
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	resolveErr := ResolveConflicts(vaultDir, hostname)
	if resolveErr == nil {
		w2, wtErr := repo.Worktree()
		if wtErr == nil {
			if s, _ := w2.Status(); s != nil {
				for path := range s {
					if strings.Contains(path, ".conflict-") {
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
func ResolveConflicts(vaultDir string, hostname string) error {
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
	for path, fileStatus := range status {
		if fileStatus.Staging != gogit.Unmodified || fileStatus.Worktree == gogit.Unmodified {
			continue
		}
		if !strings.HasSuffix(path, ".age") && path != "config.yaml" {
			continue
		}
		if strings.Contains(path, ".conflict-") {
			continue
		}
		fullPath := filepath.Join(vaultDir, path)
		if path == "identity.age" || isProtectedRuntimePath(path) {
			continue
		}
		ext := filepath.Ext(path)
		base := strings.TrimSuffix(path, ext)
		conflictName := fmt.Sprintf("%s.conflict-%s%s", base, hostname, ext)
		conflictPath := filepath.Join(vaultDir, conflictName)
		if err := copyFile(fullPath, conflictPath); err != nil {
			return fmt.Errorf("save conflict file %s: %w", conflictName, err)
		}
	}
	return nil
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

func isOfflineError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "refused") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "network") ||
		strings.Contains(errStr, "TLS") ||
		strings.Contains(errStr, "EOF")
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src) //#nosec G304
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}
