package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
)

func hasStagedChanges(status gogit.Status) bool {
	for _, fileStatus := range status {
		if fileStatus.Staging != gogit.Unmodified && fileStatus.Staging != gogit.Untracked {
			return true
		}
	}
	return false
}

func hasStagedChangesForPaths(repo *gogit.Repository, paths []string) bool {
	head, err := repo.Head()
	if err != nil {
		return true
	}
	headCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return true
	}
	headTree, err := headCommit.Tree()
	if err != nil {
		return true
	}
	idx, err := repo.Storer.Index()
	if err != nil {
		return true
	}
	for _, path := range paths {
		normalized := filepath.ToSlash(filepath.Clean(path))
		idxEntry, err := idx.Entry(normalized)
		if err != nil {
			return true
		}
		headEntry, err := headTree.FindEntry(normalized)
		if err != nil {
			return true
		}
		if headEntry == nil {
			return true
		}
		if idxEntry.Hash != headEntry.Hash {
			return true
		}
	}
	return false
}

func stageAffectedPaths(repo *gogit.Repository, w *gogit.Worktree, vaultDir string, paths []string) error {
	seen := make(map[string]bool, len(paths)+1)
	for _, path := range append(paths, ".gitignore") {
		normalized, ok, err := normalizeAffectedPath(path)
		if err != nil {
			return err
		}
		if !ok || seen[normalized] || isProtectedRuntimePath(normalized) {
			continue
		}
		seen[normalized] = true
		fullPath := filepath.Join(vaultDir, filepath.FromSlash(normalized))
		if _, err := os.Lstat(fullPath); err != nil {
			if os.IsNotExist(err) {
				if removeErr := removeFromIndex(repo, normalized); removeErr != nil {
					return removeErr
				}
				continue
			}
			return err
		}
		if err := w.AddWithOptions(&gogit.AddOptions{Path: normalized, SkipStatus: true}); err != nil {
			return err
		}
	}
	return nil
}

func normalizeAffectedPath(path string) (string, bool, error) {
	if filepath.IsAbs(path) {
		return "", false, fmt.Errorf("affected path %q must be relative", path)
	}
	normalized := filepath.ToSlash(filepath.Clean(path))
	if normalized == "." || normalized == "" {
		return "", false, nil
	}
	if normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", false, fmt.Errorf("affected path %q escapes repository", path)
	}
	return normalized, true, nil
}

func removeFromIndex(repo *gogit.Repository, path string) error {
	idx, err := repo.Storer.Index()
	if err != nil {
		return err
	}
	if _, err := idx.Remove(path); err != nil {
		return nil
	}
	return repo.Storer.SetIndex(idx)
}

func unstageProtectedRuntimeArtifacts(repo *gogit.Repository, w *gogit.Worktree, status gogit.Status) ([]string, error) {
	var staged []string
	for path, fileStatus := range status {
		if !isProtectedRuntimePath(path) {
			continue
		}
		if fileStatus.Staging != gogit.Unmodified && fileStatus.Staging != gogit.Untracked {
			staged = append(staged, filepath.ToSlash(path))
		}
	}
	if len(staged) == 0 {
		return nil, nil
	}
	if _, err := repo.Head(); err == nil {
		return staged, w.Reset(&gogit.ResetOptions{Mode: gogit.MixedReset, Files: staged})
	}
	idx, err := repo.Storer.Index()
	if err != nil {
		return nil, err
	}
	for _, path := range staged {
		_, _ = idx.Remove(path)
	}
	return staged, repo.Storer.SetIndex(idx)
}

func isProtectedRuntimePath(path string) bool {
	normalized := filepath.ToSlash(filepath.Clean(path))
	for _, protected := range protectedRuntimePaths {
		if normalized == protected {
			return true
		}
		if strings.HasPrefix(normalized, protected+".") {
			return true
		}
	}
	return false
}
