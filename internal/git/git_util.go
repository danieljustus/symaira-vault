package git

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v5/osfs"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

var errStopIter = errors.New("stop iteration")

func Log(vaultDir string, path string, limit int) ([]Commit, error) {
	repo, err := openRepo(vaultDir)
	if err != nil {
		return []Commit{}, nil
	}
	var opts gogit.LogOptions
	if path != "" {
		rel := filepath.ToSlash(path)
		opts.FileName = &rel
	}
	iter, err := repo.Log(&opts)
	if err != nil {
		if errors.Is(err, gogit.ErrRepositoryNotExists) {
			return []Commit{}, nil
		}
		return nil, err
	}
	defer iter.Close()
	commits := make([]Commit, 0)
	err = iter.ForEach(func(c *object.Commit) error {
		commits = append(commits, Commit{
			Hash:    c.Hash.String(),
			Author:  formatAuthor(c.Author),
			Date:    c.Author.When,
			Message: c.Message,
		})
		if limit > 0 && len(commits) >= limit {
			return errStopIter
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopIter) {
		return nil, err
	}
	if limit > 0 && len(commits) > limit {
		commits = commits[:limit]
	}
	return commits, nil
}

func openRepo(vaultDir string) (*gogit.Repository, error) {
	if vaultDir == "" {
		return nil, fmt.Errorf("empty vault dir")
	}
	// Fast path: a normal in-tree .git repository.
	if repo, err := gogit.PlainOpen(vaultDir); err == nil {
		return repo, nil
	}
	// Filesystem-synced vaults (e.g. iCloud Drive) keep the .git directory
	// outside the synced folder so it is never replicated. Open it through the
	// deterministic external path with an explicit worktree; this requires no
	// .git file inside the vault.
	if IsGitExternal(vaultDir) {
		ext := ExternalGitDirPath(vaultDir)
		storage := filesystem.NewStorage(osfs.New(ext), cache.NewObjectLRUDefault())
		if repo, err := gogit.Open(storage, osfs.New(vaultDir)); err == nil {
			return repo, nil
		}
	}
	return nil, gogit.ErrRepositoryNotExists
}

func formatAuthor(sig object.Signature) string {
	if sig.Email == "" {
		return sig.Name
	}
	if sig.Name == "" {
		return sig.Email
	}
	return fmt.Sprintf("%s <%s>", sig.Name, sig.Email)
}

// gitConfigUser resolves identity from the vault repository rather than the
// caller's working directory, so an unrelated project's local Git config
// cannot change metadata on vault commits.
func gitConfigUser(vaultDir, key string) string {
	out, err := exec.Command("git", "-C", vaultDir, "config", "--get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
