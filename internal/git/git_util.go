package git

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
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
	repo, err := gogit.PlainOpen(vaultDir)
	if err != nil {
		return nil, err
	}
	return repo, nil
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

func gitConfigUser(key string) string {
	out, err := exec.Command("git", "config", "--get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
