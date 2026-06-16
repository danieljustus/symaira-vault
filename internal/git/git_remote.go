package git

import (
	"errors"
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
)

// AddRemote adds a new remote to the vault's git repository.
func AddRemote(vaultDir, remoteName, remoteURL string) error {
	if vaultDir == "" {
		return fmt.Errorf("empty vault dir")
	}
	repo, err := openRepo(vaultDir)
	if err != nil {
		return fmt.Errorf("cannot open vault git repository: %w", err)
	}
	existing, err := repo.Remote(remoteName)
	if err == nil && existing != nil {
		return fmt.Errorf("remote %q already exists in vault git repository", remoteName)
	}
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: remoteName,
		URLs: []string{remoteURL},
	})
	if err != nil {
		return fmt.Errorf("cannot create remote %q: %w", remoteName, err)
	}
	return nil
}

// HasRemote checks whether a remote with the given name exists.
func HasRemote(vaultDir, remoteName string) (bool, error) {
	if vaultDir == "" {
		return false, nil
	}
	repo, err := openRepo(vaultDir)
	if err != nil {
		return false, nil
	}
	_, err = repo.Remote(remoteName)
	if err != nil {
		if errors.Is(err, gogit.ErrRemoteNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("cannot look up remote %q: %w", remoteName, err)
	}
	return true, nil
}

// GetRemoteURL returns the first URL of the named remote.
func GetRemoteURL(vaultDir, remoteName string) (string, error) {
	if vaultDir == "" {
		return "", nil
	}
	repo, err := openRepo(vaultDir)
	if err != nil {
		return "", nil
	}
	remote, err := repo.Remote(remoteName)
	if err != nil {
		if errors.Is(err, gogit.ErrRemoteNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("cannot get remote %q: %w", remoteName, err)
	}
	urls := remote.Config().URLs
	if len(urls) == 0 {
		return "", nil
	}
	return urls[0], nil
}
