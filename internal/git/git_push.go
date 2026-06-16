package git

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

func isSSHURL(url string) bool {
	return strings.HasPrefix(url, "git@") || strings.HasPrefix(url, "ssh://")
}

func getSSHAuth() (*ssh.PublicKeysCallback, error) {
	auth, err := ssh.NewSSHAgentAuth("git")
	if err != nil {
		return nil, err
	}
	khFile := os.Getenv("SSH_KNOWN_HOSTS")
	if khFile == "" {
		khFile = filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
	}
	cb, err := ssh.NewKnownHostsCallback(khFile)
	if err != nil {
		return nil, fmt.Errorf("cannot load known_hosts file %q: %w. "+
			"Set SSH_KNOWN_HOSTS or add host keys with: ssh-keyscan <host> >> %s", khFile, err, khFile)
	}
	auth.HostKeyCallback = cb
	return auth, nil
}

func pushWithSSHAuth(repo *gogit.Repository, remoteURL string) error {
	opts := &gogit.PushOptions{RemoteName: "origin"}
	if isSSHURL(remoteURL) {
		auth, err := getSSHAuth()
		if err == nil {
			opts.Auth = auth
		}
	}
	return repo.Push(opts)
}

// PushWithResult pushes to origin and returns detailed result
func PushWithResult(vaultDir string) PushResult {
	result := PushResult{Success: false, Skipped: false}

	repo, err := openRepo(vaultDir)
	if err != nil {
		result.Skipped = true
		return result
	}

	remotes, err := repo.Remotes()
	if err != nil {
		result.Error = &PushError{Message: "failed to list remotes", Cause: err}
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
		result.Error = &PushError{Message: "no 'origin' remote configured"}
		return result
	}

	err = pushWithSSHAuth(repo, originRemote.Config().URLs[0])
	if err == nil {
		result.Success = true
		return result
	}

	if errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		result.Success = true
		result.Skipped = true
		return result
	}

	if errors.Is(err, gogit.ErrRemoteNotFound) || errors.Is(err, gogit.ErrRepositoryNotExists) {
		result.Skipped = true
		result.Error = &PushError{Message: "remote not found", Cause: err}
		return result
	}

	result.Error = classifyPushError(err)
	return result
}

func classifyPushError(err error) *PushError {
	if err == nil {
		return nil
	}
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "known_hosts"),
		strings.Contains(errStr, "known hosts"),
		strings.Contains(errStr, "SSH_KNOWN_HOSTS"):
		return &PushError{
			Message: "SSH configuration error - please check known_hosts or SSH_KNOWN_HOSTS",
			Cause:   err,
		}
	case strings.Contains(errStr, "authentication"),
		strings.Contains(errStr, "credentials"),
		strings.Contains(errStr, "401"),
		strings.Contains(errStr, "403"):
		return &PushError{
			Message: "authentication failed - please check your credentials",
			Cause:   err,
		}
	case strings.Contains(errStr, "connection"),
		strings.Contains(errStr, "timeout"),
		strings.Contains(errStr, "refused"):
		return &PushError{
			Message: "network error - please check your connection",
			Cause:   err,
		}
	default:
		return &PushError{
			Message: "push failed",
			Cause:   err,
		}
	}
}

func Push(vaultDir string) error {
	result := PushWithResult(vaultDir)
	if result.Error != nil && !result.Skipped {
		return result.Error
	}
	return nil
}
