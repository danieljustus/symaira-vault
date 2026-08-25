package vault

import (
	"sync"
)

// GitCommitOptions holds options for an automatic git commit.
type GitCommitOptions struct {
	Message       string
	Template      string
	Author        string
	Email         string
	AffectedPaths []string
}

// GitSyncer abstracts git version control operations for a vault.
type GitSyncer interface {
	CreateGitignore(vaultDir string) error
	AutoCommitAndPushWithOptions(vaultDir string, opts GitCommitOptions, autoPush bool) error
}

var (
	gitSyncerMu      sync.RWMutex
	defaultGitSyncer GitSyncer
)

// SetDefaultGitSyncer configures the default GitSyncer used by vaults when none is explicitly set on the Vault instance.
func SetDefaultGitSyncer(syncer GitSyncer) {
	gitSyncerMu.Lock()
	defer gitSyncerMu.Unlock()
	defaultGitSyncer = syncer
}

func (v *Vault) getGitSyncer() GitSyncer {
	if v != nil && v.GitSyncer != nil {
		return v.GitSyncer
	}
	gitSyncerMu.RLock()
	defer gitSyncerMu.RUnlock()
	return defaultGitSyncer
}
