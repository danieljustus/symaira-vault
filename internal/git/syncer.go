package git

import (
	"github.com/danieljustus/symaira-vault/internal/vault"
)

// Syncer implements vault.GitSyncer using local git operations.
type Syncer struct{}

// NewSyncer returns a new Syncer instance.
func NewSyncer() *Syncer {
	return &Syncer{}
}

// CreateGitignore creates or updates the .gitignore file in the vault directory.
func (s *Syncer) CreateGitignore(vaultDir string) error {
	return CreateGitignore(vaultDir)
}

// AutoCommitAndPushWithOptions creates a commit and optionally pushes to the remote.
func (s *Syncer) AutoCommitAndPushWithOptions(vaultDir string, opts vault.GitCommitOptions, autoPush bool) error {
	return AutoCommitAndPushWithOptions(vaultDir, CommitOptions{
		Message:       opts.Message,
		Template:      opts.Template,
		Author:        opts.Author,
		Email:         opts.Email,
		AffectedPaths: opts.AffectedPaths,
	}, autoPush)
}
