package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// PushError represents an error that occurred during push
type PushError struct {
	Cause   error
	Message string
}

func (e *PushError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("push failed: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("push failed: %s", e.Message)
}

func (e *PushError) Unwrap() error {
	return e.Cause
}

type PushResult struct {
	Error     error
	RemoteURL string
	Success   bool
	Skipped   bool
	HasRemote bool
}

type PullResult struct {
	Error     error
	RemoteURL string
	Success   bool
	Skipped   bool
	HasRemote bool
	Conflicts []string
}

type SyncResult struct {
	PullResult
	PushDone    bool
	PushSuccess bool
}

type CommitOptions struct {
	Message       string
	Template      string
	Author        string
	Email         string
	AffectedPaths []string
}

const DefaultCommitTemplate = "Update from Symaira Vault"

const DefaultGitignoreContent = `# Symaira Vault vault - ignore sensitive files
identity.age
*.key
*.pem
# Ignore Symaira Vault runtime artifacts
mcp-token
mcp-tokens.json
.runtime-port
# Ignore OS files
.DS_Store
Thumbs.db
# Ignore IDE files
.idea/
.vscode/
*.swp
*.swo
*~
`

var protectedRuntimePaths = []string{
	"mcp-token",
	"mcp-tokens.json",
	".runtime-port",
}

type Commit struct {
	Hash    string
	Author  string
	Date    time.Time
	Message string
}

func Init(vaultDir string) error {
	if vaultDir == "" {
		return nil
	}
	if _, err := openRepo(vaultDir); err == nil {
		return nil
	}
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return err
	}
	_, err := gogit.PlainInit(vaultDir, false)
	return err
}

func CreateGitignore(vaultDir string) error {
	if vaultDir == "" {
		return nil
	}
	cleanVaultDir := filepath.Clean(vaultDir)
	gitignorePath := filepath.Join(cleanVaultDir, ".gitignore")
	cleanGitignorePath := filepath.Clean(gitignorePath)
	if !strings.HasPrefix(cleanGitignorePath, cleanVaultDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid gitignore path: outside vault directory")
	}
	content, err := os.ReadFile(cleanGitignorePath) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(cleanGitignorePath, []byte(DefaultGitignoreContent), 0o600)
		}
		return err
	}
	updated := appendMissingGitignoreEntries(string(content), DefaultGitignoreContent)
	if updated == string(content) {
		return nil
	}
	return os.WriteFile(cleanGitignorePath, []byte(updated), 0o600) //#nosec G703
}

func appendMissingGitignoreEntries(current string, defaults string) string {
	seen := make(map[string]bool)
	for _, line := range strings.Split(current, "\n") {
		seen[strings.TrimSpace(line)] = true
	}
	var missing []string
	for _, line := range strings.Split(defaults, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || seen[trimmed] {
			continue
		}
		missing = append(missing, trimmed)
		seen[trimmed] = true
	}
	if len(missing) == 0 {
		return current
	}
	var b strings.Builder
	b.WriteString(current)
	if current != "" && !strings.HasSuffix(current, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("# Symaira Vault runtime artifacts\n")
	for _, line := range missing {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

// AutoCommitWithOptions performs an auto-commit with the given options
func AutoCommitWithOptions(vaultDir string, opts CommitOptions) error {
	repo, err := openRepo(vaultDir)
	if err != nil {
		return nil
	}
	w, err := repo.Worktree()
	if err != nil {
		return nil
	}
	if gitignoreErr := CreateGitignore(vaultDir); gitignoreErr != nil {
		return gitignoreErr
	}
	if len(opts.AffectedPaths) > 0 {
		if addErr := stageAffectedPaths(repo, w, vaultDir, opts.AffectedPaths); addErr != nil {
			return addErr
		}
		if !hasStagedChangesForPaths(repo, opts.AffectedPaths) {
			return nil
		}
	} else {
		if addErr := w.AddWithOptions(&gogit.AddOptions{All: true}); addErr != nil {
			return addErr
		}
		status, statusErr := w.Status()
		if statusErr != nil {
			return nil
		}
		unstaged, unstageErr := unstageProtectedRuntimeArtifacts(repo, w, status)
		if unstageErr != nil {
			return unstageErr
		}
		for _, path := range unstaged {
			fileStatus := status[path]
			fileStatus.Staging = gogit.Unmodified
			status[path] = fileStatus
		}
		if !hasStagedChanges(status) {
			return nil
		}
	}
	message := opts.Message
	if message == "" {
		message = opts.Template
	}
	if message == "" {
		message = DefaultCommitTemplate
	}
	authorName := opts.Author
	if authorName == "" {
		authorName = gitConfigUser("user.name")
	}
	authorEmail := opts.Email
	if authorEmail == "" {
		authorEmail = gitConfigUser("user.email")
	}
	if authorName == "" {
		authorName = "Symaira Vault"
	}
	if authorEmail == "" {
		authorEmail = "symvault@example.com"
	}
	_, err = w.Commit(message, &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  authorName,
			Email: authorEmail,
			When:  time.Now(),
		},
	})
	return err
}

func AutoCommit(vaultDir string, message string) error {
	return AutoCommitWithOptions(vaultDir, CommitOptions{Message: message})
}

func AutoCommitAndPush(vaultDir string, message string, autoPush bool) error {
	return AutoCommitAndPushWithOptions(vaultDir, CommitOptions{Message: message}, autoPush)
}

func AutoCommitAndPushWithOptions(vaultDir string, opts CommitOptions, autoPush bool) error {
	if err := AutoCommitWithOptions(vaultDir, opts); err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}
	if autoPush {
		result := PushWithResult(vaultDir)
		if result.Error != nil {
			if result.Skipped {
				return nil
			}
			return fmt.Errorf("push failed: %w", result.Error)
		}
	}
	return nil
}
