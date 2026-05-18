// Package git provides Git integration for OpenPass vaults.
package git

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
)

var errStopIter = errors.New("stop iteration")

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

// PushResult represents the result of a push operation
type PushResult struct {
	Error     error
	RemoteURL string
	Success   bool
	Skipped   bool
	HasRemote bool
}

// PullResult represents the result of a pull operation
type PullResult struct {
	Error     error
	RemoteURL string
	Success   bool
	Skipped   bool
	HasRemote bool
	Conflicts []string
}

// SyncResult represents the result of a sync (pull + push) operation
type SyncResult struct {
	PullResult
	PushDone    bool
	PushSuccess bool
}

// CommitOptions holds options for committing
type CommitOptions struct {
	Message  string
	Template string
	Author   string
	Email    string
}

// DefaultCommitTemplate is the default commit message template
const DefaultCommitTemplate = "Update from OpenPass"

// DefaultGitignoreContent is the default .gitignore content for OpenPass vaults
const DefaultGitignoreContent = `# OpenPass vault - ignore sensitive files
identity.age
*.key
*.pem
# Ignore OpenPass runtime artifacts
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

// CreateGitignore creates a .gitignore file in the vault directory
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

	content, err := os.ReadFile(cleanGitignorePath) //nolint:gosec // path is validated above
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
	return os.WriteFile(cleanGitignorePath, []byte(updated), 0o600) //#nosec G703 -- path validated above: cleaned and checked to be within vault dir
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

	if addErr := w.AddWithOptions(&gogit.AddOptions{All: true}); addErr != nil {
		return addErr
	}

	status, statusErr := w.Status()
	if statusErr != nil {
		return nil
	}
	if unstageErr := unstageProtectedRuntimeArtifacts(repo, w, status); unstageErr != nil {
		return unstageErr
	}

	status, statusErr = w.Status()
	if statusErr != nil {
		return nil
	}
	if !hasStagedChanges(status) {
		return nil
	}

	// Determine commit message
	message := opts.Message
	if message == "" {
		message = opts.Template
	}
	if message == "" {
		message = DefaultCommitTemplate
	}

	// Determine author
	authorName := opts.Author
	if authorName == "" {
		authorName = "OpenPass"
	}
	authorEmail := opts.Email
	if authorEmail == "" {
		authorEmail = "openpass@example.com"
	}

	_, err = w.Commit(message, &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  authorName,
			Email: authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return err
	}

	return nil
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
	b.WriteString("# OpenPass runtime artifacts\n")
	for _, line := range missing {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func hasStagedChanges(status gogit.Status) bool {
	for _, fileStatus := range status {
		if fileStatus.Staging != gogit.Unmodified && fileStatus.Staging != gogit.Untracked {
			return true
		}
	}
	return false
}

func unstageProtectedRuntimeArtifacts(repo *gogit.Repository, w *gogit.Worktree, status gogit.Status) error {
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
		return nil
	}

	if _, err := repo.Head(); err == nil {
		return w.Reset(&gogit.ResetOptions{Mode: gogit.MixedReset, Files: staged})
	}

	idx, err := repo.Storer.Index()
	if err != nil {
		return err
	}
	for _, path := range staged {
		_, _ = idx.Remove(path)
	}
	return repo.Storer.SetIndex(idx)
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

// AutoCommit performs a simple auto-commit with the given message
func AutoCommit(vaultDir string, message string) error {
	return AutoCommitWithOptions(vaultDir, CommitOptions{Message: message})
}

// isSSHURL returns true if the remote URL uses SSH protocol (git@ or ssh://).
func isSSHURL(url string) bool {
	return strings.HasPrefix(url, "git@") || strings.HasPrefix(url, "ssh://")
}

// getSSHAuth creates an SSH agent auth method with known_hosts verification.
// It checks SSH_KNOWN_HOSTS first, then falls back to ~/.ssh/known_hosts.
// Returns an error if neither is available — callers handle this gracefully.
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

// pushWithSSHAuth performs a push with SSH auth when the remote uses SSH protocol.
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

// pullWithSSHAuth performs a pull with SSH auth when the remote uses SSH protocol.
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

// PushWithResult pushes to origin and returns detailed result
func PushWithResult(vaultDir string) PushResult {
	result := PushResult{Success: false, Skipped: false}

	repo, err := openRepo(vaultDir)
	if err != nil {
		result.Skipped = true
		return result
	}

	// Check if remote exists
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

// AutoCommitAndPush performs auto-commit and optionally auto-push
func AutoCommitAndPush(vaultDir string, message string, autoPush bool) error {
	// Perform commit
	if err := AutoCommit(vaultDir, message); err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}

	// Perform push if enabled
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

func Push(vaultDir string) error {
	result := PushWithResult(vaultDir)
	if result.Error != nil && !result.Skipped {
		return result.Error
	}
	return nil
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

	// Check if remote exists
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

	// Check for authentication errors
	errStr := pullErr.Error()
	if strings.Contains(errStr, "authentication") || strings.Contains(errStr, "credentials") ||
		strings.Contains(errStr, "401") || strings.Contains(errStr, "403") {
		result.Error = &PushError{
			Message: "authentication failed - please check your credentials",
			Cause:   pullErr,
		}
		return result
	}

	// Auto-resolve conflicts: save local changes as .conflict-<hostname> variants
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

// ResolveConflicts handles conflicts after a pull by renaming local conflicting
// files to .conflict-<hostname> variants. This implements Last-Write-Wins strategy
// where remote changes are kept and local changes are preserved as conflict files.
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

		// Only handle modified .age and config files
		if !strings.HasSuffix(path, ".age") && path != "config.yaml" {
			continue
		}
		// Skip conflict files themselves
		if strings.Contains(path, ".conflict-") {
			continue
		}

		fullPath := filepath.Join(vaultDir, path)

		// Skip identity.age and runtime artifacts
		if path == "identity.age" || isProtectedRuntimePath(path) {
			continue
		}

		// Create conflict backup name
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
// It reads the timestamp from a marker file in the vault's .git directory.
func LastSyncTime(vaultDir string) (time.Time, error) {
	markerPath := filepath.Join(vaultDir, ".git", "openpass-last-sync")
	data, err := os.ReadFile(markerPath) //#nosec G304 -- vaultDir is not user input
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
	markerPath := filepath.Join(vaultDir, ".git", "openpass-last-sync")
	if err := os.MkdirAll(filepath.Dir(markerPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(markerPath, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
}

// ShouldAutoPull checks if an auto-pull should be performed based on the configured
// interval. Returns true if the last pull was longer than interval ago or if no
// pull has been recorded.
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
	data, err := os.ReadFile(src) //#nosec G304 -- both paths are constructed internally
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

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

// AddRemote adds a new remote to the vault's git repository.
// Returns an error if the repository cannot be opened or the remote cannot be created.
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

// HasRemote checks whether a remote with the given name exists in the vault's git repository.
// Returns false without error if the vault directory is empty or the repository doesn't exist.
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

// GetRemoteURL returns the first URL of the named remote in the vault's git repository.
// Returns an empty string without error if the remote doesn't exist or the vault isn't a git repo.
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

var _ = config.RemoteConfig{}
