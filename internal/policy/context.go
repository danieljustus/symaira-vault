package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ContextProvider gathers runtime context for policy evaluation.
type ContextProvider struct {
	workingDir string
	gitBranch  string
}

// NewContextProvider creates a new context provider.
func NewContextProvider() *ContextProvider {
	return &ContextProvider{}
}

// BuildContext builds an evaluation context for the given request parameters.
func (cp *ContextProvider) BuildContext(agentID, path, actionType string, tags []string) EvalContext {
	ctx := EvalContext{
		AgentID:    agentID,
		Path:       path,
		Tags:       tags,
		ActionType: actionType,
		Now:        time.Now(),
		EnvVars:    make(map[string]string),
	}

	ctx.WorkingDir = cp.getWorkingDir()
	ctx.EnvVars["GIT_BRANCH"] = cp.getGitBranch(ctx.WorkingDir)
	ctx.EnvVars["HOME"] = cp.getHomeDir()

	return ctx
}

func (cp *ContextProvider) getWorkingDir() string {
	if cp.workingDir != "" {
		return cp.workingDir
	}
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return dir
}

func (cp *ContextProvider) getGitBranch(workingDir string) string {
	if cp.gitBranch != "" {
		return cp.gitBranch
	}

	// Try to get git branch from working directory
	if workingDir == "" {
		return ""
	}

	cmd := exec.Command("git", "-C", workingDir, "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Env = os.Environ() // TODO: filter to safe subset — git may need GIT_CONFIG_PARAMETERS, GIT_SSH_COMMAND, etc.
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	branch := strings.TrimSpace(string(out))
	if branch == "HEAD" {
		return ""
	}
	return branch
}

func (cp *ContextProvider) getHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// SetWorkingDir overrides the working directory (useful for testing).
func (cp *ContextProvider) SetWorkingDir(dir string) {
	cp.workingDir = dir
}

// SetGitBranch overrides the git branch (useful for testing).
func (cp *ContextProvider) SetGitBranch(branch string) {
	cp.gitBranch = branch
}

// DetectProjectContext attempts to detect project context from the working directory.
// It looks for common project markers like go.mod, package.json, Cargo.toml, etc.
func DetectProjectContext(workingDir string) string {
	if workingDir == "" {
		return ""
	}

	markers := []string{
		"go.mod",
		"package.json",
		"Cargo.toml",
		"pyproject.toml",
		"setup.py",
		"pom.xml",
		"build.gradle",
		"CMakeLists.txt",
		"Makefile",
	}

	dir := workingDir
	for {
		for _, marker := range markers {
			path := filepath.Join(dir, marker)
			if _, err := os.Stat(path); err == nil {
				return filepath.Base(dir)
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}
