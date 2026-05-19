package health

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danieljustus/OpenPass/internal/git"
)

func checkGitRepo(vaultDir string, _ Options) Result {
	r := Result{ID: "git.repo", Name: "Git repository"}
	r.Fixable = true
	r.Fix = func() error {
		if FixDryRun {
			return nil
		}
		return git.Init(vaultDir)
	}
	gitDir := filepath.Join(vaultDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		r.Status = StatusOK
		r.Message = ".git directory present"
	} else {
		r.Status = StatusWarn
		r.Message = "no git repository in vault directory"
		r.Hint = "run `openpass git init` to enable version history and sync"
	}
	return r
}

func checkGitRemote(vaultDir string, _ Options) Result {
	r := Result{ID: "git.remote", Name: "Git remote"}
	has, err := git.HasRemote(vaultDir, "origin")
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot determine git remote: " + err.Error()
		return r
	}
	if has {
		r.Status = StatusOK
		r.Message = "remote 'origin' configured"
	} else {
		r.Status = StatusWarn
		r.Message = "no remote 'origin' — vault is local-only"
		r.Hint = "run `openpass git remote add origin <url>` to enable sync"
	}
	return r
}

func checkGitignoreProtects(vaultDir string, _ Options) Result {
	r := Result{ID: "git.gitignore.protects", Name: ".gitignore protects sensitive files"}
	r.Fixable = true
	r.Fix = func() error {
		if FixDryRun {
			return nil
		}
		gitignorePath := filepath.Join(vaultDir, ".gitignore")
		var existing []string
		// #nosec G304 -- vaultDir is controlled
		if data, err := os.ReadFile(gitignorePath); err == nil {
			existing = strings.Split(strings.TrimSpace(string(data)), "\n")
		}
		required := []string{"identity.age", "mcp-token", "mcp-tokens.json"}
		var toAdd []string
		for _, entry := range required {
			found := false
			for _, e := range existing {
				if strings.TrimSpace(e) == entry {
					found = true
					break
				}
			}
			if !found {
				toAdd = append(toAdd, entry)
			}
		}
		if len(toAdd) == 0 {
			return nil
		}
		existing = append(existing, toAdd...)
		//#nosec G703 -- gitignorePath is derived from trusted vaultDir
		return os.WriteFile(gitignorePath, []byte(strings.Join(existing, "\n")+"\n"), 0o600)
	}
	gitignorePath := filepath.Join(vaultDir, ".gitignore")
	data, err := os.ReadFile(gitignorePath) //#nosec G304 -- vaultDir is controlled
	if err != nil {
		if os.IsNotExist(err) {
			r.Status = StatusWarn
			r.Message = ".gitignore missing"
			r.Hint = "run `openpass git init` to create a protective .gitignore"
			return r
		}
		r.Status = StatusWarn
		r.Message = "cannot read .gitignore: " + err.Error()
		return r
	}
	content := string(data)
	required := []string{"identity.age", "mcp-token", "mcp-tokens.json"}
	var missing []string
	for _, entry := range required {
		if !strings.Contains(content, entry) {
			missing = append(missing, entry)
		}
	}
	if len(missing) > 0 {
		r.Status = StatusWarn
		r.Message = ".gitignore missing entries: " + strings.Join(missing, ", ")
		r.Hint = "add missing entries to " + gitignorePath
	} else {
		r.Status = StatusOK
		r.Message = "identity.age, mcp-token, mcp-tokens.json are gitignored"
	}
	return r
}

func checkGitLastSync(vaultDir string, _ Options) Result {
	r := Result{ID: "git.lastsync.fresh", Name: "Last sync fresh"}
	t, err := git.LastSyncTime(vaultDir)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot determine last sync time: " + err.Error()
		return r
	}
	if t.IsZero() {
		r.Status = StatusWarn
		r.Message = "no sync recorded yet"
		r.Hint = "run `openpass git push` to sync your vault"
		return r
	}
	age := time.Since(t).Round(time.Hour)
	if age > 7*24*time.Hour {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("last sync %s ago", age)
		r.Hint = "run `openpass git pull` to sync latest changes"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("last sync %s ago", age)
	}
	return r
}
