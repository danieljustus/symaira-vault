package mcp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/danieljustus/OpenPass/internal/envfilter"
	"github.com/danieljustus/OpenPass/internal/vault/taint"
)

// Intent describes a sensitive operation that requires user approval.
type Intent struct {
	// Action is the operation being performed (e.g. "get_entry_value",
	// "set_entry_field", "delete_entry").
	Action string
	// EntryPath is the vault path the operation targets.
	EntryPath string
	// FieldName is the specific field being accessed, if applicable.
	FieldName string
	// Summary is a human-readable description shown in the approval prompt.
	Summary string
}

// requireApproval checks whether the current agent profile requires approval
// for the given intent. Returns nil if the operation is allowed, or an error
// if it is denied or the user did not approve.
func (s *Server) requireApproval(ctx context.Context, intent Intent) error {
	if s == nil || s.agent == nil {
		return fmt.Errorf("server not initialized")
	}

	var mode string
	if s.agent.ApprovalMode != nil {
		mode = *s.agent.ApprovalMode
	}
	if mode == "" {
		if s.agent.RequireApproval != nil && *s.agent.RequireApproval {
			mode = "prompt"
		} else {
			mode = "none"
		}
	}

	switch mode {
	case "none", "auto":
		return nil
	case "deny":
		s.logAudit(ctx, "approval."+intent.Action+".denied", intent.EntryPath, false)
		return fmt.Errorf("%s denied: approval mode is 'deny'", intent.Action)
	case "prompt":
		if !IsTTYPresent() {
			s.logAudit(ctx, "approval."+intent.Action+".denied", intent.EntryPath, false)
			return fmt.Errorf("%s requires approval but no TTY available", intent.Action)
		}

		riskLevel := toolRiskLevel(intent.Action)

		if riskLevel.CanRemember() && s.approvalCache != nil {
			cacheKey := approvalCacheKey(s.agent.Name, intent.Action, intent.EntryPath)
			if s.approvalCache.isRemembered(cacheKey) {
				s.logAudit(ctx, "approval."+intent.Action+".remembered", intent.EntryPath, true)
				return nil
			}
		}

		s.logAudit(ctx, "approval."+intent.Action+".requested", intent.EntryPath, true)

		var timeout time.Duration
		if s.agent.ApprovalTimeout != nil {
			timeout = *s.agent.ApprovalTimeout
		}
		if timeout <= 0 {
			timeout = defaultTimeout
		}

		workingDir := getWorkingDir()
		gitBranch := getGitBranch(workingDir)
		projectType := detectProjectContext(workingDir)

		result := RequestApproval(ApprovalRequest{
			Operation:       intent.Action,
			Details:         intent.Summary,
			Timeout:         timeout,
			AgentName:       s.agent.Name,
			WorkingDir:      workingDir,
			GitBranch:       gitBranch,
			ProjectType:     projectType,
			RiskLevel:       riskLevel,
			SecretsAccessed: int(s.approvalKeyCounter.Load()),
			CanRemember:     riskLevel.CanRemember(),
		})
		if result.Error != nil {
			return fmt.Errorf("%s approval failed: %w", intent.Action, result.Error)
		}
		if !result.Approved {
			s.logAudit(ctx, "approval."+intent.Action+".denied", intent.EntryPath, false)
			return fmt.Errorf("%s denied: user did not approve", intent.Action)
		}

		if result.Remembered && riskLevel.CanRemember() && s.approvalCache != nil {
			cacheKey := approvalCacheKey(s.agent.Name, intent.Action, intent.EntryPath)
			s.approvalCache.setRemembered(cacheKey)
			s.logAudit(ctx, "approval."+intent.Action+".remembered", intent.EntryPath, true)
		}

		s.approvalKeyCounter.Add(1)

		s.logAudit(ctx, "approval."+intent.Action+".granted", intent.EntryPath, true)
		return nil
	default:
		return nil
	}
}

// toolRiskLevel returns the risk classification for a tool by name.
func toolRiskLevel(name string) RiskLevel {
	if def, ok := findToolDefinition(name); ok {
		return def.RiskLevel
	}
	return RiskLevelMedium
}

// getWorkingDir returns the current working directory.
func getWorkingDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return dir
}

// getGitBranch returns the current git branch name.
func getGitBranch(workingDir string) string {
	if workingDir == "" {
		return ""
	}
	cmd := exec.Command("git", "-C", workingDir, "rev-parse", "--abbrev-ref", "HEAD")
	envfilter.PrepareCmd(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	branch := string(out)
	if len(branch) > 0 {
		branch = branch[:len(branch)-1] // trim newline
	}
	branch = trimNewline(branch)
	if branch == "HEAD" {
		return ""
	}
	return branch
}

func trimNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		return s[:len(s)-1]
	}
	return s
}

// detectProjectContext attempts to detect the project type from the working
// directory by looking for common project marker files.
func detectProjectContext(workingDir string) string {
	if workingDir == "" {
		return ""
	}

	markers := []struct {
		file  string
		label string
	}{
		{"go.mod", "Go"},
		{"package.json", "Node.js"},
		{"Cargo.toml", "Rust"},
		{"pyproject.toml", "Python"},
		{"setup.py", "Python"},
		{"pom.xml", "Java (Maven)"},
		{"build.gradle", "Java (Gradle)"},
		{"CMakeLists.txt", "C/C++ (CMake)"},
		{"Makefile", "Make"},
	}

	dir := workingDir
	for {
		for _, m := range markers {
			path := filepath.Join(dir, m.file)
			if _, err := os.Stat(path); err == nil {
				return filepath.Base(dir) + " (" + m.label + ")"
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

// RenderSummary produces a safe terminal summary for an approval prompt.
// It strips ANSI/control characters from the entry path and field name.
func RenderSummary(action, entryPath, fieldName string) string {
	safePath := sanitizeForSummary(entryPath)
	safeField := sanitizeForSummary(fieldName)
	if safeField != "" {
		return fmt.Sprintf("%s on %s field %s", action, safePath, safeField)
	}
	return fmt.Sprintf("%s on %s", action, safePath)
}

// sanitizeForSummary strips ANSI and control characters from a string
// for inclusion in terminal approval prompts.
func sanitizeForSummary(s string) string {
	if s == "" {
		return s
	}
	u := taint.Wrap(s, taint.Provenance{Source: "summary"})
	return stripTerminalControl(u.UnsafeRawForStorage())
}

// stripTerminalControl removes ANSI escape sequences and control characters.
func stripTerminalControl(s string) string {
	out := make([]byte, 0, len(s))
	inEscape := false
	inOSC := false
	for i := 0; i < len(s); i++ {
		b := s[i]
		if inEscape {
			if b == '[' || (b >= '0' && b <= '9') || b == ';' {
				continue
			}
			if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
				inEscape = false
				continue
			}
			inEscape = false
			continue
		}
		if inOSC {
			if b == 0x07 {
				inOSC = false
				continue
			}
			if b == '\\' {
				inOSC = false
				continue
			}
			continue
		}
		if b == 0x1b {
			if i+1 < len(s) && s[i+1] == '[' {
				inEscape = true
				continue
			}
			if i+1 < len(s) && s[i+1] == ']' {
				inOSC = true
				i++
				continue
			}
			continue
		}
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			continue
		}
		if b == 0x7f {
			continue
		}
		out = append(out, b)
	}
	return string(out)
}
