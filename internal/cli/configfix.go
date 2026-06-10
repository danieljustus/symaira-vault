package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
)

// InteractiveFixConfig walks the user through repairing a malformed or
// invalid config file. It first attempts deterministic auto-fixes (restoring
// defaults for known-bad numeric/enum values) and, when that is insufficient,
// offers to open the file in $EDITOR for manual repair. The loop is re-entered
// after the user edits the file, so the call returns only when the file
// validates cleanly, the user aborts, or an I/O error occurs.
func InteractiveFixConfig(configPath string, loadErr error, cfg *configpkg.Config, valErr error) (*configpkg.Config, error) {
	fmt.Fprintf(os.Stderr, "Configuration error detected in %s\n", configPath)
	if loadErr != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Load error: %v\n", loadErr)
	}
	if valErr != nil {
		for _, line := range strings.Split(valErr.Error(), "\n") {
			if line != "" {
				fmt.Fprintf(os.Stderr, "  ✗ Validation error: %s\n", line)
			}
		}
	}

	// Try to auto-fix deterministic errors if cfg is loaded
	if cfg != nil {
		modified := false
		// Some validation errors are surfaced at Load() time (e.g. invalid
		// approvalMode) rather than from Validate(), so we match against
		// the combined error string from both sources.
		var sb strings.Builder
		if loadErr != nil {
			sb.WriteString(loadErr.Error())
			sb.WriteString("\n")
		}
		if valErr != nil {
			sb.WriteString(valErr.Error())
		}
		errStr := sb.String()

		if strings.Contains(errStr, "sessionTimeout") {
			ok, _ := ConfirmInteractive("Field 'sessionTimeout' must be greater than 0. Suggestion: 15m. Apply this fix?", false)
			if ok {
				cfg.SessionTimeout = 15 * time.Minute
				modified = true
			}
		}
		if strings.Contains(errStr, "audit.maxFileSize") {
			ok, _ := ConfirmInteractive("Field 'audit.maxFileSize' must be greater than 0. Suggestion: 100MB. Apply this fix?", false)
			if ok {
				if cfg.Audit == nil {
					cfg.Audit = &configpkg.AuditConfig{}
				}
				cfg.Audit.MaxFileSize = 100 * 1024 * 1024
				modified = true
			}
		}
		if strings.Contains(errStr, "clipboard.autoClearDuration") {
			ok, _ := ConfirmInteractive("Field 'clipboard.autoClearDuration' must be non-negative. Suggestion: 30s. Apply this fix?", false)
			if ok {
				if cfg.Clipboard == nil {
					cfg.Clipboard = &configpkg.ClipboardConfig{}
				}
				cfg.Clipboard.AutoClearDuration = 30
				modified = true
			}
		}
		if strings.Contains(errStr, "mcp.bind") || (loadErr != nil && strings.Contains(loadErr.Error(), "mcp.bind")) {
			ok, _ := ConfirmInteractive("Field 'mcp.bind' must not be empty. Suggestion: 127.0.0.1. Apply this fix?", false)
			if ok {
				if cfg.MCP == nil {
					cfg.MCP = &configpkg.MCPConfig{}
				}
				cfg.MCP.Bind = "127.0.0.1"
				modified = true
			}
		}
		if strings.Contains(errStr, "vaultDir: must not be empty") {
			defaultDir, _ := os.UserHomeDir()
			suggestion := "~/.symvault"
			if defaultDir != "" {
				suggestion = filepath.Join(defaultDir, ".symvault")
			}
			ok, _ := ConfirmInteractive(fmt.Sprintf("Field 'vaultDir' must not be empty. Suggestion: %s. Apply this fix?", suggestion), false)
			if ok {
				cfg.VaultDir = suggestion
				modified = true
			}
		}
		if strings.Contains(errStr, "defaultAgent:") && strings.Contains(errStr, "not found in agents") {
			firstAgent := ""
			for name := range cfg.Agents {
				firstAgent = name
				break
			}
			if firstAgent != "" {
				ok, _ := ConfirmInteractive(fmt.Sprintf("Field 'defaultAgent' references an agent profile that does not exist. Suggestion: %q (the only defined agent). Apply this fix?", firstAgent), false)
				if ok {
					cfg.DefaultAgent = firstAgent
					modified = true
				}
			}
		}
		if strings.Contains(errStr, "invalid approvalMode") {
			ok, _ := ConfirmInteractive("An agent profile has an invalid approvalMode. Suggestion: 'prompt'. Apply this fix for all affected agents?", false)
			if ok {
				for name, agent := range cfg.Agents {
					mode := ""
					if agent.ApprovalMode != nil {
						mode = *agent.ApprovalMode
					}
					if mode != "" && mode != "none" && mode != "deny" && mode != "prompt" && mode != "auto" {
						suggestion := "prompt"
						agent.ApprovalMode = &suggestion
						cfg.Agents[name] = agent
						modified = true
					}
				}
			}
		}
		if strings.Contains(errStr, "invalid promptInjectionMode") {
			ok, _ := ConfirmInteractive("An agent profile has an invalid promptInjectionMode. Suggestion: 'off'. Apply this fix for all affected agents?", false)
			if ok {
				for name, agent := range cfg.Agents {
					mode := ""
					if agent.PromptInjectionMode != nil {
						mode = *agent.PromptInjectionMode
					}
					if mode != "" && mode != "off" && mode != "log-only" && mode != "wrap" && mode != "deny" {
						suggestion := "off"
						agent.PromptInjectionMode = &suggestion
						cfg.Agents[name] = agent
						modified = true
					}
				}
			}
		}
		if strings.Contains(errStr, "invalid auth method") || strings.Contains(errStr, "invalid authMethod") {
			ok, _ := ConfirmInteractive("Auth method is invalid. Suggestion: 'passphrase'. Apply this fix?", false)
			if ok {
				if err := cfg.SetAuthMethod(configpkg.AuthMethodPassphrase); err == nil {
					modified = true
				}
			}
		}

		if modified {
			if saveErr := cfg.SaveTo(configPath); saveErr != nil {
				fmt.Fprintf(os.Stderr, "Failed to save auto-fixes: %v\n", saveErr)
			} else {
				fmt.Fprintln(os.Stderr, "Auto-fixes applied successfully.")
				// Re-validate
				newCfg, newLoadErr := configpkg.Load(configPath)
				var newValErr error
				if newLoadErr == nil && newCfg != nil {
					newValErr = newCfg.Validate()
				}
				if newLoadErr == nil && newValErr == nil {
					return newCfg, nil
				}
				// Otherwise, continue to manual editor fix
				cfg = newCfg
				loadErr = newLoadErr
				valErr = newValErr
			}
		}
	}

	// Manual editor fix prompt
	ok, _ := ConfirmInteractive("Open config.yaml in $EDITOR to fix manually?", false)
	if !ok {
		return nil, fmt.Errorf("configuration fix aborted by user")
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	if _, lookErr := exec.LookPath(editor); lookErr != nil {
		return nil, fmt.Errorf("editor %q not found in PATH", editor)
	}

	//#nosec G204 -- editor path validated via exec.LookPath above
	editorCmd := exec.Command(editor, configPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr

	if runErr := editorCmd.Run(); runErr != nil {
		return nil, fmt.Errorf("editor failed: %w", runErr)
	}

	return nil, nil
}
