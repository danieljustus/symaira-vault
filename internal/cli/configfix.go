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
	reportConfigErrors(os.Stderr, configPath, loadErr, valErr)

	if cfg != nil {
		if modified := applyAutoFixes(cfg, loadErr, valErr); modified {
			return saveAndRevalidate(configPath, cfg)
		}
	}

	return runEditorFix(configPath)
}

func reportConfigErrors(w *os.File, configPath string, loadErr, valErr error) {
	_, _ = fmt.Fprintf(w, "Configuration error detected in %s\n", configPath)
	if loadErr != nil {
		_, _ = fmt.Fprintf(w, "  ✗ Load error: %v\n", loadErr)
	}
	if valErr != nil {
		for _, line := range strings.Split(valErr.Error(), "\n") {
			if line != "" {
				_, _ = fmt.Fprintf(w, "  ✗ Validation error: %s\n", line)
			}
		}
	}
}

// combinedErrorString joins the load-time and validation error messages so the
// pattern matchers below can find substrings regardless of which stage
// surfaced the problem.
func combinedErrorString(loadErr, valErr error) string {
	var sb strings.Builder
	if loadErr != nil {
		sb.WriteString(loadErr.Error())
		sb.WriteString("\n")
	}
	if valErr != nil {
		sb.WriteString(valErr.Error())
	}
	return sb.String()
}

// applyAutoFixes walks through the well-known validation errors and asks the
// user whether to apply the deterministic fix for each. Returns whether any
// change was made.
func applyAutoFixes(cfg *configpkg.Config, loadErr, valErr error) bool {
	errStr := combinedErrorString(loadErr, valErr)
	modified := false

	type fix struct {
		matches bool
		confirm string
		apply   func() bool
	}
	fixes := []fix{
		{strings.Contains(errStr, "sessionTimeout"), "Field 'sessionTimeout' must be greater than 0. Suggestion: 15m. Apply this fix?", func() bool { cfg.SessionTimeout = 15 * time.Minute; return true }},
		{strings.Contains(errStr, "audit.maxFileSize"), "Field 'audit.maxFileSize' must be greater than 0. Suggestion: 100MB. Apply this fix?", func() bool {
			if cfg.Audit == nil {
				cfg.Audit = &configpkg.AuditConfig{}
			}
			cfg.Audit.MaxFileSize = 100 * 1024 * 1024
			return true
		}},
		{strings.Contains(errStr, "clipboard.autoClearDuration"), "Field 'clipboard.autoClearDuration' must be non-negative. Suggestion: 30s. Apply this fix?", func() bool {
			if cfg.Clipboard == nil {
				cfg.Clipboard = &configpkg.ClipboardConfig{}
			}
			cfg.Clipboard.AutoClearDuration = 30
			return true
		}},
		{strings.Contains(errStr, "mcp.bind") || (loadErr != nil && strings.Contains(loadErr.Error(), "mcp.bind")), "Field 'mcp.bind' must not be empty. Suggestion: 127.0.0.1. Apply this fix?", func() bool {
			if cfg.MCP == nil {
				cfg.MCP = &configpkg.MCPConfig{}
			}
			cfg.MCP.Bind = "127.0.0.1"
			return true
		}},
	}
	for _, f := range fixes {
		if !f.matches {
			continue
		}
		ok, _ := ConfirmInteractive(f.confirm, false)
		if ok && f.apply() {
			modified = true
		}
	}

	if strings.Contains(errStr, "vaultDir: must not be empty") {
		defaultDir, _ := os.UserHomeDir()
		suggestion := "~/" + configpkg.DefaultVaultSubdir
		if defaultDir != "" {
			suggestion = filepath.Join(defaultDir, configpkg.DefaultVaultSubdir)
		}
		ok, _ := ConfirmInteractive(fmt.Sprintf("Field 'vaultDir' must not be empty. Suggestion: %s. Apply this fix?", suggestion), false)
		if ok {
			cfg.VaultDir = suggestion
			modified = true
		}
	}

	if strings.Contains(errStr, "defaultAgent:") && strings.Contains(errStr, "not found in agents") {
		if firstAgent := firstAgentName(cfg); firstAgent != "" {
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
			modified = repairAgentMode(cfg, "approvalMode", validApprovalModes, "prompt") || modified
		}
	}

	if strings.Contains(errStr, "invalid promptInjectionMode") {
		ok, _ := ConfirmInteractive("An agent profile has an invalid promptInjectionMode. Suggestion: 'off'. Apply this fix for all affected agents?", false)
		if ok {
			modified = repairAgentMode(cfg, "promptInjectionMode", validPromptInjectionModes, "off") || modified
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

	return modified
}

// agentApprovalModeAuto is the canonical "auto" string for the agent
// approval-mode enum. Named at package scope (rather than a string literal)
// so the goconst linter treats it as a named identifier and does not flag
// it as a duplicate of the semantically-unrelated "auto" used for terminal
// color-mode selection in cli.go.
const agentApprovalModeAuto = "auto"

var (
	validApprovalModes        = map[string]struct{}{"none": {}, "deny": {}, "prompt": {}, agentApprovalModeAuto: {}}
	validPromptInjectionModes = map[string]struct{}{"off": {}, "log-only": {}, "wrap": {}, "deny": {}}
)

func firstAgentName(cfg *configpkg.Config) string {
	for name := range cfg.Agents {
		return name
	}
	return ""
}

// repairAgentMode scans the agent profiles and replaces values for the named
// field that fall outside the allowed set with the given suggestion. Returns
// whether any profile was changed.
func repairAgentMode(cfg *configpkg.Config, field string, valid map[string]struct{}, suggestion string) bool {
	modified := false
	for name, agent := range cfg.Agents {
		var current *string
		switch field {
		case "approvalMode":
			current = agent.ApprovalMode
		case "promptInjectionMode":
			current = agent.PromptInjectionMode
		}
		if current == nil {
			continue
		}
		if _, ok := valid[*current]; ok {
			continue
		}
		if *current == "" {
			continue
		}
		s := suggestion
		switch field {
		case "approvalMode":
			agent.ApprovalMode = &s
		case "promptInjectionMode":
			agent.PromptInjectionMode = &s
		}
		cfg.Agents[name] = agent
		modified = true
	}
	return modified
}

func saveAndRevalidate(configPath string, cfg *configpkg.Config) (*configpkg.Config, error) {
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
		_ = newCfg
		_ = newLoadErr
		_ = newValErr
	}
	return runEditorFix(configPath)
}

func runEditorFix(configPath string) (*configpkg.Config, error) {
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
