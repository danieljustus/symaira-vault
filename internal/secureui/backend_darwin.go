//go:build darwin

package secureui

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type osascriptBackend struct{ r runner }

// newGUIBackend returns an osascript-based GUI backend on macOS, or nil if
// osascript is not on PATH.
func newGUIBackend(r runner) backend {
	if r == nil {
		r = defaultRunner
	}
	if _, err := r.lookPath("osascript"); err != nil {
		return nil
	}
	return &osascriptBackend{r: r}
}

func (*osascriptBackend) capability() Capability { return CapGUI }

func (b *osascriptBackend) prompt(req PromptRequest) (string, error) {
	title := orDefault(req.Title, "Symaira Vault")
	body := FormatPrompt(req)
	hidden := " with hidden answer"
	if !req.Hidden {
		hidden = ""
	}
	script := fmt.Sprintf(
		"set v to text returned of (display dialog %s with title %s default answer \"\"%s)\nreturn v",
		osaQuote(body), osaQuote(title), hidden,
	)
	out, err := b.r.run("osascript", []string{"-e", script}, req.Timeout)
	if err != nil {
		canceled, osaErr := isOsaCancel(err)
		if canceled {
			return "", ErrCanceled
		}
		if osaErr != nil {
			return "", osaErr
		}
		return "", fmt.Errorf("osascript: %w", err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// osaQuote returns s as a double-quoted AppleScript string literal.
func osaQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

// isOsaCancel inspects osascript exit errors to distinguish genuine user
// cancellation from TCC/automation permission denials and other failures.
// Returns (true, nil) for cancellation, (false, nil) for non-cancel errors
// that should be surfaced, or (false, error) for unexpected cases.
func isOsaCancel(err error) (bool, error) {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		stderr := string(exitErr.Stderr)
		if strings.Contains(stderr, "-128") || strings.Contains(stderr, "User canceled") {
			return true, nil
		}
		if stderr != "" {
			return false, fmt.Errorf("osascript failed: %s (check System Events permissions in System Settings > Privacy & Security > Automation, or run 'symvault doctor')", strings.TrimSpace(stderr))
		}
	}

	// Fallback: if no stderr content, treat exit status 1 as cancellation
	// for backward compatibility with tests and older osascript versions.
	if strings.Contains(err.Error(), "exit status 1") {
		return true, nil
	}

	return false, nil
}
