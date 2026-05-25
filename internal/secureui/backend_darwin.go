//go:build darwin

package secureui

import (
	"fmt"
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
		if isOsaCancel(err) {
			return "", ErrCanceled
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

// isOsaCancel detects "User canceled" — osascript exits with status 1.
func isOsaCancel(err error) bool {
	return strings.Contains(err.Error(), "exit status 1")
}
