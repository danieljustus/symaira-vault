//go:build windows

package secureui

import (
	"fmt"
	"strings"
)

type powershellBackend struct{ r runner }

// newGUIBackend returns a PowerShell-based GUI backend on Windows. Get-Credential
// pops a system credential dialog; InputBox is used for non-hidden input.
func newGUIBackend(r runner) backend {
	if r == nil {
		r = defaultRunner
	}
	if _, err := r.lookPath("powershell.exe"); err != nil {
		return nil
	}
	return &powershellBackend{r: r}
}

func (*powershellBackend) capability() Capability { return CapGUI }

func (b *powershellBackend) prompt(req PromptRequest) (string, error) {
	title := orDefault(req.Title, "OpenPass")
	body := FormatPrompt(req)

	var script string
	if req.Hidden {
		// Get-Credential always shows a dialog with hidden password field.
		// Title is bundled into the message because Get-Credential lacks a
		// separate title parameter on some Windows versions.
		script = fmt.Sprintf(
			"$cred = Get-Credential -UserName 'openpass' -Message %s; if (-not $cred) { exit 1 }; $cred.GetNetworkCredential().Password",
			psQuote(title+"\n\n"+body),
		)
	} else {
		script = fmt.Sprintf(
			"Add-Type -AssemblyName Microsoft.VisualBasic; [Microsoft.VisualBasic.Interaction]::InputBox(%s, %s, '')",
			psQuote(body), psQuote(title),
		)
	}

	out, err := b.r.run("powershell.exe",
		[]string{"-NoProfile", "-NonInteractive", "-Command", script},
		req.Timeout)
	if err != nil {
		if isCmdCancel(err) {
			return "", ErrCanceled
		}
		return "", fmt.Errorf("powershell: %w", err)
	}
	value := strings.TrimRight(string(out), "\r\n")
	if value == "" {
		return "", ErrCanceled
	}
	return value, nil
}

// psQuote returns s as a single-quoted PowerShell literal (single quotes are
// escaped by doubling).
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func isCmdCancel(err error) bool {
	return strings.Contains(err.Error(), "exit status 1")
}
