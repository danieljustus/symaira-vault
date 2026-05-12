//go:build linux || freebsd || openbsd || netbsd

package secureui

import (
	"fmt"
	"strings"
)

type linuxGUIBackend struct {
	r       runner
	tool    string // "zenity" | "kdialog"
	toolBin string
}

// newGUIBackend probes for a desktop dialog tool. zenity (GNOME-ish) is
// preferred over kdialog, but either works. Returns nil if neither exists.
func newGUIBackend(r runner) backend {
	if r == nil {
		r = defaultRunner
	}
	for _, name := range []string{"zenity", "kdialog"} {
		if path, err := r.lookPath(name); err == nil {
			return &linuxGUIBackend{r: r, tool: name, toolBin: path}
		}
	}
	return nil
}

func (*linuxGUIBackend) capability() Capability { return CapGUI }

func (b *linuxGUIBackend) prompt(req PromptRequest) (string, error) {
	title := orDefault(req.Title, "OpenPass")
	body := FormatPrompt(req)
	switch b.tool {
	case "zenity":
		args := []string{"--entry", "--title=" + sanitizeOneLine(title), "--text=" + body}
		if req.Hidden {
			args = append(args, "--hide-text")
		}
		out, err := b.r.run(b.toolBin, args, req.Timeout)
		if err != nil {
			if isCmdCancel(err) {
				return "", ErrCanceled
			}
			return "", fmt.Errorf("zenity: %w", err)
		}
		return strings.TrimRight(string(out), "\n"), nil

	case "kdialog":
		flag := "--inputbox"
		if req.Hidden {
			flag = "--password"
		}
		args := []string{flag, body, "--title", sanitizeOneLine(title)}
		out, err := b.r.run(b.toolBin, args, req.Timeout)
		if err != nil {
			if isCmdCancel(err) {
				return "", ErrCanceled
			}
			return "", fmt.Errorf("kdialog: %w", err)
		}
		return strings.TrimRight(string(out), "\n"), nil
	}
	return "", ErrUnavailable
}

// sanitizeOneLine strips characters that some dialog tools mishandle in title
// flags (newlines, control chars). Body text is passed through unchanged so
// multi-line descriptions render correctly.
func sanitizeOneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func isCmdCancel(err error) bool {
	return strings.Contains(err.Error(), "exit status 1")
}
