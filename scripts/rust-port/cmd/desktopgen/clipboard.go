package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/clipboard"
)

const childFlag = "--child-clipboard"

type clipboardCase struct {
	Name            string   `json:"name"`
	WaylandDisplay  string   `json:"wayland_display"`
	WaylandEmptySet bool     `json:"wayland_display_set_to_empty,omitempty"`
	Tools           []string `json:"path_tools"`
	// PathSpec overrides PATH ("{bin}" is the absolute tool directory); nil keeps
	// the default. RelTools/CwdTools install tools under <cwd>/rel and <cwd>,
	// which a relative or empty PATH entry resolves to.
	PathSpec    *string        `json:"path_spec,omitempty"`
	RelTools    []string       `json:"rel_tools,omitempty"`
	CwdTools    []string       `json:"cwd_tools,omitempty"`
	Payload     string         `json:"payload"`
	PasteOutput string         `json:"paste_output"`
	Exit        int            `json:"tool_exit"`
	Calls       []recordedCall `json:"calls"`
	CopyError   string         `json:"copy_error"`
	PasteError  string         `json:"paste_error"`
	PasteResult string         `json:"paste_result"`
}

type childRequest struct {
	Payload string `json:"payload"`
}

type childResult struct {
	CopyError   string `json:"copy_error"`
	PasteError  string `json:"paste_error"`
	PasteResult string `json:"paste_result"`
}

// runChild is the re-executed process: it performs one Copy and one Read
// through the production clipboard.NewSystemClipboard, whose backend was
// selected by atotto/clipboard's init() from this process's PATH/environment.
func runChild(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "desktopgen: unexpected child arguments")
		return 2
	}
	var req childRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, "desktopgen: child request:", err)
		return 2
	}
	var res childResult
	cb := clipboard.NewSystemClipboard()
	if err := cb.Copy(req.Payload); err != nil {
		res.CopyError = err.Error()
	}
	text, err := cb.Read()
	if err != nil {
		res.PasteError = err.Error()
	}
	res.PasteResult = text
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		return 2
	}
	return 0
}

func runClipboardCase(c clipboardCase) (clipboardCase, error) {
	sb, err := newPlacedSandbox(placement{Tools: c.Tools, RelTools: c.RelTools, CwdTools: c.CwdTools}, toolParams{exit: c.Exit}, c.PasteOutput)
	if err != nil {
		return c, err
	}
	defer sb.close()
	self, err := os.Executable()
	if err != nil {
		return c, err
	}
	request, err := json.Marshal(childRequest{Payload: c.Payload})
	if err != nil {
		return c, err
	}
	cmd := exec.Command(self, childFlag) // #nosec G204 -- re-executes this generator binary with a fixed flag
	cmd.Dir = sb.cwd
	cmd.Env = childEnv(sb, c.PathSpec, c.WaylandDisplay, c.WaylandEmptySet)
	cmd.Stdin = strings.NewReader(string(request))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return c, fmt.Errorf("child for %s: %w: %s", c.Name, err, stderr.String())
	}
	var res childResult
	if decodeErr := json.Unmarshal(out, &res); decodeErr != nil {
		return c, fmt.Errorf("child output for %s: %w", c.Name, decodeErr)
	}
	c.CopyError, c.PasteError, c.PasteResult = res.CopyError, res.PasteError, res.PasteResult
	c.Calls, err = sb.readCalls()
	return c, err
}

// childEnv is deliberately minimal: PATH is the fake-tool directory only.
func childEnv(sb *sandbox, pathSpec *string, wayland string, emptySet bool) []string {
	env := []string{
		"PATH=" + sb.pathValue(pathSpec),
		"HOME=" + sb.home,
		"TMPDIR=" + sb.root,
		"XDG_CONFIG_HOME=" + sb.home,
		"XDG_DATA_HOME=" + sb.home,
		"XDG_CACHE_HOME=" + sb.home,
	}
	if wayland != "" || emptySet {
		env = append(env, "WAYLAND_DISPLAY="+wayland)
	}
	return env
}
