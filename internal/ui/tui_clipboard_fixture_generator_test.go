package ui

// PLATFORM-001-FIDELITY: what the Go TUI shows when the clipboard misbehaves,
// and which auto-clear seconds it uses.
//
// The status line is TUIModel.statusView(): whenever m.err is set it is
// theme.ErrorStyle.Render(m.err.Error()), so the fixed `status` strings
// ("Copy failed", "Clipboard clear failed") are never visible next to an
// error. A failed copy is `copy to clipboard: <cause>`; a failed clear is the
// bare cause. writeClipboard is the package's clipboard seam; no real
// clipboard is touched. The causes are the strings Go's atotto backend
// produces (recorded end to end in get_clipboard_darwin.json /
// get_clipboard_linux.json).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

type tuiClipboardFixture struct {
	Commit        string                  `json:"commit"`
	SourceFiles   []string                `json:"source_files"`
	SourceHash    string                  `json:"source_hash"`
	GeneratorHash string                  `json:"generator_hash"`
	Note          string                  `json:"note"`
	Failures      []tuiClipboardFailure   `json:"failures"`
	AutoClear     []tuiClipboardAutoClear `json:"auto_clear_seconds"`
}

type tuiClipboardFailure struct {
	Name string `json:"name"`
	// Kind: copy | clear | quit_clear.
	Kind  string `json:"kind"`
	Cause string `json:"cause"`
	// StatusLine is the last line of statusView() (the error replaces status).
	StatusLine string `json:"status_line"`
}

type tuiClipboardAutoClear struct {
	Name string `json:"name"`
	// Config: none (nil Config) | no_clipboard (nil Clipboard section) | value.
	Config   string `json:"config"`
	Duration int    `json:"duration,omitempty"`
	Seconds  int    `json:"seconds"`
}

func TestGenerateTUIClipboardFixture(t *testing.T) {
	mode := os.Getenv("SYMVAULT_TUI_CLIPBOARD_FIXTURE")
	if mode == "" {
		t.Skip("set SYMVAULT_TUI_CLIPBOARD_FIXTURE=write or check")
	}
	const root = "../.."
	const pin = "5229f9490cd25c22adb641677546a57802417304"
	files := []string{
		"go.mod",
		"go.sum",
		"internal/ui/tui.go",
		"internal/ui/tui_commands.go",
		"internal/ui/tui_view.go",
		"internal/clipboard/clipboard.go",
	}
	hash := sha256.New()
	for _, name := range files {
		source, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- fixed compiled-in source list
		if err != nil {
			t.Fatal(err)
		}
		// #nosec G204 -- fixed git operation over compiled-in source paths and immutable pin
		show := exec.Command("git", "show", pin+":"+name)
		show.Dir = root
		pinned, err := show.Output()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(source, pinned) {
			t.Fatalf("oracle source drift: %s", name)
		}
		_, _ = hash.Write([]byte(name + "\x00"))
		_, _ = hash.Write(source)
		_, _ = hash.Write([]byte{0})
	}
	generator, err := os.ReadFile("tui_clipboard_fixture_generator_test.go")
	if err != nil {
		t.Fatal(err)
	}
	generatorHash := sha256.Sum256(generator)

	out := tuiClipboardFixture{
		Commit:        pin,
		SourceFiles:   files,
		SourceHash:    hex.EncodeToString(hash.Sum(nil)),
		GeneratorHash: hex.EncodeToString(generatorHash[:]),
		Note:          "Recorded from the production TUIModel.Update/statusView with the package's writeClipboard seam; no real clipboard was touched.",
	}

	causes := []struct{ name, cause string }{
		{"exit_status_3", "exit status 3"},
		{"signal_killed", "signal: killed"},
		{"signal_terminated", "signal: terminated"},
		{"missing_pbcopy", `exec: "pbcopy": executable file not found in $PATH`},
		{"broken_pipe", "write |1: broken pipe"},
		{"missing_linux_tools", "No clipboard utilities available. Please install xsel, xclip, wl-clipboard or Termux:API add-on for termux-clipboard-get/set."},
	}
	original := writeClipboard
	t.Cleanup(func() { writeClipboard = original })
	for _, kind := range []string{"copy", "clear", "quit_clear"} {
		for _, c := range causes {
			failure := errors.New(c.cause)
			writeClipboard = func(string) error { return failure }
			m := NewTUIModel(&vaultpkg.Vault{})
			m.loading = false
			var msg any
			switch kind {
			case "copy":
				msg = copyTextMsg("secret", "Copied password for entry")
			case "clear":
				msg = clipboardClearedMsg{err: writeClipboard("")}
			default:
				msg = clipboardQuitClearedMsg{err: writeClipboard("")}
			}
			next, _ := m.Update(msg)
			view := next.(TUIModel).statusView()
			lines := strings.Split(view, "\n")
			out.Failures = append(out.Failures, tuiClipboardFailure{
				Name:       kind + "_" + c.name,
				Kind:       kind,
				Cause:      c.cause,
				StatusLine: lines[len(lines)-1],
			})
		}
	}

	for _, c := range []struct {
		name, config string
		duration     int
	}{
		{"no_config", "none", 0},
		{"no_clipboard_section", "no_clipboard", 0},
		{"default_30", "value", 30},
		{"zero_disables", "value", 0},
		{"one", "value", 1},
		{"positive", "value", 45},
		{"negative_one_falls_back", "value", -1},
		{"negative_five_falls_back", "value", -5},
	} {
		model := NewTUIModel(&vaultpkg.Vault{})
		switch c.config {
		case "no_clipboard":
			model.vault.Config = &config.Config{}
		case "value":
			model.vault.Config = &config.Config{Clipboard: &config.ClipboardConfig{AutoClearDuration: c.duration}}
		}
		out.AutoClear = append(out.AutoClear, tuiClipboardAutoClear{
			Name: c.name, Config: c.config, Duration: c.duration, Seconds: model.autoClearSeconds(),
		})
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "testdata/port/platform/tui_clipboard.json")
	if mode == "write" {
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	existing, err := os.ReadFile(path) // #nosec G304 -- fixed fixture path under the repository root
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(existing, buf.Bytes()) {
		t.Fatal("tui clipboard fixture stale; regenerate with SYMVAULT_TUI_CLIPBOARD_FIXTURE=write")
	}
}
