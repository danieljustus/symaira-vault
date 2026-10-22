package main

import (
	"fmt"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/secrets"
)

type autotypeCase struct {
	Name            string         `json:"name"`
	WaylandDisplay  string         `json:"wayland_display"`
	WaylandEmptySet bool           `json:"wayland_display_set_to_empty,omitempty"`
	Tools           []string       `json:"path_tools"`
	PathSpec        *string        `json:"path_spec,omitempty"`
	RelTools        []string       `json:"rel_tools,omitempty"`
	CwdTools        []string       `json:"cwd_tools,omitempty"`
	Strict          string         `json:"strict_focus_env"`
	Focus           [2]string      `json:"focus_class_outputs"`
	FocusExit       int            `json:"focus_probe_exit"`
	TypeExit        int            `json:"type_exit"`
	Text            string         `json:"text"`
	Error           string         `json:"error"`
	Calls           []recordedCall `json:"calls"`
}

var (
	wlPair     = []string{"wl-copy", "wl-paste"}
	termuxPair = []string{"termux-clipboard-set", "termux-clipboard-get"}
	winPair    = []string{"clip.exe", "powershell.exe"}
)

func tools(groups ...[]string) []string {
	out := []string{}
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func one(name string) []string { return []string{name} }

func spec(path string) *string { return &path }

// clipboardScenarios exercises atotto/clipboard's init() selection order and
// the Read/Copy behavior built on it. Each case documents why it exists.
func clipboardScenarios() []clipboardCase {
	const wl = "wayland-0"
	longPayload := strings.Repeat("0123456789abcdef", 512)
	cases := []clipboardCase{
		{Name: "x11_no_tools", Payload: "secret"},
		{Name: "wayland_no_tools", WaylandDisplay: wl, Payload: "secret"},
		{Name: "wayland_wl_pair", WaylandDisplay: wl, Tools: wlPair, Payload: "secret", PasteOutput: "secret"},
		{Name: "wayland_wl_pair_beats_xclip", WaylandDisplay: wl, Tools: tools(wlPair, one("xclip")), Payload: "secret", PasteOutput: "secret"},
		{Name: "wayland_wl_copy_without_paste_falls_to_xclip", WaylandDisplay: wl, Tools: tools(one("wl-copy"), one("xclip")), Payload: "secret", PasteOutput: "secret"},
		{Name: "wayland_wl_paste_without_copy_is_unsupported", WaylandDisplay: wl, Tools: one("wl-paste"), Payload: "secret"},
		{Name: "wayland_empty_string_is_unset", WaylandEmptySet: true, Tools: tools(wlPair, one("xclip")), Payload: "secret", PasteOutput: "secret"},
		{Name: "x11_wl_pair_ignored_for_xclip", Tools: tools(wlPair, one("xclip")), Payload: "secret", PasteOutput: "secret"},
		{Name: "x11_wl_pair_only_is_unsupported", Tools: wlPair, Payload: "secret"},
		{Name: "x11_xclip_only", Tools: one("xclip"), Payload: "secret", PasteOutput: "secret"},
		{Name: "x11_xsel_only", Tools: one("xsel"), Payload: "secret", PasteOutput: "secret"},
		{Name: "x11_xclip_beats_xsel", Tools: tools(one("xsel"), one("xclip")), Payload: "secret", PasteOutput: "secret"},
		{Name: "x11_xsel_beats_termux", Tools: tools(one("xsel"), termuxPair), Payload: "secret", PasteOutput: "secret"},
		{Name: "termux_pair", Tools: termuxPair, Payload: "secret", PasteOutput: "secret"},
		{Name: "termux_set_without_get_is_unsupported", Tools: one("termux-clipboard-set"), Payload: "secret"},
		{Name: "termux_beats_windows_pair_and_does_not_trim", Tools: tools(termuxPair, winPair), Payload: "secret", PasteOutput: "secret\r\n"},
		{Name: "windows_pair_trims_crlf", Tools: winPair, Payload: "secret", PasteOutput: "secret\r\n"},
		{Name: "windows_pair_trims_two_bytes_unconditionally", Tools: winPair, Payload: "secret", PasteOutput: "secret"},
		{Name: "windows_pair_one_byte_output_is_kept", Tools: winPair, Payload: "a", PasteOutput: "a"},
		{Name: "windows_pair_two_byte_output_becomes_empty", Tools: winPair, Payload: "ab", PasteOutput: "ab"},
		{Name: "windows_pair_empty_output", Tools: winPair, Payload: "", PasteOutput: ""},
		{Name: "windows_clip_exe_without_powershell_is_unsupported", Tools: one("clip.exe"), Payload: "secret"},
		{Name: "windows_powershell_without_clip_exe_is_unsupported", Tools: one("powershell.exe"), Payload: "secret"},
		{Name: "xclip_empty_payload_clear", Tools: one("xclip"), Payload: "", PasteOutput: ""},
		{Name: "xclip_multiline_payload", Tools: one("xclip"), Payload: "line1\nline2\r\nline3", PasteOutput: "line1\nline2\r\nline3"},
		{Name: "xclip_unicode_payload", Tools: one("xclip"), Payload: "pässwörd ✓ 𝄞 日本語", PasteOutput: "pässwörd ✓ 𝄞 日本語"},
		{Name: "xclip_nul_in_payload", Tools: one("xclip"), Payload: "a\x00b", PasteOutput: "a\x00b"},
		{Name: "xclip_payload_that_looks_like_flags", Tools: one("xclip"), Payload: "-in -selection clipboard", PasteOutput: "x"},
		{Name: "xclip_long_payload", Tools: one("xclip"), Payload: longPayload, PasteOutput: longPayload},
		{Name: "xclip_exit_1_reports_exit_status", Tools: one("xclip"), Payload: "secret", PasteOutput: "secret", Exit: 1},
		{Name: "wayland_wl_exit_2_reports_exit_status", WaylandDisplay: wl, Tools: wlPair, Payload: "secret", PasteOutput: "secret", Exit: 2},
		// Relative and empty PATH entries: exec.LookPath returns ErrDot for an
		// executable found relative to the working directory, so atotto's init()
		// treats the tool as absent and never runs it.
		{Name: "relative_path_xclip_is_not_used", PathSpec: spec("rel"), RelTools: one("xclip"), Payload: "secret", PasteOutput: "secret"},
		{Name: "dot_path_xclip_is_not_used", PathSpec: spec("."), CwdTools: one("xclip"), Payload: "secret", PasteOutput: "secret"},
		{Name: "empty_entry_xclip_in_cwd_is_not_used", PathSpec: spec(":{bin}"), CwdTools: one("xclip"), Payload: "secret", PasteOutput: "secret"},
		{Name: "empty_path_searches_nothing", PathSpec: spec(""), CwdTools: one("xclip"), Payload: "secret", PasteOutput: "secret"},
		{Name: "relative_hit_shadows_absolute_same_tool", PathSpec: spec("rel:{bin}"), RelTools: one("xclip"), Tools: one("xclip"), Payload: "secret", PasteOutput: "secret"},
		{Name: "relative_xclip_falls_to_absolute_xsel", PathSpec: spec("rel:{bin}"), RelTools: one("xclip"), Tools: one("xsel"), Payload: "secret", PasteOutput: "secret"},
		{Name: "empty_entry_falls_through_to_absolute_xclip", PathSpec: spec(":{bin}"), Tools: one("xclip"), Payload: "secret", PasteOutput: "secret"},
		{Name: "wayland_relative_wl_pair_ignored_for_absolute_xclip", WaylandDisplay: wl, PathSpec: spec("rel:{bin}"), RelTools: wlPair, Tools: one("xclip"), Payload: "secret", PasteOutput: "secret"},
	}
	return cases
}

// autotypeScenarios exercises NewLinuxAutotype().Type: X11/Wayland tool
// choice, stdin-only text routing, error text, and the focus guard.
func autotypeScenarios() []autotypeCase {
	const wl = "wayland-0"
	stable := [2]string{"firefox", "firefox"}
	long := strings.Repeat("hunter2-", 256)
	cases := []autotypeCase{
		{Name: "x11_xdotool_stable_focus", Tools: one("xdotool"), Focus: stable, Text: "hunter2-supersecret"},
		{Name: "x11_sendkeys_metacharacters_are_not_escaped", Tools: one("xdotool"), Focus: stable, Text: "a+b^c%d~e{f}g[h]i"},
		{Name: "x11_multiline_text", Tools: one("xdotool"), Focus: stable, Text: "user\tname\nsecond\r\nthird"},
		{Name: "x11_unicode_text", Tools: one("xdotool"), Focus: stable, Text: "pässwörd ✓ 𝄞 日本語"},
		{Name: "x11_empty_text", Tools: one("xdotool"), Focus: stable, Text: ""},
		{Name: "x11_text_that_looks_like_flags", Tools: one("xdotool"), Focus: stable, Text: "--clearmodifiers --file /etc/passwd"},
		{Name: "x11_long_text", Tools: one("xdotool"), Focus: stable, Text: long},
		{Name: "x11_focus_changed_aborts_before_typing", Tools: one("xdotool"), Focus: [2]string{"firefox", "xterm"}, Text: "hunter2"},
		{Name: "x11_first_focus_class_empty_still_compares", Tools: one("xdotool"), Focus: [2]string{"", "xterm"}, Text: "hunter2"},
		{Name: "x11_focus_probe_fails_lenient_still_types", Tools: one("xdotool"), Focus: stable, FocusExit: 1, Text: "hunter2"},
		{Name: "x11_focus_probe_fails_strict_refuses", Tools: one("xdotool"), Focus: stable, FocusExit: 1, Strict: "1", Text: "hunter2"},
		{Name: "x11_strict_zero_is_lenient", Tools: one("xdotool"), Focus: stable, FocusExit: 1, Strict: "0", Text: "hunter2"},
		{Name: "x11_strict_false_string_is_strict", Tools: one("xdotool"), Focus: stable, FocusExit: 1, Strict: "false", Text: "hunter2"},
		{Name: "x11_type_failure_reports_exit_status", Tools: one("xdotool"), Focus: stable, TypeExit: 1, Text: "hunter2"},
		{Name: "x11_no_xdotool", Text: "hunter2"},
		{Name: "x11_no_xdotool_strict_refuses_on_focus", Strict: "1", Text: "hunter2"},
		{Name: "x11_wtype_and_ydotool_do_not_substitute", Tools: tools(one("wtype"), one("ydotool")), Text: "hunter2"},
		{Name: "wayland_empty_string_uses_x11_path", WaylandEmptySet: true, Tools: one("xdotool"), Focus: stable, Text: "hunter2"},
		{Name: "wayland_wtype", WaylandDisplay: wl, Tools: one("wtype"), Text: "hunter2-supersecret"},
		{Name: "wayland_wtype_beats_ydotool", WaylandDisplay: wl, Tools: tools(one("wtype"), one("ydotool")), Text: "hunter2"},
		{Name: "wayland_ydotool_fallback", WaylandDisplay: wl, Tools: one("ydotool"), Text: "hunter2-supersecret"},
		{Name: "wayland_wtype_metacharacters_and_unicode", WaylandDisplay: wl, Tools: one("wtype"), Text: "a+b^c%d~e{f}g[h]i ✓"},
		{Name: "wayland_wtype_failure_does_not_fall_back", WaylandDisplay: wl, Tools: tools(one("wtype"), one("ydotool")), TypeExit: 1, Text: "hunter2"},
		{Name: "wayland_ydotool_failure", WaylandDisplay: wl, Tools: one("ydotool"), TypeExit: 3, Text: "hunter2"},
		{Name: "wayland_no_tools_install_hint", WaylandDisplay: wl, Text: "hunter2"},
		{Name: "wayland_xdotool_alone_is_not_used", WaylandDisplay: wl, Tools: one("xdotool"), Focus: stable, Text: "hunter2"},
		{Name: "wayland_strict_focus_refuses", WaylandDisplay: wl, Tools: one("wtype"), Strict: "1", Text: "hunter2"},
		{Name: "wayland_empty_text", WaylandDisplay: wl, Tools: one("wtype"), Text: ""},
		// Relative and empty PATH entries: exec.LookPath returns ErrDot, the
		// adapters treat that as "tool not installed", and the secret is never
		// written to the planted executable.
		{Name: "x11_relative_path_xdotool_is_refused", PathSpec: spec("rel"), RelTools: one("xdotool"), Focus: stable, Text: "hunter2-supersecret"},
		{Name: "x11_dot_path_xdotool_is_refused", PathSpec: spec("."), CwdTools: one("xdotool"), Focus: stable, Text: "hunter2-supersecret"},
		{Name: "x11_empty_entry_xdotool_in_cwd_is_refused", PathSpec: spec(":{bin}"), CwdTools: one("xdotool"), Focus: stable, Text: "hunter2-supersecret"},
		{Name: "x11_empty_path_searches_nothing", PathSpec: spec(""), CwdTools: one("xdotool"), Focus: stable, Text: "hunter2-supersecret"},
		{Name: "x11_relative_hit_shadows_absolute_xdotool", PathSpec: spec("rel:{bin}"), RelTools: one("xdotool"), Tools: one("xdotool"), Focus: stable, Text: "hunter2-supersecret"},
		{Name: "x11_relative_xdotool_strict_refuses_on_focus", PathSpec: spec("rel"), RelTools: one("xdotool"), Focus: stable, Strict: "1", Text: "hunter2-supersecret"},
		{Name: "x11_empty_entry_falls_through_to_absolute_xdotool", PathSpec: spec(":{bin}"), Tools: one("xdotool"), Focus: stable, Text: "hunter2-supersecret"},
		{Name: "wayland_relative_wtype_is_refused", WaylandDisplay: wl, PathSpec: spec("rel"), RelTools: one("wtype"), Text: "hunter2-supersecret"},
		{Name: "wayland_relative_wtype_falls_to_absolute_ydotool", WaylandDisplay: wl, PathSpec: spec("rel:{bin}"), RelTools: one("wtype"), Tools: one("ydotool"), Text: "hunter2-supersecret"},
	}
	for i := range cases {
		cases[i].Tools = append([]string{}, cases[i].Tools...)
	}
	return cases
}

func buildFixture() (fixture, error) {
	f := fixture{
		SchemaVersion:      1,
		Note:               "Go-derived by scripts/rust-port/cmd/desktopgen on GOOS=linux with fake POSIX-shell desktop tools on a disposable PATH. Sections: clipboard_cases drive internal/clipboard (atotto backend selection); autotype_cases drive internal/autotype NewLinuxAutotype().Type; windows_extracted_not_executed are go/parser literals from GOOS=windows sources and were never executed. No real clipboard, display or credential was touched.",
		ScriptPlaceholders: scriptPlaceholders,
		FakeTools:          fakeToolTemplates(),
		// Autotype tools receive exactly this environment (secrets.PrepareCmd).
		AutotypeEnvWhitelist: secrets.DefaultWhitelist(),
	}
	for _, c := range clipboardScenarios() {
		c.Tools = append([]string{}, c.Tools...)
		got, err := runClipboardCase(c)
		if err != nil {
			return f, fmt.Errorf("clipboard %s: %w", c.Name, err)
		}
		if got.Calls == nil {
			got.Calls = []recordedCall{}
		}
		f.Clipboard = append(f.Clipboard, got)
	}
	for _, c := range autotypeScenarios() {
		got, err := runAutotypeCase(c)
		if err != nil {
			return f, fmt.Errorf("autotype %s: %w", c.Name, err)
		}
		if got.Calls == nil {
			got.Calls = []recordedCall{}
		}
		f.Autotype = append(f.Autotype, got)
	}
	if err := validateCoverage(f); err != nil {
		return f, err
	}
	return f, nil
}

// validateCoverage refuses a corpus that cannot discriminate: every fake tool
// must have been executed at least once, both clipboard outcomes and a focus
// abort must occur, and no payload may leak into a recorded argv.
func validateCoverage(f fixture) error {
	seen := map[string]bool{}
	var sawCopyErr, sawOK, sawFocusChanged bool
	for _, c := range f.Clipboard {
		for _, call := range c.Calls {
			seen[call.Tool] = true
			if c.Payload != "" && len(c.Payload) > 3 {
				for _, a := range call.Argv {
					if strings.Contains(a, c.Payload) {
						return fmt.Errorf("clipboard %s: payload leaked into argv %q", c.Name, a)
					}
				}
			}
		}
		if c.CopyError != "" {
			sawCopyErr = true
		} else {
			sawOK = true
		}
	}
	for _, c := range f.Autotype {
		for _, call := range c.Calls {
			seen[call.Tool] = true
			if call.Mode == "type" && len(c.Text) > 3 {
				for _, a := range call.Argv {
					if strings.Contains(a, c.Text) {
						return fmt.Errorf("autotype %s: text leaked into argv %q", c.Name, a)
					}
				}
			}
		}
		if strings.Contains(c.Error, "active window changed") {
			sawFocusChanged = true
		}
	}
	for _, spec := range toolSpecs {
		if !seen[spec.name] {
			return fmt.Errorf("fake tool %s was never executed by any scenario", spec.name)
		}
	}
	if !sawCopyErr || !sawOK || !sawFocusChanged {
		return fmt.Errorf("corpus lacks discriminating outcomes (copyErr=%v ok=%v focusChanged=%v)", sawCopyErr, sawOK, sawFocusChanged)
	}
	return nil
}
