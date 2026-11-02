//go:build linux

package cmd

// PLATFORM-WIRE-001: `symvault get <path.field>` on a terminal with the
// clipboard Go really uses on Linux.
//
// get_clipboard.json records the command with an in-memory clipboard. Here the
// production crud.GetClipboard (clipboard.DefaultClipboard() -> the atotto
// command backend, selected in that package's init() from PATH and
// WAYLAND_DISPLAY) is left in place, so each scenario re-executes the test
// binary with a disposable PATH holding only POSIX-shell fake tools. Only the
// terminal decision and the auto-clear timer are stubbed, exactly as
// get_clipboard.json does. Nothing touches a real clipboard or display.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	crud "github.com/danieljustus/symaira-vault/cmd/crud"
	"github.com/danieljustus/symaira-vault/internal/cli"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	getClipboardLinuxChildEnv = "SYMAIRA_GET_CLIPBOARD_LINUX_CHILD"
	getClipboardLinuxFixture  = "testdata/port/platform/get_clipboard_linux.json"
)

type getClipboardLinuxTool struct {
	name     string
	mode     string
	copyFlag string
}

// Mirrors scripts/rust-port/cmd/desktopgen toolSpec for the clipboard tools;
// the Rust replay asserts the rendered templates equal desktop_linux.json's.
var getClipboardLinuxTools = []getClipboardLinuxTool{
	{name: "wl-copy", mode: "copy"},
	{name: "wl-paste", mode: "paste"},
	{name: "xclip", copyFlag: "-in"},
	{name: "xsel", copyFlag: "--input"},
	{name: "termux-clipboard-set", mode: "copy"},
	{name: "termux-clipboard-get", mode: "paste"},
	{name: "clip.exe", mode: "copy"},
	{name: "powershell.exe", mode: "paste"},
}

func (s getClipboardLinuxTool) template() string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("REC='@REC@'\n")
	b.WriteString("n=$(/bin/cat \"$REC/seq\" 2>/dev/null || echo 0)\n")
	b.WriteString("n=$((n+1))\n")
	b.WriteString("echo \"$n\" > \"$REC/seq\"\n")
	if s.copyFlag != "" {
		fmt.Fprintf(&b, "mode=paste\nfor a in \"$@\"; do case \"$a\" in %s) mode=copy;; esac; done\n", s.copyFlag)
	} else {
		fmt.Fprintf(&b, "mode=%s\n", s.mode)
	}
	fmt.Fprintf(&b, "{ printf '%%s\\n' '%s' \"$mode\" \"$#\"; for a in \"$@\"; do printf '%%s\\n' \"$a\"; done; } > \"$REC/call.$n\"\n", s.name)
	b.WriteString("case \"$mode\" in\n")
	b.WriteString("copy|type) /bin/cat > \"$REC/call.$n.stdin\"; exit @EXIT@ ;;\n")
	b.WriteString("paste) /bin/cat \"$REC/paste\"; exit @EXIT@ ;;\n")
	b.WriteString("focus)\n")
	b.WriteString("  f=$(/bin/cat \"$REC/focus.n\" 2>/dev/null || echo 0)\n")
	b.WriteString("  f=$((f+1))\n")
	b.WriteString("  echo \"$f\" > \"$REC/focus.n\"\n")
	b.WriteString("  if [ \"$f\" = 1 ]; then printf '%s\\n' '@FOCUS1@'; else printf '%s\\n' '@FOCUS2@'; fi\n")
	b.WriteString("  exit @FOCUSEXIT@ ;;\n")
	b.WriteString("esac\n")
	return b.String()
}

type getClipboardLinuxScenario struct {
	Name            string   `json:"name"`
	PathTools       []string `json:"path_tools"`
	WaylandDisplay  string   `json:"wayland_display"`
	ToolExit        int      `json:"tool_exit"`
	Secret          string   `json:"secret"`
	AutoClear       int      `json:"auto_clear_seconds"`
	TimerStubMillis int      `json:"timer_stub_ms"`
	// PasteOutput is what the fake paste tool prints; "@SECRET@" stands for
	// the scenario secret (a clipboard-history manager restoring it).
	PasteOutput string `json:"paste_output"`
	// SecretRepeat > 0 makes the stored password Secret repeated that many times.
	SecretRepeat int `json:"secret_repeat,omitempty"`
	// ToolOverrides replace a rendered fake tool's script for this scenario.
	ToolOverrides map[string]string `json:"tool_overrides,omitempty"`
}

type getClipboardLinuxCall struct {
	Tool  string   `json:"tool"`
	Mode  string   `json:"mode"`
	Argv  []string `json:"argv"`
	Stdin string   `json:"stdin"`
}

type getClipboardLinuxResult struct {
	getClipboardLinuxScenario
	Stdout    string                  `json:"stdout"`
	Stderr    string                  `json:"stderr"`
	ExitCode  int                     `json:"exit_code"`
	ToolCalls []getClipboardLinuxCall `json:"tool_calls"`
}

type getClipboardLinuxOracle struct {
	Commit         string   `json:"commit"`
	CommitSHA      string   `json:"commit_sha"`
	GoVersion      string   `json:"go_version"`
	GOOS           string   `json:"goos"`
	AtottoVersion  string   `json:"atotto_clipboard_version"`
	SourceFiles    []string `json:"source_files"`
	SourceHash     string   `json:"source_hash"`
	GeneratorFiles []string `json:"generator_files"`
	GeneratorHash  string   `json:"generator_hash"`
}

type getClipboardLinuxDocument struct {
	SchemaVersion     int                       `json:"schema_version"`
	Oracle            getClipboardLinuxOracle   `json:"oracle"`
	Note              string                    `json:"note"`
	ScriptPlaceholder []string                  `json:"script_placeholders"`
	FakeTools         map[string]string         `json:"fake_tools"`
	Scenarios         []getClipboardLinuxResult `json:"scenarios"`
}

func getClipboardLinuxScenarios() []getClipboardLinuxScenario {
	const secret = "s3cret-linux"
	return []getClipboardLinuxScenario{
		{Name: "no_tool_installed", Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "xclip_cleared", PathTools: []string{"xclip"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "xclip_cleared_two_second_ticks", PathTools: []string{"xclip"}, Secret: secret, AutoClear: 2, TimerStubMillis: 1500},
		{Name: "xclip_history_manager_restores_secret", PathTools: []string{"xclip"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150, PasteOutput: "@SECRET@"},
		{Name: "xclip_user_copied_something_else", PathTools: []string{"xclip"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150, PasteOutput: "something the user copied later"},
		{Name: "xclip_auto_clear_disabled", PathTools: []string{"xclip"}, Secret: secret},
		{Name: "xsel_cleared", PathTools: []string{"xsel"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "xclip_beats_xsel", PathTools: []string{"xsel", "xclip"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "wayland_wl_copy_cleared", PathTools: []string{"wl-copy", "wl-paste", "xclip"}, WaylandDisplay: "wayland-0", Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "wayland_without_wl_paste_uses_xclip", PathTools: []string{"wl-copy", "xclip"}, WaylandDisplay: "wayland-0", Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "wl_copy_ignored_without_wayland", PathTools: []string{"wl-copy", "wl-paste", "xsel"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "termux_cleared", PathTools: []string{"termux-clipboard-set", "termux-clipboard-get"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "windows_exe_cleared", PathTools: []string{"clip.exe", "powershell.exe"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "windows_exe_trims_crlf_and_flags_restored_secret", PathTools: []string{"clip.exe", "powershell.exe"}, Secret: secret, AutoClear: 1, TimerStubMillis: 150, PasteOutput: "@SECRET@\r\n"},
		{Name: "xclip_exit_failure", PathTools: []string{"xclip"}, ToolExit: 1, Secret: secret, AutoClear: 1, TimerStubMillis: 150},
		{Name: "xsel_exit_failure_code_3", PathTools: []string{"xsel"}, ToolExit: 3, Secret: secret},
		// atotto's writeAll returns the stdin write error without waiting for
		// the tool, even when the tool exits 0: a payload larger than the pipe
		// buffer and a tool that closes its stdin make that deterministic.
		{Name: "large_payload_tool_closes_stdin_exit_0", PathTools: []string{"xclip"}, Secret: secret, SecretRepeat: 80000, AutoClear: 1, TimerStubMillis: 150,
			ToolOverrides: map[string]string{"xclip": getClipboardLinuxClosedStdinTool("xclip")}},
		{Name: "large_payload_tool_closes_stdin_exit_1", PathTools: []string{"xclip"}, ToolExit: 1, Secret: secret, SecretRepeat: 80000,
			ToolOverrides: map[string]string{"xclip": getClipboardLinuxClosedStdinTool("xclip")}},
	}
}

// getClipboardLinuxClosedStdinTool is a tool that records its call, closes its
// stdin without reading it and exits.
func getClipboardLinuxClosedStdinTool(name string) string {
	for _, tool := range getClipboardLinuxTools {
		if tool.name == name {
			tpl := tool.template()
			const read = "copy|type) /bin/cat > \"$REC/call.$n.stdin\"; exit @EXIT@ ;;\n"
			const closed = "copy|type) exec 0<&-; : > \"$REC/call.$n.stdin\"; exit @EXIT@ ;;\n"
			if !strings.Contains(tpl, read) {
				panic("fake tool template changed: " + name)
			}
			return strings.Replace(tpl, read, closed, 1)
		}
	}
	panic("unknown fake tool " + name)
}

func renderGetClipboardLinuxTool(tpl, rec string, exit int) string {
	return strings.NewReplacer("@REC@", rec, "@EXIT@", strconv.Itoa(exit), "@FOCUS1@", "", "@FOCUS2@", "", "@FOCUSEXIT@", "0").Replace(tpl)
}

func TestGenerateGetClipboardLinuxFixture(t *testing.T) {
	mode := os.Getenv("SYMVAULT_GET_CLIPBOARD_LINUX_FIXTURE")
	if mode == "" {
		t.Skip("set SYMVAULT_GET_CLIPBOARD_LINUX_FIXTURE=write or check")
	}
	root := ".."
	pin := resolveGetClipboardLinuxPin(t, root)
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	templates := make(map[string]string, len(getClipboardLinuxTools))
	for _, tool := range getClipboardLinuxTools {
		templates[tool.name] = tool.template()
	}
	results := make([]getClipboardLinuxResult, 0, 20)
	for _, scenario := range getClipboardLinuxScenarios() {
		results = append(results, runGetClipboardLinuxScenario(t, self, templates, scenario))
	}
	generatorFiles := []string{"cmd/get_clipboard_linux_fixture_generator_test.go", "cmd/get_clipboard_linux_pin_test.go", "cmd/get_clipboard_fixture_generator_test.go", "cmd/test_helpers_test.go"}
	doc := getClipboardLinuxDocument{
		SchemaVersion: 1,
		Oracle: getClipboardLinuxOracle{
			Commit:         pin.Commit,
			CommitSHA:      pin.CommitSHA,
			GoVersion:      getClipboardLinuxGoVersion,
			GOOS:           "linux",
			AtottoVersion:  "v0.1.4",
			SourceFiles:    getClipboardLinuxSourceFiles,
			SourceHash:     pin.SourceHash,
			GeneratorFiles: generatorFiles,
			GeneratorHash:  getClipboardLinuxWorkingDigest(t, root, generatorFiles),
		},
		Note:              "Recorded from the production `get` command (cobra root + cli.ExecuteRoot) on GOOS=linux with the production clipboard.DefaultClipboard() (atotto/clipboard command backend, selected at process start from PATH and WAYLAND_DISPLAY) and fake POSIX-shell tools on a disposable PATH; only the terminal decision and the auto-clear timer are stubbed, as in get_clipboard.json. source_hash is the digest of source_files, identical in the working tree and in commit_sha (the generator fails otherwise); go_version names the pinned oracle toolchain, the capture itself may run on a newer Go inside a Linux container.",
		ScriptPlaceholder: []string{"@REC@", "@EXIT@", "@FOCUS1@", "@FOCUS2@", "@FOCUSEXIT@"},
		FakeTools:         templates,
		Scenarios:         results,
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, getClipboardLinuxFixture)
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
		t.Fatal("get clipboard Linux fixture stale; regenerate with SYMVAULT_GET_CLIPBOARD_LINUX_FIXTURE=write")
	}
}

type getClipboardLinuxChildRequest struct {
	Scenario getClipboardLinuxScenario `json:"scenario"`
	Out      string                    `json:"out"`
}

type getClipboardLinuxChildResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

func runGetClipboardLinuxScenario(t *testing.T, self string, templates map[string]string, scenario getClipboardLinuxScenario) getClipboardLinuxResult {
	t.Helper()
	sandbox := t.TempDir()
	bin := filepath.Join(sandbox, "bin")
	rec := filepath.Join(sandbox, "rec")
	home := filepath.Join(sandbox, "home")
	for _, dir := range []string{bin, rec, home} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("%s: %v", scenario.Name, err)
		}
	}
	paste := strings.ReplaceAll(scenario.PasteOutput, "@SECRET@", scenario.Secret)
	if err := os.WriteFile(filepath.Join(rec, "paste"), []byte(paste), 0o600); err != nil {
		t.Fatalf("%s: %v", scenario.Name, err)
	}
	for _, name := range scenario.PathTools {
		template := templates[name]
		if override, ok := scenario.ToolOverrides[name]; ok {
			template = override
		}
		body := renderGetClipboardLinuxTool(template, rec, scenario.ToolExit)
		// #nosec G306 -- a fake desktop tool must be executable; it lives in a private scratch directory
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatalf("%s: %v", scenario.Name, err)
		}
	}
	out := filepath.Join(sandbox, "result.json")
	request, err := json.Marshal(getClipboardLinuxChildRequest{Scenario: scenario, Out: out})
	if err != nil {
		t.Fatalf("%s: %v", scenario.Name, err)
	}
	cmd := exec.Command(self, "-test.run=^TestGetClipboardLinuxChild$", "-test.count=1") // #nosec G204 -- re-executes this test binary with fixed flags
	cmd.Dir = home
	cmd.Env = []string{
		"PATH=" + bin,
		"HOME=" + home,
		"TMPDIR=" + sandbox,
		getClipboardLinuxChildEnv + "=" + string(request),
	}
	if scenario.WaylandDisplay != "" {
		cmd.Env = append(cmd.Env, "WAYLAND_DISPLAY="+scenario.WaylandDisplay)
	}
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s child: %v\n%s", scenario.Name, err, combined)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("%s result: %v", scenario.Name, err)
	}
	var child getClipboardLinuxChildResult
	if err := json.Unmarshal(raw, &child); err != nil {
		t.Fatalf("%s result decode: %v", scenario.Name, err)
	}
	return getClipboardLinuxResult{
		getClipboardLinuxScenario: scenario,
		Stdout:                    child.Stdout,
		Stderr:                    child.Stderr,
		ExitCode:                  child.ExitCode,
		ToolCalls:                 readGetClipboardLinuxCalls(t, rec),
	}
}

func readGetClipboardLinuxCalls(t *testing.T, rec string) []getClipboardLinuxCall {
	t.Helper()
	seqRaw, err := os.ReadFile(filepath.Join(rec, "seq"))
	if err != nil {
		if os.IsNotExist(err) {
			return []getClipboardLinuxCall{}
		}
		t.Fatal(err)
	}
	total, err := strconv.Atoi(strings.TrimSpace(string(seqRaw)))
	if err != nil {
		t.Fatalf("bad seq: %v", err)
	}
	calls := make([]getClipboardLinuxCall, 0, total)
	for i := 1; i <= total; i++ {
		raw, err := os.ReadFile(filepath.Join(rec, fmt.Sprintf("call.%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if len(lines) < 3 {
			t.Fatalf("short call record %d", i)
		}
		argc, err := strconv.Atoi(lines[2])
		if err != nil || len(lines) != 3+argc {
			t.Fatalf("malformed call record %d", i)
		}
		stdin, err := os.ReadFile(filepath.Join(rec, fmt.Sprintf("call.%d.stdin", i)))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		calls = append(calls, getClipboardLinuxCall{Tool: lines[0], Mode: lines[1], Argv: append([]string{}, lines[3:]...), Stdin: string(stdin)})
	}
	return calls
}

// TestGetClipboardLinuxChild is the re-executed process; it is a no-op unless
// the generator started it.
func TestGetClipboardLinuxChild(t *testing.T) {
	raw := os.Getenv(getClipboardLinuxChildEnv)
	if raw == "" {
		t.Skip("only runs as the re-executed child of TestGenerateGetClipboardLinuxFixture")
	}
	var request getClipboardLinuxChildRequest
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		t.Fatalf("child request: %v", err)
	}
	s := request.Scenario
	resetCommandTestState()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("NO_COLOR", "1")
	vaultDir, passphrase := initVault(t)
	identity, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	password := s.Secret
	if s.SecretRepeat > 0 {
		password = strings.Repeat(s.Secret, s.SecretRepeat)
	}
	entry := &vaultpkg.Entry{Data: map[string]any{"password": password}}
	if err := vaultpkg.WriteEntry(vaultDir, "fixture-entry", entry, identity.Identity); err != nil {
		t.Fatal(err)
	}
	clipboardYAML := fmt.Sprintf("clipboard:\n  auto_clear_duration: %d\n", s.AutoClear)
	if err := os.WriteFile(filepath.Join(vaultDir, "config.yaml"), []byte(clipboardYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	setPassEnv(t, string(passphrase))
	oldVaultFlagChanged := cli.VaultFlag.Changed
	cli.VaultFlag.Changed = false
	t.Cleanup(func() { cli.VaultFlag.Changed = oldVaultFlagChanged })
	t.Setenv("SYMVAULT_VAULT", vaultDir)

	// crud.GetClipboard stays the production DefaultClipboard.
	oldDuration := crud.GetAutoClearDurationFunc
	crud.GetAutoClearDurationFunc = func() int { return s.AutoClear }
	oldStart := crud.StartAutoClear
	crud.StartAutoClear = func(_ int, clearFn func(), _ <-chan struct{}) {
		time.Sleep(time.Duration(s.TimerStubMillis) * time.Millisecond)
		clearFn()
	}
	oldTerminal := cli.IsTerminalFunc
	cli.IsTerminalFunc = func(int) bool { return true }
	exitCode := 0
	oldExit := cli.OsExit
	cli.OsExit = func(code int) { exitCode = code }
	cli.ActiveContext = nil
	t.Cleanup(func() {
		crud.GetAutoClearDurationFunc = oldDuration
		crud.StartAutoClear = oldStart
		cli.IsTerminalFunc = oldTerminal
		cli.OsExit = oldExit
		cli.ActiveContext = nil
	})

	var stdout string
	stderr := captureStderr(func() {
		stdout = captureStdout(func() {
			root := NewRootCmd()
			root.SetArgs([]string{"get", "fixture-entry.password"})
			_ = cli.ExecuteRoot(root)
			root.SetArgs(nil)
		})
	})
	time.Sleep(20 * time.Millisecond)
	stderr = strings.ReplaceAll(stderr, envPassphraseNotice, "")
	encoded, err := json.Marshal(getClipboardLinuxChildResult{
		Stdout:   stdout,
		Stderr:   strings.ReplaceAll(stderr, vaultDir, "/fixture/vault"),
		ExitCode: exitCode,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(request.Out, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
