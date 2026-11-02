//go:build linux

package server

// PLATFORM-WIRE-001: the Linux half of MCP copy_to_clipboard.
//
// The existing copy-clipboard.json fixture drives the real handler with an
// in-memory clipboard. On Linux the production clipboard is
// clipboard.DefaultClipboard() -> clipboard.NewSystemClipboard() -> the
// atotto/clipboard command backend, whose tool selection happens in that
// package's init() from PATH and WAYLAND_DISPLAY. This generator therefore
// re-executes the test binary per scenario with a disposable PATH holding only
// POSIX-shell fake tools, calls the real tools/call copy_to_clipboard handler
// WITHOUT clipboard.SetClipboard, and records the protocol output plus every
// tool invocation (argv, stdin bytes). No real clipboard, display, keychain or
// credential is touched.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	copyClipboardLinuxChildEnv = "SYMAIRA_MCP_COPY_CLIPBOARD_LINUX_CHILD"
	copyClipboardLinuxFixture  = "testdata/port/mcp/copy-clipboard-linux.json"
)

var copyClipboardLinuxGeneratorFiles = []string{
	"internal/mcp/server/mcp_copy_clipboard_linux_fixture_generator_test.go",
	"internal/mcp/server/mcp_copy_clipboard_linux_pin_test.go",
	"internal/mcp/server/mcp_copy_clipboard_fixture_generator_test.go",
	"internal/mcp/server/mcpsetentry_fixture_generator_test.go",
	"internal/mcp/server/tools_test_helpers.go",
}

// copyClipboardLinuxTool mirrors scripts/rust-port/cmd/desktopgen toolSpec for
// the clipboard tools; the Rust replay asserts the rendered templates equal
// the ones recorded in testdata/port/platform/desktop_linux.json.
type copyClipboardLinuxTool struct {
	name     string
	mode     string
	copyFlag string
}

var copyClipboardLinuxTools = []copyClipboardLinuxTool{
	{name: "wl-copy", mode: "copy"},
	{name: "wl-paste", mode: "paste"},
	{name: "xclip", copyFlag: "-in"},
	{name: "xsel", copyFlag: "--input"},
	{name: "termux-clipboard-set", mode: "copy"},
	{name: "termux-clipboard-get", mode: "paste"},
	{name: "clip.exe", mode: "copy"},
	{name: "powershell.exe", mode: "paste"},
}

func (s copyClipboardLinuxTool) template() string {
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
	// The focus branch is unused by clipboard tools but kept so the rendered
	// text equals desktopgen's template byte for byte.
	b.WriteString("focus)\n")
	b.WriteString("  f=$(/bin/cat \"$REC/focus.n\" 2>/dev/null || echo 0)\n")
	b.WriteString("  f=$((f+1))\n")
	b.WriteString("  echo \"$f\" > \"$REC/focus.n\"\n")
	b.WriteString("  if [ \"$f\" = 1 ]; then printf '%s\\n' '@FOCUS1@'; else printf '%s\\n' '@FOCUS2@'; fi\n")
	b.WriteString("  exit @FOCUSEXIT@ ;;\n")
	b.WriteString("esac\n")
	return b.String()
}

type copyClipboardLinuxScenario struct {
	Name string `json:"name"`
	// Tool is the MCP tool the scenario calls: copy_to_clipboard or generate_totp.
	Tool string `json:"tool"`
	// Arguments is the tools/call arguments object, verbatim.
	Arguments      string   `json:"arguments"`
	PathTools      []string `json:"path_tools"`
	WaylandDisplay string   `json:"wayland_display"`
	ToolExit       int      `json:"tool_exit"`
	AutoClear      int      `json:"auto_clear_duration"`
	Repeat         int      `json:"repeat"`
	// WantCalls is how many tool invocations the scenario must have recorded
	// before the child may exit (the auto-clear runs on a timer).
	WantCalls int `json:"want_calls"`
	// ApprovalMode is the agent profile's approval mode ("none" when empty).
	ApprovalMode string `json:"approval_mode"`
	// PasswordRepeat > 0 reads the password of the "big" entry, which is
	// "0123456789abcdef" repeated that many times.
	PasswordRepeat int `json:"password_repeat,omitempty"`
	// ToolOverrides replace a rendered fake tool's script for this scenario.
	ToolOverrides map[string]string `json:"tool_overrides,omitempty"`
}

type copyClipboardLinuxCase struct {
	copyClipboardLinuxScenario
	Input     []string                 `json:"input"`
	Output    []json.RawMessage        `json:"output"`
	ToolCalls []copyClipboardLinuxCall `json:"tool_calls"`
}

type copyClipboardLinuxCall struct {
	Tool  string   `json:"tool"`
	Mode  string   `json:"mode"`
	Argv  []string `json:"argv"`
	Stdin string   `json:"stdin"`
}

type copyClipboardLinuxOracle struct {
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

// copyClipboardLinuxTOTP describes the fixed TOTP secret of the "github" entry.
// Go's handler reads the system clock, so the copied code is recorded as the
// placeholder after the generator proved it equals the code of a counter inside
// the call's time window; the Rust replay injects a clock and asserts the exact
// code for that clock.
type copyClipboardLinuxTOTP struct {
	Secret          string `json:"secret"`
	Algorithm       string `json:"algorithm"`
	Digits          int    `json:"digits"`
	Period          int    `json:"period"`
	CodePlaceholder string `json:"code_placeholder"`
}

const (
	copyClipboardLinuxTOTPPlaceholder = "@TOTP_CODE@"
	copyClipboardLinuxTOTPSecret      = "JBSWY3DPEHPK3PXP"
)

type copyClipboardLinuxDocument struct {
	SchemaVersion     int                      `json:"schema_version"`
	Oracle            copyClipboardLinuxOracle `json:"oracle"`
	Note              string                   `json:"note"`
	TOTP              copyClipboardLinuxTOTP   `json:"totp"`
	ServerName        string                   `json:"server_name"`
	ServerVersion     string                   `json:"server_version"`
	ScriptPlaceholder []string                 `json:"script_placeholders"`
	FakeTools         map[string]string        `json:"fake_tools"`
	Cases             []copyClipboardLinuxCase `json:"cases"`
}

// copyClipboardLinuxClosedStdinTool is a tool that records its call, closes
// its stdin without reading it and exits: the copy tool a clipboard owner that
// died early looks like to the writer.
func copyClipboardLinuxClosedStdinTool(name string) string {
	for _, tool := range copyClipboardLinuxTools {
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

func copyClipboardLinuxScenarios() []copyClipboardLinuxScenario {
	const (
		copyTool = "copy_to_clipboard"
		totpTool = "generate_totp"
		pathArgs = `{"path":"github"}`
		totpArgs = `{"path":"github","destination":"clipboard"}`
	)
	totp := func(s copyClipboardLinuxScenario) copyClipboardLinuxScenario {
		s.Tool = totpTool
		if s.Arguments == "" {
			s.Arguments = totpArgs
		}
		return s
	}
	scenarios := []copyClipboardLinuxScenario{
		{Name: "no_tool_installed", Repeat: 1, WantCalls: 0},
		{Name: "xclip_success", PathTools: []string{"xclip"}, Repeat: 1, WantCalls: 1},
		{Name: "xclip_success_auto_clear", PathTools: []string{"xclip"}, AutoClear: 1, Repeat: 1, WantCalls: 2},
		{Name: "xclip_refreshes_auto_clear", PathTools: []string{"xclip"}, AutoClear: 1, Repeat: 2, WantCalls: 3},
		{Name: "xsel_success_auto_clear", PathTools: []string{"xsel"}, AutoClear: 1, Repeat: 1, WantCalls: 2},
		{Name: "xclip_beats_xsel", PathTools: []string{"xsel", "xclip"}, Repeat: 1, WantCalls: 1},
		{Name: "wayland_wl_copy_auto_clear", PathTools: []string{"wl-copy", "wl-paste", "xclip"}, WaylandDisplay: "wayland-0", AutoClear: 1, Repeat: 1, WantCalls: 2},
		{Name: "wayland_without_wl_paste_uses_xclip", PathTools: []string{"wl-copy", "xclip"}, WaylandDisplay: "wayland-0", Repeat: 1, WantCalls: 1},
		{Name: "wl_copy_ignored_without_wayland", PathTools: []string{"wl-copy", "wl-paste", "xsel"}, Repeat: 1, WantCalls: 1},
		{Name: "termux_success", PathTools: []string{"termux-clipboard-set", "termux-clipboard-get"}, Repeat: 1, WantCalls: 1},
		{Name: "windows_exe_success", PathTools: []string{"clip.exe", "powershell.exe"}, Repeat: 1, WantCalls: 1},
		{Name: "xclip_exit_failure", PathTools: []string{"xclip"}, ToolExit: 1, AutoClear: 1, Repeat: 1, WantCalls: 1},
		{Name: "xsel_exit_failure_code_3", PathTools: []string{"xsel"}, ToolExit: 3, Repeat: 1, WantCalls: 1},
		// atotto's writeAll returns the stdin write error without waiting for
		// the tool, even when the tool exits 0: a payload larger than the pipe
		// buffer and a tool that closes its stdin make that deterministic.
		{Name: "large_payload_tool_closes_stdin_exit_0", Arguments: `{"path":"big"}`, PathTools: []string{"xclip"}, PasswordRepeat: 65536, AutoClear: 1, Repeat: 1, WantCalls: 1,
			ToolOverrides: map[string]string{"xclip": copyClipboardLinuxClosedStdinTool("xclip")}},
		{Name: "large_payload_tool_closes_stdin_exit_1", Arguments: `{"path":"big"}`, PathTools: []string{"xclip"}, ToolExit: 1, PasswordRepeat: 65536, Repeat: 1, WantCalls: 1,
			ToolOverrides: map[string]string{"xclip": copyClipboardLinuxClosedStdinTool("xclip")}},
		// generate_totp with the clipboard destination uses the same
		// clipboard.DefaultClipboard() and the same auto-clear.
		totp(copyClipboardLinuxScenario{Name: "totp_default_destination_xclip_auto_clear", Arguments: pathArgs, PathTools: []string{"xclip"}, AutoClear: 1, Repeat: 1, WantCalls: 2}),
		totp(copyClipboardLinuxScenario{Name: "totp_xclip_without_auto_clear", PathTools: []string{"xclip"}, Repeat: 1, WantCalls: 1}),
		totp(copyClipboardLinuxScenario{Name: "totp_xclip_refreshes_auto_clear", PathTools: []string{"xclip"}, AutoClear: 1, Repeat: 2, WantCalls: 3}),
		totp(copyClipboardLinuxScenario{Name: "totp_xsel_auto_clear", PathTools: []string{"xsel"}, AutoClear: 1, Repeat: 1, WantCalls: 2}),
		totp(copyClipboardLinuxScenario{Name: "totp_wayland_wl_copy_auto_clear", PathTools: []string{"wl-copy", "wl-paste", "xclip"}, WaylandDisplay: "wayland-0", AutoClear: 1, Repeat: 1, WantCalls: 2}),
		totp(copyClipboardLinuxScenario{Name: "totp_windows_exe_without_auto_clear", PathTools: []string{"clip.exe", "powershell.exe"}, Repeat: 1, WantCalls: 1}),
		totp(copyClipboardLinuxScenario{Name: "totp_no_tool_installed", Repeat: 1, WantCalls: 0}),
		totp(copyClipboardLinuxScenario{Name: "totp_xclip_exit_failure", PathTools: []string{"xclip"}, ToolExit: 1, AutoClear: 1, Repeat: 1, WantCalls: 1}),
		totp(copyClipboardLinuxScenario{Name: "totp_prompt_approval_not_supported", PathTools: []string{"xclip"}, ApprovalMode: "prompt", AutoClear: 1, Repeat: 1, WantCalls: 0}),
		totp(copyClipboardLinuxScenario{Name: "totp_deny_approval_not_supported", PathTools: []string{"xclip"}, ApprovalMode: "deny", AutoClear: 1, Repeat: 1, WantCalls: 0}),
	}
	for index := range scenarios {
		if scenarios[index].Tool == "" {
			scenarios[index].Tool = copyTool
		}
		if scenarios[index].Arguments == "" {
			scenarios[index].Arguments = pathArgs
		}
		if scenarios[index].ApprovalMode == "" {
			scenarios[index].ApprovalMode = "none"
		}
	}
	return scenarios
}

func renderCopyClipboardLinuxTool(tpl, rec string, exit int) string {
	return strings.NewReplacer("@REC@", rec, "@EXIT@", strconv.Itoa(exit), "@FOCUS1@", "", "@FOCUS2@", "", "@FOCUSEXIT@", "0").Replace(tpl)
}

func TestGenerateMCPCopyClipboardLinuxFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_COPY_CLIPBOARD_LINUX_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_COPY_CLIPBOARD_LINUX_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_COPY_CLIPBOARD_LINUX_FIXTURE=1 or SYMAIRA_CHECK_MCP_COPY_CLIPBOARD_LINUX_FIXTURE=1")
	}
	root := executeAPIRequestRepoRoot(t)
	pin := resolveCopyClipboardLinuxPin(t, root)
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}

	templates := make(map[string]string, len(copyClipboardLinuxTools))
	for _, tool := range copyClipboardLinuxTools {
		templates[tool.name] = tool.template()
	}
	cases := make([]copyClipboardLinuxCase, 0, 32)
	for _, scenario := range copyClipboardLinuxScenarios() {
		cases = append(cases, runCopyClipboardLinuxScenario(t, self, templates, scenario))
	}

	doc := copyClipboardLinuxDocument{
		SchemaVersion: 1,
		Oracle: copyClipboardLinuxOracle{
			Commit:         pin.Commit,
			CommitSHA:      pin.CommitSHA,
			GoVersion:      localMCPOracleGoVersion,
			GOOS:           "linux",
			AtottoVersion:  "v0.1.4",
			SourceFiles:    copyClipboardLinuxSourceFiles,
			SourceHash:     pin.SourceHash,
			GeneratorFiles: copyClipboardLinuxGeneratorFiles,
			GeneratorHash:  executeAPIRequestWorkingDigest(t, root, copyClipboardLinuxGeneratorFiles),
		},
		Note: "Real Go tools/call copy_to_clipboard and generate_totp (destination clipboard) on GOOS=linux with the production clipboard.DefaultClipboard() (atotto/clipboard command backend, selected at process start from PATH and WAYLAND_DISPLAY) and fake POSIX-shell tools on a disposable PATH; no clipboard.SetClipboard. source_hash is the digest of source_files, identical in the working tree and in commit_sha (the generator fails otherwise); go_version names the pinned oracle toolchain, the capture itself may run on a newer Go inside a Linux container. generate_totp reads the system clock, so the copied code is recorded as the placeholder after the generator proved it equals a code inside the call's time window.",
		TOTP: copyClipboardLinuxTOTP{
			Secret:          copyClipboardLinuxTOTPSecret,
			Algorithm:       "SHA1",
			Digits:          6,
			Period:          30,
			CodePlaceholder: copyClipboardLinuxTOTPPlaceholder,
		},
		ServerName:        "symvault",
		ServerVersion:     "0.0.0-copy-clipboard-linux-fixture",
		ScriptPlaceholder: []string{"@REC@", "@EXIT@", "@FOCUS1@", "@FOCUS2@", "@FOCUSEXIT@"},
		FakeTools:         templates,
		Cases:             cases,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, copyClipboardLinuxFixture)
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("copy_to_clipboard Linux fixture is stale; run with SYMAIRA_GENERATE_MCP_COPY_CLIPBOARD_LINUX_FIXTURE=1")
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

type copyClipboardLinuxChildResult struct {
	Input  []string          `json:"input"`
	Output []json.RawMessage `json:"output"`
	// StartUnix/EndUnix bracket the tools/call dispatches, in Unix seconds.
	StartUnix int64 `json:"start_unix"`
	EndUnix   int64 `json:"end_unix"`
}

// normalizeCopyClipboardLinuxTOTPCalls proves every non-empty copy carried a
// TOTP code Go could have generated inside [start, end] and records the
// placeholder in its place; the clear (empty stdin) is kept as is.
func normalizeCopyClipboardLinuxTOTPCalls(t *testing.T, name string, calls []copyClipboardLinuxCall, start, end int64) []copyClipboardLinuxCall {
	t.Helper()
	valid := map[string]bool{}
	for counter := start / 30; counter <= end/30; counter++ {
		code, err := crypto.GenerateTOTPAt(copyClipboardLinuxTOTPSecret, "SHA1", 6, 30, time.Unix(counter*30, 0))
		if err != nil {
			t.Fatalf("%s: expected TOTP code: %v", name, err)
		}
		valid[code.Code] = true
	}
	out := make([]copyClipboardLinuxCall, len(calls))
	copies := 0
	for index, call := range calls {
		out[index] = call
		if call.Mode != "copy" || call.Stdin == "" {
			continue
		}
		copies++
		if !valid[call.Stdin] {
			t.Fatalf("%s: call %d copied %q, which is no TOTP code of the window [%d, %d]", name, index+1, call.Stdin, start, end)
		}
		out[index].Stdin = copyClipboardLinuxTOTPPlaceholder
	}
	if len(calls) > 0 && copies == 0 {
		t.Fatalf("%s: no TOTP copy was recorded", name)
	}
	return out
}

type copyClipboardLinuxChildRequest struct {
	Scenario copyClipboardLinuxScenario `json:"scenario"`
	Rec      string                     `json:"rec"`
	Out      string                     `json:"out"`
}

func runCopyClipboardLinuxScenario(t *testing.T, self string, templates map[string]string, scenario copyClipboardLinuxScenario) copyClipboardLinuxCase {
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
	if err := os.WriteFile(filepath.Join(rec, "paste"), nil, 0o600); err != nil {
		t.Fatalf("%s: %v", scenario.Name, err)
	}
	for _, name := range scenario.PathTools {
		template := templates[name]
		if override, ok := scenario.ToolOverrides[name]; ok {
			template = override
		}
		body := renderCopyClipboardLinuxTool(template, rec, scenario.ToolExit)
		// #nosec G306 -- a fake desktop tool must be executable; it lives in a private scratch directory
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil {
			t.Fatalf("%s: %v", scenario.Name, err)
		}
	}
	out := filepath.Join(sandbox, "result.json")
	request, err := json.Marshal(copyClipboardLinuxChildRequest{Scenario: scenario, Rec: rec, Out: out})
	if err != nil {
		t.Fatalf("%s: %v", scenario.Name, err)
	}
	cmd := exec.Command(self, "-test.run=^TestMCPCopyClipboardLinuxChild$", "-test.count=1") // #nosec G204 -- re-executes this test binary with fixed flags
	cmd.Dir = home
	cmd.Env = []string{
		"PATH=" + bin,
		"HOME=" + home,
		"TMPDIR=" + sandbox,
		"XDG_CONFIG_HOME=" + home,
		"XDG_DATA_HOME=" + home,
		"XDG_CACHE_HOME=" + home,
		copyClipboardLinuxChildEnv + "=" + string(request),
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
	var child copyClipboardLinuxChildResult
	if err := json.Unmarshal(raw, &child); err != nil {
		t.Fatalf("%s result decode: %v", scenario.Name, err)
	}
	observed := copyClipboardLinuxCase{
		copyClipboardLinuxScenario: scenario,
		Input:                      child.Input,
		Output:                     child.Output,
		ToolCalls:                  readCopyClipboardLinuxCalls(t, rec),
	}
	if scenario.Tool == "generate_totp" {
		observed.ToolCalls = normalizeCopyClipboardLinuxTOTPCalls(t, scenario.Name, observed.ToolCalls, child.StartUnix, child.EndUnix)
	}
	if len(observed.ToolCalls) != scenario.WantCalls {
		t.Fatalf("%s: recorded %d tool calls, want %d", scenario.Name, len(observed.ToolCalls), scenario.WantCalls)
	}
	return observed
}

func readCopyClipboardLinuxCalls(t *testing.T, rec string) []copyClipboardLinuxCall {
	t.Helper()
	seqRaw, err := os.ReadFile(filepath.Join(rec, "seq"))
	if err != nil {
		if os.IsNotExist(err) {
			return []copyClipboardLinuxCall{}
		}
		t.Fatal(err)
	}
	total, err := strconv.Atoi(strings.TrimSpace(string(seqRaw)))
	if err != nil {
		t.Fatalf("bad seq: %v", err)
	}
	calls := make([]copyClipboardLinuxCall, 0, total)
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
		calls = append(calls, copyClipboardLinuxCall{Tool: lines[0], Mode: lines[1], Argv: append([]string{}, lines[3:]...), Stdin: string(stdin)})
	}
	return calls
}

// TestMCPCopyClipboardLinuxChild is the re-executed process. It is a no-op
// unless the generator started it, so a normal `go test` run skips it.
func TestMCPCopyClipboardLinuxChild(t *testing.T) {
	raw := os.Getenv(copyClipboardLinuxChildEnv)
	if raw == "" {
		t.Skip("only runs as the re-executed child of TestGenerateMCPCopyClipboardLinuxFixture")
	}
	var request copyClipboardLinuxChildRequest
	if err := json.Unmarshal([]byte(raw), &request); err != nil {
		t.Fatalf("child request: %v", err)
	}
	scenario := request.Scenario
	vaultDir, identity := mcpSetEntryFixtureVault(t)
	if scenario.PasswordRepeat > 0 {
		big := &vault.Entry{Data: map[string]any{
			"username": "fixture-user",
			"password": strings.Repeat("0123456789abcdef", scenario.PasswordRepeat),
		}}
		if err := vault.WriteEntry(vaultDir, "big", big, identity); err != nil {
			t.Fatalf("write large fixture entry: %v", err)
		}
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "clipboard-linux-fixture",
		Tier:            config.StrPtr("admin"),
		AllowedPaths:    []string{"*"},
		CanUseClipboard: config.BoolPtr(true),
		ApprovalMode:    config.StrPtr(scenario.ApprovalMode),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	srv.vault.Config = &config.Config{
		Clipboard: &config.ClipboardConfig{AutoClearDuration: scenario.AutoClear},
	}
	srv.approvalCache = newApprovalCache()

	inputs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	for index := 0; index < scenario.Repeat; index++ {
		inputs = append(inputs, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, index+2, scenario.Tool, scenario.Arguments))
	}
	handler := NewProtocolHandler("symvault", "0.0.0-copy-clipboard-linux-fixture", srv)
	outputs := make([]json.RawMessage, 0, len(inputs))
	startUnix := time.Now().Unix()
	for _, line := range inputs {
		var message transport.Message
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			t.Fatalf("decode input: %v", err)
		}
		response, err := handler.HandleMessage(context.Background(), &message)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		if response == nil {
			continue
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		if bytes.Contains(encoded, []byte("StrongP@ssw0rd123")) {
			t.Fatal("synthetic password exposed in protocol output")
		}
		outputs = append(outputs, encoded)
	}
	endUnix := time.Now().Unix()
	// The auto-clear runs on a timer; wait until the fake tools logged it.
	deadline := time.Now().Add(5 * time.Second)
	for scenario.WantCalls > 0 {
		seq, _ := os.ReadFile(filepath.Join(request.Rec, "seq"))
		if n, err := strconv.Atoi(strings.TrimSpace(string(seq))); err == nil && n >= scenario.WantCalls {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tool calls did not reach %d", scenario.WantCalls)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A call the scenario does not expect must not appear late.
	time.Sleep(150 * time.Millisecond)
	encoded, err := json.Marshal(copyClipboardLinuxChildResult{Input: inputs, Output: outputs, StartUnix: startUnix, EndUnix: endUnix})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(request.Out, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
