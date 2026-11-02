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
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

const (
	copyClipboardLinuxChildEnv = "SYMAIRA_MCP_COPY_CLIPBOARD_LINUX_CHILD"
	copyClipboardLinuxFixture  = "testdata/port/mcp/copy-clipboard-linux.json"
)

var copyClipboardLinuxSourceFiles = []string{
	"go.mod",
	"go.sum",
	"internal/clipboard/clipboard.go",
	"internal/clipboard/clipboard_signal_unix.go",
	"internal/clipboard/interface.go",
	"internal/clipboard/provider.go",
	"internal/clipboard/system_clipboard.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/tools_clipboard.go",
}

var copyClipboardLinuxGeneratorFiles = []string{
	"internal/mcp/server/mcp_copy_clipboard_linux_fixture_generator_test.go",
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
	Name           string   `json:"name"`
	PathTools      []string `json:"path_tools"`
	WaylandDisplay string   `json:"wayland_display"`
	ToolExit       int      `json:"tool_exit"`
	AutoClear      int      `json:"auto_clear_duration"`
	Repeat         int      `json:"repeat"`
	// WantCalls is how many tool invocations the scenario must have recorded
	// before the child may exit (the auto-clear runs on a timer).
	WantCalls int `json:"want_calls"`
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
	GoVersion      string   `json:"go_version"`
	GOOS           string   `json:"goos"`
	AtottoVersion  string   `json:"atotto_clipboard_version"`
	SourceFiles    []string `json:"source_files"`
	SourceHash     string   `json:"source_hash"`
	GeneratorFiles []string `json:"generator_files"`
	GeneratorHash  string   `json:"generator_hash"`
}

type copyClipboardLinuxDocument struct {
	SchemaVersion     int                      `json:"schema_version"`
	Oracle            copyClipboardLinuxOracle `json:"oracle"`
	Note              string                   `json:"note"`
	ServerName        string                   `json:"server_name"`
	ServerVersion     string                   `json:"server_version"`
	ScriptPlaceholder []string                 `json:"script_placeholders"`
	FakeTools         map[string]string        `json:"fake_tools"`
	Cases             []copyClipboardLinuxCase `json:"cases"`
}

func copyClipboardLinuxScenarios() []copyClipboardLinuxScenario {
	return []copyClipboardLinuxScenario{
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
	}
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
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}

	templates := make(map[string]string, len(copyClipboardLinuxTools))
	for _, tool := range copyClipboardLinuxTools {
		templates[tool.name] = tool.template()
	}
	cases := make([]copyClipboardLinuxCase, 0, 16)
	for _, scenario := range copyClipboardLinuxScenarios() {
		cases = append(cases, runCopyClipboardLinuxScenario(t, self, templates, scenario))
	}

	doc := copyClipboardLinuxDocument{
		SchemaVersion: 1,
		Oracle: copyClipboardLinuxOracle{
			GoVersion:      localMCPOracleGoVersion,
			GOOS:           "linux",
			AtottoVersion:  "v0.1.4",
			SourceFiles:    copyClipboardLinuxSourceFiles,
			SourceHash:     executeAPIRequestWorkingDigest(t, root, copyClipboardLinuxSourceFiles),
			GeneratorFiles: copyClipboardLinuxGeneratorFiles,
			GeneratorHash:  executeAPIRequestWorkingDigest(t, root, copyClipboardLinuxGeneratorFiles),
		},
		Note:              "Real Go tools/call copy_to_clipboard on GOOS=linux with the production clipboard.DefaultClipboard() (atotto/clipboard command backend, selected at process start from PATH and WAYLAND_DISPLAY) and fake POSIX-shell tools on a disposable PATH; no clipboard.SetClipboard. Source digests are working-tree digests of the files listed, not a commit pin.",
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
		body := renderCopyClipboardLinuxTool(templates[name], rec, scenario.ToolExit)
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
	var observed copyClipboardLinuxCase
	if err := json.Unmarshal(raw, &observed); err != nil {
		t.Fatalf("%s result decode: %v", scenario.Name, err)
	}
	observed.copyClipboardLinuxScenario = scenario
	observed.ToolCalls = readCopyClipboardLinuxCalls(t, rec)
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
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:            "clipboard-linux-fixture",
		Tier:            config.StrPtr("admin"),
		AllowedPaths:    []string{"*"},
		CanUseClipboard: config.BoolPtr(true),
		ApprovalMode:    config.StrPtr("none"),
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
		inputs = append(inputs, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"copy_to_clipboard","arguments":{"path":"github"}}}`, index+2))
	}
	handler := NewProtocolHandler("symvault", "0.0.0-copy-clipboard-linux-fixture", srv)
	outputs := make([]json.RawMessage, 0, len(inputs))
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
	encoded, err := json.Marshal(copyClipboardLinuxCase{Input: inputs, Output: outputs})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(request.Out, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
