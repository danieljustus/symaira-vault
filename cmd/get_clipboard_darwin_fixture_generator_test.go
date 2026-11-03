//go:build darwin

package cmd

// PLATFORM-001-FIDELITY: `symvault get <path.field>` on a terminal with the
// clipboard Go really uses on macOS.
//
// get_clipboard.json records the command with an in-memory clipboard. Here the
// production crud.GetClipboard (clipboard.DefaultClipboard() -> atotto
// clipboard v0.1.4, which runs `pbcopy`/`pbpaste` found through PATH) stays in
// place and PATH holds only POSIX-shell fake tools, so the recorded stderr is
// the text of Go's *exec.ExitError, *fs.PathError and exec.Error values:
// `exit status N`, `signal: <name>`, `write |1: broken pipe` and
// `exec: "pbcopy": executable file not found in $PATH`. Nothing touches the
// real pasteboard. Only the terminal decision and the auto-clear timer are
// stubbed, exactly as in get_clipboard.json.
//
// The same file records Go's darwin signal-name table by executing
// syscall.Signal.String, and extracts (does not execute) the Linux table from
// the pinned toolchain's zerrors_linux_*.go.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	clipboardapp "github.com/danieljustus/symaira-vault/internal/clipboard"
)

const getClipboardDarwinFixture = "testdata/port/platform/get_clipboard_darwin.json"

// darwinScenario is the recorded input of one fake-tool run.
type darwinScenario struct {
	Name         string `json:"name"`
	Secret       string `json:"secret"`
	SecretRepeat int    `json:"secret_repeat,omitempty"`
	AutoClear    int    `json:"auto_clear_seconds"`
	// Copy and Paste behaviours: ok | exit:N | signal:NAME | closes_stdin:N | missing.
	Copy  string `json:"copy"`
	Paste string `json:"paste"`
	// CopyFailOnCall limits a failing Copy behaviour to the nth pbcopy call
	// (2 = the clear); 0 means every call.
	CopyFailOnCall int `json:"copy_fail_on_call,omitempty"`
	// ToolStderr is a message the failing fake tool writes to its own stderr
	// just before it fails (ADR 0034 item 23: a real pbcopy explains itself on
	// stderr). atotto v0.1.4 never connects the tool's stderr, so Go's error
	// text must stay `exit status N` / `signal: ...` and never contain it.
	ToolStderr string `json:"tool_stderr,omitempty"`
}

type darwinCall struct {
	Tool  string `json:"tool"`
	Stdin string `json:"stdin"`
}

type darwinResult struct {
	darwinScenario
	PbcopyScript  string       `json:"pbcopy_script,omitempty"`
	PbpasteScript string       `json:"pbpaste_script,omitempty"`
	Stdout        string       `json:"stdout"`
	Stderr        string       `json:"stderr"`
	ExitCode      int          `json:"exit_code"`
	ToolCalls     []darwinCall `json:"tool_calls"`
}

type darwinFixture struct {
	Commit        string            `json:"commit"`
	GOOS          string            `json:"goos"`
	GoVersion     string            `json:"go_version"`
	Atotto        string            `json:"atotto_clipboard_version"`
	SourceFiles   []string          `json:"source_files"`
	SourceHash    string            `json:"source_hash"`
	GeneratorHash string            `json:"generator_hash"`
	Note          string            `json:"note"`
	DarwinSignals map[string]string `json:"darwin_signal_names_executed"`
	LinuxSignals  map[string]string `json:"linux_signal_names_extracted_not_executed"`
	Scenarios     []darwinResult    `json:"scenarios"`
}

func TestGenerateGetClipboardDarwinFixture(t *testing.T) {
	mode := os.Getenv("SYMVAULT_GET_CLIPBOARD_FIXTURE")
	if mode == "" {
		t.Skip("set SYMVAULT_GET_CLIPBOARD_FIXTURE=write or check")
	}
	const root = ".."
	const pin = "5229f9490cd25c22adb641677546a57802417304"
	files := []string{
		"go.mod",
		"go.sum",
		"cmd/crud/get.go",
		"internal/clipboard/clipboard.go",
		"internal/clipboard/clipboard_signal_unix.go",
		"internal/clipboard/interface.go",
		"internal/clipboard/provider.go",
		"internal/clipboard/system_clipboard.go",
		"internal/ui/cliout/cliout.go",
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
	var generator []byte
	for _, name := range []string{"get_clipboard_fixture_generator_test.go", "get_clipboard_darwin_fixture_generator_test.go"} {
		source, err := os.ReadFile(name) // #nosec G304 -- fixed compiled-in generator list
		if err != nil {
			t.Fatal(err)
		}
		generator = append(generator, source...)
	}
	generatorHash := sha256.Sum256(generator)

	out := darwinFixture{
		Commit:        pin,
		GOOS:          runtime.GOOS,
		GoVersion:     runtime.Version(),
		Atotto:        "v0.1.4",
		SourceFiles:   files,
		SourceHash:    hex.EncodeToString(hash.Sum(nil)),
		GeneratorHash: hex.EncodeToString(generatorHash[:]),
		Note:          "Recorded from the production `get` command (cobra root + cli.ExecuteRoot) with clipboard.DefaultClipboard() (atotto v0.1.4 pbcopy/pbpaste) over POSIX-shell fake tools on a disposable PATH; no real pasteboard was touched.",
		DarwinSignals: map[string]string{},
		LinuxSignals:  extractLinuxSignalNames(t),
	}
	for n := 0; n <= 40; n++ {
		out.DarwinSignals[strconv.Itoa(n)] = syscall.Signal(n).String()
	}
	for _, s := range getClipboardDarwinScenarios() {
		out.Scenarios = append(out.Scenarios, runGetClipboardDarwinScenario(t, s))
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, getClipboardDarwinFixture)
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
		t.Fatal("get clipboard darwin fixture stale; regenerate with SYMVAULT_GET_CLIPBOARD_FIXTURE=write")
	}
}

// extractLinuxSignalNames reads the `signals` table of the pinned toolchain's
// linux/amd64 and linux/arm64 syscall packages with go/parser (they are build
// constrained away on this host) and requires both to agree.
func extractLinuxSignalNames(t *testing.T) map[string]string {
	t.Helper()
	goroot := runtime.GOROOT()
	tables := map[string]map[string]string{}
	for _, arch := range []string{"amd64", "arm64"} {
		path := filepath.Join(goroot, "src", "syscall", "zerrors_linux_"+arch+".go")
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		table := map[string]string{}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || len(value.Names) != 1 || value.Names[0].Name != "signals" {
					continue
				}
				literal := value.Values[0].(*ast.CompositeLit)
				for _, element := range literal.Elts {
					pair := element.(*ast.KeyValueExpr)
					key, err := strconv.Unquote(pair.Key.(*ast.BasicLit).Value)
					if err != nil {
						key = pair.Key.(*ast.BasicLit).Value
					}
					name, err := strconv.Unquote(pair.Value.(*ast.BasicLit).Value)
					if err != nil {
						t.Fatal(err)
					}
					table[key] = name
				}
			}
		}
		if len(table) == 0 {
			t.Fatalf("no signals table in %s", path)
		}
		tables[arch] = table
	}
	keys := func(m map[string]string) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if fmt.Sprint(keys(tables["amd64"]), tables["amd64"]) != fmt.Sprint(keys(tables["arm64"]), tables["arm64"]) {
		t.Fatal("linux/amd64 and linux/arm64 signal tables differ")
	}
	return tables["amd64"]
}

func getClipboardDarwinScenarios() []darwinScenario {
	var out []darwinScenario
	add := func(s darwinScenario) {
		if s.Copy == "" {
			s.Copy = "ok"
		}
		if s.Paste == "" {
			s.Paste = "ok"
		}
		if s.AutoClear == 0 {
			s.AutoClear = 1
		}
		if s.Secret == "" {
			s.Secret = "s3cret-pb"
		}
		out = append(out, s)
	}
	add(darwinScenario{Name: "cleared_honest"})
	add(darwinScenario{Name: "copy_exit_1", Copy: "exit:1"})
	add(darwinScenario{Name: "copy_exit_3", Copy: "exit:3"})
	add(darwinScenario{Name: "copy_exit_127", Copy: "exit:127"})
	add(darwinScenario{Name: "copy_missing", Copy: "missing"})
	for _, sig := range []string{"HUP", "INT", "QUIT", "KILL", "USR1", "USR2", "ALRM", "TERM"} {
		add(darwinScenario{Name: "copy_signal_" + strings.ToLower(sig), Copy: "signal:" + sig})
	}
	add(darwinScenario{Name: "copy_large_payload_tool_closes_stdin_exit_0", Secret: "0123456789abcdef", SecretRepeat: 60000, Copy: "closes_stdin:0"})
	add(darwinScenario{Name: "copy_large_payload_tool_closes_stdin_exit_1", Secret: "0123456789abcdef", SecretRepeat: 60000, Copy: "closes_stdin:1"})
	add(darwinScenario{Name: "clear_exit_3", Copy: "exit:3", CopyFailOnCall: 2})
	add(darwinScenario{Name: "clear_signal_term", Copy: "signal:TERM", CopyFailOnCall: 2})
	add(darwinScenario{Name: "paste_exit_1", Paste: "exit:1"})
	add(darwinScenario{Name: "paste_exit_2", Paste: "exit:2"})
	add(darwinScenario{Name: "paste_signal_term", Paste: "signal:TERM"})
	add(darwinScenario{Name: "paste_signal_kill", Paste: "signal:KILL"})
	add(darwinScenario{Name: "paste_missing", Paste: "missing"})
	add(darwinScenario{Name: "paste_missing_and_clear_exit_3", Copy: "exit:3", CopyFailOnCall: 2, Paste: "missing"})
	// A real pbcopy/pbpaste says why it failed on stderr (ADR 0034 item 23).
	add(darwinScenario{Name: "copy_exit_1_tool_stderr", Copy: "exit:1", ToolStderr: "pbcopy: unable to connect to the pasteboard server"})
	add(darwinScenario{Name: "copy_signal_kill_tool_stderr", Copy: "signal:KILL", ToolStderr: "pbcopy: terminated by the window server"})
	add(darwinScenario{Name: "clear_exit_3_tool_stderr", Copy: "exit:3", CopyFailOnCall: 2, ToolStderr: "pbcopy: pasteboard is locked"})
	add(darwinScenario{Name: "paste_exit_1_tool_stderr", Paste: "exit:1", ToolStderr: "pbpaste: no pasteboard available"})
	return out
}

// renderPbcopy returns the fake pbcopy: it records the call and its stdin,
// keeps the last payload as the "clipboard", and fails as the scenario says.
func renderPbcopy(s darwinScenario) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("REC='@REC@'\n")
	b.WriteString("n=$(/bin/cat \"$REC/seq\" 2>/dev/null || echo 0)\n")
	b.WriteString("n=$((n+1))\n")
	b.WriteString("echo \"$n\" > \"$REC/seq\"\n")
	b.WriteString("printf '%s\\n' pbcopy > \"$REC/call.$n\"\n")
	kind, arg, _ := strings.Cut(s.Copy, ":")
	if kind == "closes_stdin" {
		b.WriteString("exec 0<&-\n")
		fmt.Fprintf(&b, "exit %s\n", arg)
		return b.String()
	}
	b.WriteString("/bin/cat > \"$REC/call.$n.stdin\"\n")
	b.WriteString("/bin/cp \"$REC/call.$n.stdin\" \"$REC/clip\"\n")
	failure := ""
	switch kind {
	case "exit":
		failure = "exit " + arg
	case "signal":
		failure = "kill -s " + arg + " $$"
	}
	if failure != "" && s.ToolStderr != "" {
		failure = "printf '%s\\n' '" + s.ToolStderr + "' >&2; " + failure
	}
	if failure != "" {
		if s.CopyFailOnCall > 0 {
			fmt.Fprintf(&b, "if [ \"$n\" = %d ]; then %s; fi\n", s.CopyFailOnCall, failure)
		} else {
			b.WriteString(failure + "\n")
		}
	}
	b.WriteString("exit 0\n")
	return b.String()
}

func renderPbpaste(s darwinScenario) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("REC='@REC@'\n")
	b.WriteString("n=$(/bin/cat \"$REC/seq\" 2>/dev/null || echo 0)\n")
	b.WriteString("n=$((n+1))\n")
	b.WriteString("echo \"$n\" > \"$REC/seq\"\n")
	b.WriteString("printf '%s\\n' pbpaste > \"$REC/call.$n\"\n")
	kind, arg, _ := strings.Cut(s.Paste, ":")
	switch kind {
	case "exit":
		if s.ToolStderr != "" {
			fmt.Fprintf(&b, "printf '%%s\\n' '%s' >&2\n", s.ToolStderr)
		}
		fmt.Fprintf(&b, "exit %s\n", arg)
	case "signal":
		if s.ToolStderr != "" {
			fmt.Fprintf(&b, "printf '%%s\\n' '%s' >&2\n", s.ToolStderr)
		}
		fmt.Fprintf(&b, "kill -s %s $$\n", arg)
	default:
		b.WriteString("/bin/cat \"$REC/clip\" 2>/dev/null\n")
		b.WriteString("exit 0\n")
	}
	return b.String()
}

func runGetClipboardDarwinScenario(t *testing.T, s darwinScenario) darwinResult {
	t.Helper()
	tools := t.TempDir()
	rec := t.TempDir()
	res := darwinResult{darwinScenario: s}
	if s.Copy != "missing" {
		res.PbcopyScript = renderPbcopy(s)
		writeDarwinTool(t, tools, "pbcopy", strings.ReplaceAll(res.PbcopyScript, "@REC@", rec))
	}
	if s.Paste != "missing" {
		res.PbpasteScript = renderPbpaste(s)
		writeDarwinTool(t, tools, "pbpaste", strings.ReplaceAll(res.PbpasteScript, "@REC@", rec))
	}
	t.Setenv("PATH", tools)
	scenario := getClipboardScenario{
		Name:            s.Name,
		Secret:          s.Secret,
		SecretRepeat:    s.SecretRepeat,
		AutoClear:       s.AutoClear,
		Terminal:        true,
		TimerStubMillis: 150,
		ReadMode:        "honest",
	}
	got := runGetClipboardScenarioWith(t, scenario, clipboardapp.NewSystemClipboard)
	res.Stdout = got.Stdout
	res.Stderr = got.Stderr
	res.ExitCode = got.ExitCode
	res.ToolCalls = readDarwinCalls(t, rec)
	return res
}

func writeDarwinTool(t *testing.T, dir, name, script string) {
	t.Helper()
	// #nosec G306 -- an executable fake tool inside a test-owned temp dir
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
}

func readDarwinCalls(t *testing.T, rec string) []darwinCall {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(rec, "seq")) // #nosec G304 -- test-owned temp dir
	if err != nil {
		return []darwinCall{}
	}
	total, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	calls := []darwinCall{}
	for n := 1; n <= total; n++ {
		name, err := os.ReadFile(filepath.Join(rec, fmt.Sprintf("call.%d", n))) // #nosec G304 -- test-owned temp dir
		if err != nil {
			t.Fatal(err)
		}
		call := darwinCall{Tool: strings.TrimSpace(string(name))}
		if stdin, err := os.ReadFile(filepath.Join(rec, fmt.Sprintf("call.%d.stdin", n))); err == nil { // #nosec G304 -- test-owned temp dir
			call.Stdin = string(stdin)
			if len(call.Stdin) > 64 {
				call.Stdin = fmt.Sprintf("<%d bytes>", len(stdin))
			}
		}
		calls = append(calls, call)
	}
	return calls
}
