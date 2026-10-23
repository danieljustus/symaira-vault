package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunRefusesNonLinuxHosts(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("refusal only applies off Linux")
	}
	err := run(filepath.Join(t.TempDir(), "out.json"), false, pinnedOracleCommit, false)
	if err == nil || !strings.Contains(err.Error(), "must run on Linux") {
		t.Fatalf("non-Linux run must be refused, got %v", err)
	}
}

func TestEveryToolSpecHasATemplateWithAllPlaceholders(t *testing.T) {
	templates := fakeToolTemplates()
	if len(templates) != len(toolSpecs) {
		t.Fatalf("templates %d != specs %d", len(templates), len(toolSpecs))
	}
	for name, body := range templates {
		if !strings.HasPrefix(body, "#!/bin/sh\n") {
			t.Errorf("%s: missing shebang", name)
		}
		for _, p := range []string{"@REC@", "@EXIT@", "@FOCUS1@", "@FOCUS2@", "@FOCUSEXIT@"} {
			if !strings.Contains(body, p) {
				t.Errorf("%s: placeholder %s missing", name, p)
			}
		}
		if strings.Contains(body, "$(printf") || strings.Contains(body, "eval") {
			t.Errorf("%s: unexpected shell construct", name)
		}
	}
	if len(scriptPlaceholders) != 5 {
		t.Fatalf("placeholder list drifted: %v", scriptPlaceholders)
	}
}

func TestSandboxRecordsArgvAndStdinOfRealProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fake tools")
	}
	sb, err := newSandbox([]string{"xclip", "wtype"}, toolParams{exit: 3}, "pasted")
	if err != nil {
		t.Fatal(err)
	}
	defer sb.close()

	cmd := exec.Command(filepath.Join(sb.bin, "xclip"), "-in", "-selection", "clipboard") // #nosec G204 -- fake tool created by this test
	cmd.Stdin = strings.NewReader("a b\nc")
	err = cmd.Run()
	var exitErr *exec.ExitError
	if err == nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("expected exit 3, got %v", err)
	}
	out, err := exec.Command(filepath.Join(sb.bin, "xclip"), "-out").Output() // #nosec G204 -- fake tool created by this test
	if err == nil {
		t.Fatalf("paste should also exit 3, got output %q", out)
	}
	if string(out) != "pasted" {
		t.Fatalf("paste output = %q", out)
	}
	calls, err := sb.readCalls()
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Tool != "xclip" || calls[0].Mode != "copy" || strings.Join(calls[0].Argv, " ") != "-in -selection clipboard" || calls[0].Stdin != "a b\nc" {
		t.Fatalf("copy call = %+v", calls[0])
	}
	if calls[1].Mode != "paste" || calls[1].Stdin != "" {
		t.Fatalf("paste call = %+v", calls[1])
	}
}

func TestParseCallRejectsMalformedRecords(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"short":    "tool\nmode\n",
		"badcount": "tool\nmode\nx\n",
		"mismatch": "tool\nmode\n2\nonly-one\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := parseCall(path); err == nil {
			t.Errorf("%s: malformed record accepted", name)
		}
	}
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte("t\ncopy\n1\nx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	call, err := parseCall(good)
	if err != nil || call.Tool != "t" || call.Mode != "copy" || len(call.Argv) != 1 {
		t.Fatalf("good record: %+v %v", call, err)
	}
}

func TestNewSandboxRejectsUnknownTool(t *testing.T) {
	if _, err := newSandbox([]string{"definitely-not-a-tool"}, toolParams{}, ""); err == nil {
		t.Fatal("unknown tool accepted")
	}
}

func TestWindowsExtractionReadsTheRealSources(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	extracts, err := extractWindowsConstants(root)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper, probe string
	var commands int
	for _, e := range extracts {
		switch {
		case e.Name == "readSendKeysWrapper":
			wrapper = e.Value
		case e.Name == "foregroundProbe":
			probe = e.Value
		case e.Kind == "exec_command":
			commands++
			if len(e.Argv) != 5 || e.Argv[0] != "powershell.exe" || e.Argv[4] == "" {
				t.Errorf("unexpected powershell argv %q", e.Argv)
			}
		}
	}
	if !strings.Contains(wrapper, "SendKeys($text)") || !strings.Contains(probe, "GetForegroundWindow") || commands != 2 {
		t.Fatalf("extraction incomplete: wrapper=%q probe=%q commands=%d", wrapper, probe, commands)
	}
}

func TestValidateCoverageRejectsWeakAndLeakingCorpora(t *testing.T) {
	good := func() fixture {
		f := fixture{}
		for _, spec := range toolSpecs {
			f.Clipboard = append(f.Clipboard, clipboardCase{Name: spec.name, Payload: "secret", Calls: []recordedCall{{Tool: spec.name, Mode: "copy"}}})
		}
		f.Clipboard = append(f.Clipboard, clipboardCase{Name: "fail", CopyError: "exit status 1"})
		f.Autotype = []autotypeCase{{Name: "changed", Error: "autotype: active window changed between capture and send"}}
		return f
	}
	if err := validateCoverage(good()); err != nil {
		t.Fatalf("good corpus rejected: %v", err)
	}
	f := good()
	f.Clipboard = f.Clipboard[1:]
	if err := validateCoverage(f); err == nil || !strings.Contains(err.Error(), "never executed") {
		t.Fatalf("missing tool accepted: %v", err)
	}
	f = good()
	f.Clipboard[0].Calls[0].Argv = []string{"secret"}
	if err := validateCoverage(f); err == nil || !strings.Contains(err.Error(), "leaked into argv") {
		t.Fatalf("argv leak accepted: %v", err)
	}
	f = good()
	f.Autotype = nil
	if err := validateCoverage(f); err == nil || !strings.Contains(err.Error(), "discriminating") {
		t.Fatalf("corpus without focus abort accepted: %v", err)
	}
}

func TestScenarioNamesAreUniqueAndNonEmpty(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range clipboardScenarios() {
		if c.Name == "" || seen["cb:"+c.Name] {
			t.Fatalf("bad clipboard scenario name %q", c.Name)
		}
		seen["cb:"+c.Name] = true
	}
	for _, c := range autotypeScenarios() {
		if c.Name == "" || seen["at:"+c.Name] {
			t.Fatalf("bad autotype scenario name %q", c.Name)
		}
		seen["at:"+c.Name] = true
		if c.Tools == nil {
			t.Fatalf("%s: Tools must be non-nil for stable JSON", c.Name)
		}
	}
}

func TestDependencyRecordPinsTheClipboardBackend(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	dep, err := dependencyRecord(root)
	if err != nil || !strings.Contains(dep, "github.com/atotto/clipboard v0.1.4 h1:") {
		t.Fatalf("dependency record = %q %v", dep, err)
	}
}

func TestMarshalJSONDoesNotHTMLEscape(t *testing.T) {
	out, err := marshalJSON(map[string]string{"k": "<&>"})
	if err != nil || !strings.Contains(string(out), "<&>") {
		t.Fatalf("marshal = %q %v", out, err)
	}
}
