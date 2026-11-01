package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The sandbox must never reach the developer's launchd/systemd, keychain,
// clipboard or notification tools. These tests prove the stand-ins win the PATH
// lookup, log what they were called with, and that the guard rejects every call
// of a tool no scenario may use.

func TestSandboxPathHoldsOnlyStandInsAndSystemDirectories(t *testing.T) {
	skipWithoutPOSIXShell(t)
	box, err := newSandbox()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(box.root) }()
	var path string
	for _, entry := range box.env {
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			path = value
		}
	}
	if want := box.hostToolsDir() + ":" + sandboxPathSystem; path != want {
		t.Fatalf("sandbox PATH = %q, want %q", path, want)
	}
	for _, name := range hostToolNames() {
		cmd := exec.Command("/bin/sh", "-c", "command -v "+name) // #nosec G204 -- fixed shell snippet, tool name from the package table
		cmd.Env = []string{"PATH=" + path}
		got, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s is not resolvable on the sandbox PATH: %v", name, err)
		}
		if want := filepath.Join(box.hostToolsDir(), name); strings.TrimSpace(string(got)) != want {
			t.Errorf("%s resolves to %q, want the stand-in %q", name, strings.TrimSpace(string(got)), want)
		}
	}
}

func TestStandInsLogTheirArgvAndSucceedWithoutEnvironment(t *testing.T) {
	skipWithoutPOSIXShell(t)
	box, err := newSandbox()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(box.root) }()
	for _, argv := range [][]string{
		{"launchctl", "unload", filepath.Join(box.root, "home", "LaunchAgents", "x.plist")},
		{"launchctl", "list", "com.symvault.mcp"},
		{"systemctl", "--user", "daemon-reload"},
		{"security"},
	} {
		// A service manager is started with a cleared or filtered environment.
		cmd := exec.Command(filepath.Join(box.hostToolsDir(), argv[0]), argv[1:]...) // #nosec G204 -- stand-in inside the temporary sandbox
		cmd.Env = []string{}
		if out, err := cmd.CombinedOutput(); err != nil || len(out) != 0 {
			t.Fatalf("%v: err %v, output %q", argv, err, out)
		}
	}
	calls, err := box.hostToolCalls()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"launchctl unload " + rootMarker + "/home/LaunchAgents/x.plist",
		"launchctl list com.symvault.mcp",
		"systemctl --user daemon-reload",
		"security",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls = %q, want %q", calls, want)
	}
	if got := refusedHostCalls(calls); len(got) != 1 || got[0] != "security" {
		t.Fatalf("refused = %q, want only the keychain tool", got)
	}
}

func TestRunRecordsServiceManagerCallsAndRefusesOtherHostTools(t *testing.T) {
	script := fakeOracle(t, `launchctl unload "$HOME/LaunchAgents/p.plist"; launchctl load "$HOME/LaunchAgents/p.plist"; echo done`)
	res, err := run(script, []string{"mcp", "install"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"launchctl unload " + rootMarker + "/home/LaunchAgents/p.plist",
		"launchctl load " + rootMarker + "/home/LaunchAgents/p.plist",
	}
	if strings.Join(res.hostCalls, "\n") != strings.Join(want, "\n") || res.obs.Stdout != "done\n" {
		t.Fatalf("result = %+v", res)
	}
	quiet, err := run(fakeOracle(t, "echo none"), nil, nil)
	if err != nil || len(quiet.hostCalls) != 0 {
		t.Fatalf("a run without host calls = %+v, %v", quiet, err)
	}
	for _, tool := range refusedHostTools {
		_, err := run(fakeOracle(t, tool+" x; exit 0"), []string{"doctor"}, nil)
		if err == nil || !strings.Contains(err.Error(), "reached host tools") || !strings.Contains(err.Error(), tool+" x") {
			t.Errorf("%s: err = %v, want a refusal naming the call", tool, err)
		}
	}
}

func TestRecordScenariosRecordsHostCallsAndFlagsUnstableOnes(t *testing.T) {
	skipWithoutPOSIXShell(t)
	inputs := []scenarioInput{{name: "install", state: stateUninitialized, args: []string{"mcp", "install", "x"}, platforms: darwinOnly}}
	cases, err := recordScenarios(fakeOracle(t, `launchctl load "$HOME/p"; echo ok`), nil, inputs)
	if err != nil || len(cases) != 1 {
		t.Fatalf("cases = %+v, %v", cases, err)
	}
	if got := strings.Join(cases[0].HostToolCalls, "|"); got != "launchctl load "+rootMarker+"/home/p" {
		t.Errorf("host tool calls = %q", got)
	}
	if len(cases[0].Platforms) != 1 || cases[0].Platforms[0] != "darwin" {
		t.Errorf("platforms = %v", cases[0].Platforms)
	}

	counter := filepath.Join(t.TempDir(), "n")
	flaky := fakeOracle(t, `n=$(cat `+counter+` 2>/dev/null || echo 0); n=$((n+1)); echo $n > `+counter+`; [ "$n" = 1 ] || launchctl load x; echo ok`)
	if _, err := recordScenarios(flaky, nil, inputs); err == nil || !strings.Contains(err.Error(), "different host-tool calls") {
		t.Fatalf("err = %v, want a determinism failure for the calls", err)
	}
}

func TestHostDependenceIsBookkept(t *testing.T) {
	for _, item := range scenarioHostDependence {
		if item.Reason == "" || len(item.Platforms) == 0 {
			t.Errorf("host dependence %+v needs a reason and a platform", item)
		}
	}
	orig := scenarioHostDependence
	t.Cleanup(func() { scenarioHostDependence = orig })

	inventory := []nilArgsEntry{{Path: "symvault lock", Runnable: true}, {Path: "symvault mcp install", Runnable: true}}
	withBookkeeping(t, nil, nil)
	scenarioHostDependence = []hostDependence{{"symvault mcp install", darwinOnly, "launchd path"}}
	inputs, err := extraPositionalInputs(inventory)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range inputs {
		isInstall := strings.Contains(in.name, "mcp_install")
		if isInstall != (len(in.platforms) == 1 && in.platforms[0] == "darwin") {
			t.Errorf("%s platforms = %v", in.name, in.platforms)
		}
	}

	scenarioHostDependence = []hostDependence{{"symvault gone", darwinOnly, "r"}}
	if _, err := extraPositionalInputs(inventory); err == nil || !strings.Contains(err.Error(), "scenarioHostDependence") {
		t.Fatalf("err = %v, want a stale host-dependence error", err)
	}
}
