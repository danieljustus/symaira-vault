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
	inputs := []scenarioInput{{name: "install", state: stateUninitialized, args: []string{"mcp", "install", "x"}, platforms: darwinOnly, serviceManager: true}}
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

// Negative control: a scenario outside the service-manager commands that calls
// launchctl or systemctl, on any platform, fails the recording instead of being
// recorded (and later projected away by a foreign host's --check).
func TestRecordScenariosRefusesServiceManagerCallsOutsideTheServiceCommands(t *testing.T) {
	skipWithoutPOSIXShell(t)
	for _, tool := range serviceManagerTools {
		oracle := fakeOracle(t, tool+` --user daemon-reload; echo ok`)
		inputs := []scenarioInput{{name: "unrelated", state: stateUninitialized, args: []string{"lock", "x"}}}
		_, err := recordScenarios(oracle, nil, inputs)
		if err == nil || !strings.Contains(err.Error(), "scenario unrelated is not a service-manager command") || !strings.Contains(err.Error(), tool+" --user daemon-reload") {
			t.Errorf("%s: err = %v, want a refusal naming the call", tool, err)
		}
		inputs[0].serviceManager = true
		if cases, err := recordScenarios(oracle, nil, inputs); err != nil || len(cases) != 1 || !cases[0].serviceManager {
			t.Errorf("%s: a service-manager command may call it: %+v, %v", tool, cases, err)
		}
	}
}

func TestHostDependenceIsBookkept(t *testing.T) {
	for _, item := range scenarioHostDependence {
		if item.Reason == "" || len(item.Platforms) == 0 {
			t.Errorf("host dependence %+v needs a reason and a platform", item)
		}
	}
	orig, origServiceManager := scenarioHostDependence, serviceManagerCommands
	t.Cleanup(func() { scenarioHostDependence, serviceManagerCommands = orig, origServiceManager })

	inventory := []nilArgsEntry{{Path: "symvault lock", Runnable: true}, {Path: "symvault mcp install", Runnable: true}}
	withBookkeeping(t, nil, nil)
	scenarioHostDependence = []hostDependence{{"symvault mcp install", darwinOnly, "launchd path"}}
	serviceManagerCommands = []string{"symvault mcp install"}
	inputs, err := extraPositionalInputs(inventory)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range inputs {
		isInstall := strings.Contains(in.name, "mcp_install")
		if isInstall != (len(in.platforms) == 1 && in.platforms[0] == "darwin") {
			t.Errorf("%s platforms = %v", in.name, in.platforms)
		}
		if in.serviceManager != isInstall {
			t.Errorf("%s serviceManager = %v", in.name, in.serviceManager)
		}
	}

	// A host-dependent command that is not a service-manager command, and a
	// stale service-manager command, are bookkeeping errors.
	serviceManagerCommands = nil
	if _, err := extraPositionalInputs(inventory); err == nil || !strings.Contains(err.Error(), "not in serviceManagerCommands") {
		t.Fatalf("err = %v, want a host-dependent command outside serviceManagerCommands", err)
	}
	scenarioHostDependence = nil
	serviceManagerCommands = []string{"symvault gone"}
	if _, err := extraPositionalInputs(inventory); err == nil || !strings.Contains(err.Error(), "serviceManagerCommands") {
		t.Fatalf("err = %v, want a stale service-manager command error", err)
	}
	serviceManagerCommands = []string{"symvault mcp install"}

	scenarioHostDependence = []hostDependence{{"symvault gone", darwinOnly, "r"}}
	if _, err := extraPositionalInputs(inventory); err == nil || !strings.Contains(err.Error(), "scenarioHostDependence") {
		t.Fatalf("err = %v, want a stale host-dependence error", err)
	}
}

func foreignFixtures() (recorded, fresh fixture) {
	obs := func(stdout string, args ...string) observation {
		return observation{Args: args, Stdout: stdout, Stderr: "warn\n"}
	}
	recorded = fixture{
		SchemaVersion: 1,
		GeneratedOn:   "darwin",
		Usage:         []usageCase{{Name: "u", Observation: observation{Stderr: "same\n"}}},
		ExtraPositionals: []scenarioCase{
			{Name: "install", State: stateUninitialized, Platforms: darwinOnly, Observation: obs("ok\n  Service file: LaunchAgents\n  Port: 1\n", "mcp", "install", "x"), HostToolCalls: []string{"launchctl load p"}},
			{Name: "uninstall", State: stateUninitialized, Observation: obs("Service uninstalled successfully.\n", "mcp", "uninstall", "x"), HostToolCalls: []string{"launchctl unload p"}},
			{Name: "lock", State: stateUninitialized, Observation: observation{Args: []string{"lock", "x"}, ExitCode: 3, Stderr: "not initialized\n"}},
		},
		RunFileUseArgv: []scenarioCase{{Name: "run", State: stateInitialized, Observation: observation{Stdout: "x\n"}}},
	}
	fresh = fixture{
		SchemaVersion: 1,
		GeneratedOn:   "linux",
		Usage:         []usageCase{{Name: "u", Observation: observation{Stderr: "same\n"}}},
		ExtraPositionals: []scenarioCase{
			{Name: "install", State: stateUninitialized, Platforms: darwinOnly, serviceManager: true, Observation: obs("ok\n  Service file: systemd\n  Port: 1\n", "mcp", "install", "x"), HostToolCalls: []string{"systemctl --user start x"}},
			{Name: "uninstall", State: stateUninitialized, serviceManager: true, Observation: obs("Service uninstalled successfully.\n", "mcp", "uninstall", "x"), HostToolCalls: []string{"systemctl --user stop x"}},
			{Name: "lock", State: stateUninitialized, Observation: observation{Args: []string{"lock", "x"}, ExitCode: 3, Stderr: "not initialized\n"}},
		},
		RunFileUseArgv: []scenarioCase{{Name: "run", State: stateInitialized, Observation: observation{Stdout: "x\n"}}},
	}
	return recorded, fresh
}

func TestProjectOnForeignHostTakesOnlyThePlatformBoundParts(t *testing.T) {
	recorded, fresh := foreignFixtures()
	raw, err := marshalJSON(recorded)
	if err != nil {
		t.Fatal(err)
	}
	projected, taken, err := projectOnForeignHost(raw, fresh, "linux")
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalJSON(projected)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("projection differs from the recording:\n%s\nvs\n%s", got, raw)
	}
	if taken.observations != 1 || taken.calls != 2 {
		t.Fatalf("taken = %+v, want 1 service-file line and 2 call lists", taken)
	}

	// Negative controls: any difference outside the platform-bound parts is stale.
	for name, mutate := range map[string]func(f *fixture){
		"untagged scenario output":      func(f *fixture) { f.ExtraPositionals[2].Observation.Stderr = "different\n" },
		"untagged uninstall text":       func(f *fixture) { f.ExtraPositionals[1].Observation.Stdout = "different\n" },
		"usage case":                    func(f *fixture) { f.Usage[0].Observation.Stderr = "different\n" },
		"run/file-use scenario":         func(f *fixture) { f.RunFileUseArgv[0].Observation.Stdout = "different\n" },
		"scenario platforms":            func(f *fixture) { f.ExtraPositionals[0].Platforms = nil },
		"tagged scenario argument":      func(f *fixture) { f.ExtraPositionals[0].Observation.Args[2] = "y" },
		"tagged scenario argument name": func(f *fixture) { f.ExtraPositionals[0].Observation.Args = []string{"mcp", "status", "x"} },
		"tagged scenario exit status":   func(f *fixture) { f.ExtraPositionals[0].Observation.ExitCode = 1 },
		"tagged scenario stderr":        func(f *fixture) { f.ExtraPositionals[0].Observation.Stderr = "different\n" },
		"tagged scenario other stdout line": func(f *fixture) {
			f.ExtraPositionals[0].Observation.Stdout = "ok\n  Service file: systemd\n  Port: 2\n"
		},
		"tagged scenario first stdout line": func(f *fixture) {
			f.ExtraPositionals[0].Observation.Stdout = "failed\n  Service file: systemd\n  Port: 1\n"
		},
		"tagged scenario extra stdout line": func(f *fixture) {
			f.ExtraPositionals[0].Observation.Stdout = "ok\n  Service file: systemd\n  Port: 1\n  More: 1\n"
		},
		"tagged scenario moved service line": func(f *fixture) {
			f.ExtraPositionals[0].Observation.Stdout = "ok\n  Port: 1\n  Service file: systemd\n"
		},
		"tagged scenario without service line": func(f *fixture) {
			f.ExtraPositionals[0].Observation.Stdout = "ok\n  Port: 1\n"
		},
		"tagged scenario not a service command": func(f *fixture) { f.ExtraPositionals[0].serviceManager = false },
		"untagged service scenario argument":    func(f *fixture) { f.ExtraPositionals[1].Observation.Args[2] = "y" },
		"untagged service scenario exit status": func(f *fixture) { f.ExtraPositionals[1].Observation.ExitCode = 4 },
		"service scenario stdout in untagged service scenario": func(f *fixture) {
			f.ExtraPositionals[1].Observation.Stdout = "Service uninstalled successfully.\n  Service file: x\n"
		},
		"host-tool call of an unrelated scenario": func(f *fixture) {
			f.ExtraPositionals[2].HostToolCalls = []string{"systemctl --user daemon-reload"}
		},
		"host-tool call of a run/file-use scenario": func(f *fixture) {
			f.RunFileUseArgv[0].HostToolCalls = []string{"launchctl list"}
		},
	} {
		_, fresh := foreignFixtures()
		mutate(&fresh)
		projected, _, err := projectOnForeignHost(raw, fresh, "linux")
		if err != nil {
			t.Fatal(err)
		}
		again, err := marshalJSON(projected)
		if err != nil {
			t.Fatal(err)
		}
		if string(again) == string(raw) {
			t.Errorf("a changed %s was projected away", name)
		}
	}

	// A recording made on this host, or an unreadable one, is never projected.
	if _, _, err := projectOnForeignHost(raw, fresh, "darwin"); err == nil {
		t.Error("a recording of this host was projected")
	}
	if _, _, err := projectOnForeignHost([]byte("not json"), fresh, "linux"); err == nil {
		t.Error("an unreadable recording was projected")
	}
}

func TestTakeServiceFileLines(t *testing.T) {
	const line = serviceFileLinePrefix
	got, taken := takeServiceFileLines("a\n"+line+"x\nb\n", "a\n"+line+"y\nb\n")
	if got != "a\n"+line+"y\nb\n" || taken != 1 {
		t.Fatalf("got %q, %d", got, taken)
	}
	// Nothing to take: no service-file line on the recorded side or beyond it.
	for _, recorded := range []string{"a\nz\nb\n", "a\n"} {
		got, taken := takeServiceFileLines("a\n"+line+"x\nb\n", recorded)
		if got != "a\n"+line+"x\nb\n" || taken != 0 {
			t.Errorf("recorded %q: got %q, %d", recorded, got, taken)
		}
	}
}

func TestRunsOn(t *testing.T) {
	if !runsOn(nil, "linux") || !runsOn(darwinOnly, "darwin") || runsOn(darwinOnly, "linux") {
		t.Fatal("runsOn disagrees with the platform tags")
	}
}
