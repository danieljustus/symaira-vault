package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Host tools. Some commands of the pinned CLI act on the machine they run on:
// `mcp|serve install|uninstall` register a user service with launchd (macOS) or
// systemd (Linux), the session code asks launchd for the GUI session, `doctor`
// lists the keychain and probes the clipboard and notification helpers. A
// recording or replay that reached the real tools would register a LaunchAgent
// in the developer's user domain, read the login keychain or write the
// clipboard, so no sandbox runs against the real ones.
//
// Instead every sandbox gets a directory of stand-in executables that come first
// on PATH. Go resolves `launchctl`, `systemctl`, `security` and the others
// through PATH (os/exec.Command; the native CLI does the same), so the stand-ins
// shadow the real tools. Each one appends its argv to a log inside the sandbox
// and exits 0 without output. The log is read after the run:
//
//   - the service managers (serviceManagerTools) are expected: their calls are
//     recorded with the scenario and compared on the recording platform;
//   - any call of another stand-in (refusedHostTools: keychain, clipboard,
//     notification, autotype helpers) fails the generator, so no scenario can
//     reach them unnoticed.
//
// Absolute-path invocations cannot be redirected: `/bin/launchctl unload` of
// `intake watch disable` runs only when a LaunchAgent plist already exists below
// the sandbox HOME, and `/usr/bin/osascript` of the intake notification runs
// only after an import. No scenario of this corpus creates either condition.
const (
	hostToolsDirName = ".host-tools"
	hostToolsLogName = "calls.log"
	// sandboxPathSystem is the rest of the sandbox PATH: the tools the corpus
	// needs (sh, printf, echo, sleep, git) live here on macOS and Linux.
	sandboxPathSystem = "/usr/bin:/bin"
)

// serviceManagerTools are the stand-ins whose calls are part of the contract.
var serviceManagerTools = []string{"launchctl", "systemctl"}

// refusedHostTools are the stand-ins that must never be called.
var refusedHostTools = []string{
	"security", "secret-tool", // keychain / libsecret
	"pbcopy", "pbpaste", "xclip", "xsel", "wl-copy", "wl-paste", // clipboard
	"osascript", "notify-send", "xdotool", // notification and autotype
}

// hostToolSet is the fixture's record of the stand-ins, so the replay installs
// exactly the tools the recording had.
type hostToolSet struct {
	// ServiceManagers are expected callers; their calls are recorded.
	ServiceManagers []string `json:"service_managers"`
	// Refused must never be called.
	Refused []string `json:"refused"`
}

func standInTools() hostToolSet {
	return hostToolSet{
		ServiceManagers: append([]string(nil), serviceManagerTools...),
		Refused:         append([]string(nil), refusedHostTools...),
	}
}

func hostToolNames() []string {
	return append(append([]string(nil), serviceManagerTools...), refusedHostTools...)
}

func isServiceManager(name string) bool {
	for _, tool := range serviceManagerTools {
		if tool == name {
			return true
		}
	}
	return false
}

func (s *sandbox) hostToolsDir() string { return filepath.Join(s.root, hostToolsDirName) }

// shellQuote single-quotes text for a POSIX shell.
func shellQuote(text string) string { return "'" + strings.ReplaceAll(text, "'", `'\''`) + "'" }

// installHostTools writes the stand-in executables. The log path is baked into
// each script: launchctl and systemctl run with a filtered or cleared
// environment, so the stand-ins must not depend on one.
func (s *sandbox) installHostTools() error {
	dir := s.hostToolsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	logPath := filepath.Join(dir, hostToolsLogName)
	for _, name := range hostToolNames() {
		script := "#!/bin/sh\n" +
			"printf '%s %s\\n' " + shellQuote(name) + ` "$*" >> ` + shellQuote(logPath) + "\n" +
			"exit 0\n"
		// #nosec G306 -- the stand-in must be executable; it lives in the disposable sandbox.
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil {
			return err
		}
	}
	return nil
}

// hostToolCalls returns the calls the stand-ins logged, sandbox root normalized,
// one `tool argv...` line each, in call order. No log means no call.
func (s *sandbox) hostToolCalls() ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(s.hostToolsDir(), hostToolsLogName)) // #nosec G304 -- path inside the disposable sandbox
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var calls []string
	for _, line := range strings.Split(strings.TrimSuffix(s.normalize(string(raw)), "\n"), "\n") {
		calls = append(calls, strings.TrimRight(line, " "))
	}
	return calls, nil
}

// refusedHostCalls returns the calls of tools that must never run.
func refusedHostCalls(calls []string) []string {
	var refused []string
	for _, call := range calls {
		name, _, _ := strings.Cut(call, " ")
		if !isServiceManager(name) {
			refused = append(refused, call)
		}
	}
	return refused
}

// guardHostCalls fails when a run reached a keychain, clipboard, notification or
// autotype helper.
func guardHostCalls(args []string, calls []string) error {
	if refused := refusedHostCalls(calls); len(refused) > 0 {
		return fmt.Errorf("%v reached host tools that no scenario may use: %q", args, refused)
	}
	return nil
}

// foreignParts counts what projectOnForeignHost took from the recording.
type foreignParts struct{ observations, calls int }

// projectOnForeignHost is the --check view of a corpus that another platform
// recorded. A scenario of a host-dependent command (its Platforms exclude this
// host) prints the recording platform's service paths, and every service-manager
// call list is the recording platform's (launchctl there, systemctl here). Those
// parts of fresh are replaced by the recorded ones, by scenario name, and
// GeneratedOn is the recording's; every other byte of fresh must match the
// recorded fixture, so the comparison still re-verifies the rest of the corpus
// against this host's oracle. A recording made on this host is not projected.
func projectOnForeignHost(recordedRaw []byte, fresh fixture, goos string) (fixture, foreignParts, error) {
	var recorded fixture
	if err := json.Unmarshal(recordedRaw, &recorded); err != nil {
		return fixture{}, foreignParts{}, fmt.Errorf("parse recorded fixture: %w", err)
	}
	if recorded.GeneratedOn == "" || recorded.GeneratedOn == goos {
		return fixture{}, foreignParts{}, errors.New("recorded on this host or on an unknown one")
	}
	var taken foreignParts
	project := func(fresh, recorded []scenarioCase) []scenarioCase {
		byName := make(map[string]scenarioCase, len(recorded))
		for _, item := range recorded {
			byName[item.Name] = item
		}
		out := make([]scenarioCase, len(fresh))
		for i, item := range fresh {
			out[i] = item
			rec, ok := byName[item.Name]
			if !ok {
				continue
			}
			if !runsOn(item.Platforms, goos) {
				out[i].Observation = rec.Observation
				taken.observations++
			}
			if len(rec.HostToolCalls) > 0 || len(item.HostToolCalls) > 0 {
				out[i].HostToolCalls = rec.HostToolCalls
				taken.calls++
			}
		}
		return out
	}
	fresh.GeneratedOn = recorded.GeneratedOn
	fresh.ExtraPositionals = project(fresh.ExtraPositionals, recorded.ExtraPositionals)
	fresh.RunFileUseArgv = project(fresh.RunFileUseArgv, recorded.RunFileUseArgv)
	return fresh, taken, nil
}

// runsOn reports whether a scenario tagged with platforms can be compared on goos.
func runsOn(platforms []string, goos string) bool {
	if len(platforms) == 0 {
		return true
	}
	for _, platform := range platforms {
		if platform == goos {
			return true
		}
	}
	return false
}
