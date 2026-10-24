package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsageCorpusIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, item := range usageInputs() {
		if item.name == "" || item.description == "" || len(item.args) == 0 {
			t.Fatalf("incomplete usage case %+v", item)
		}
		if seen[item.name] {
			t.Fatalf("duplicate usage case %q", item.name)
		}
		seen[item.name] = true
	}
	if len(seen) < 30 {
		t.Fatalf("only %d usage cases", len(seen))
	}
}

func TestArityRejectionClassifier(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  observation
		want bool
	}{
		{"exact", observation{ExitCode: 1, Stderr: "Error: accepts 1 arg(s), received 0\nError: accepts 1 arg(s), received 0\n"}, true},
		{"at least", observation{ExitCode: 1, Stderr: "Error: requires at least 2 arg(s), only received 0\n"}, true},
		{"at most", observation{ExitCode: 1, Stderr: "Error: accepts at most 1 arg(s), received 2\n"}, true},
		{"between", observation{ExitCode: 1, Stderr: "Error: accepts between 1 and 2 arg(s), received 0 \u2014 either\n"}, true},
		{"custom body error", observation{ExitCode: 1, Stderr: "Error: requires exactly 1 argument (agent name)\n"}, false},
		{"wrong exit", observation{ExitCode: 9, Stderr: "Error: accepts 1 arg(s), received 0\n"}, false},
		{"stdout present", observation{ExitCode: 1, Stdout: "x", Stderr: "Error: accepts 1 arg(s), received 0\n"}, false},
	} {
		if got := isArityRejection(tc.obs); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGateAndNotInitializedClassifiers(t *testing.T) {
	gate := result{obs: observation{ExitCode: 9, Stderr: "Error: output format \"json\" is not supported by 'symvault x' (supported commands: y)\n"}}
	if !isGateRefusal(gate) {
		t.Fatal("gate refusal not recognized")
	}
	gate.obs.ExitCode = 1
	if isGateRefusal(gate) {
		t.Fatal("exit 1 is not a gate refusal")
	}
	line := "Error: vault not initialized. Run 'symvault init' first\n"
	hint := "Run 'symvault init' for a quick start, or 'symvault setup' for the guided wizard.\n"
	if !isNotInitialized(observation{ExitCode: 3, Stderr: line + line + hint}) {
		t.Fatal("not-initialized triple not recognized")
	}
	if isNotInitialized(observation{ExitCode: 3, Stderr: line + line}) {
		t.Fatal("missing hint accepted")
	}
}

func TestPathArgsAndDummyArgs(t *testing.T) {
	if got := strings.Join(pathArgs("symvault agent token new"), " "); got != "agent token new" {
		t.Fatalf("pathArgs = %q", got)
	}
	if len(pathArgs("symvault")) != 0 {
		t.Fatal("root path has no arguments")
	}
	if got := strings.Join(concat([]string{"a"}, dummyArgs(2), []string{"--json"}), " "); got != "a x x --json" {
		t.Fatalf("concat = %q", got)
	}
}

func TestResolveOracleRejectsUnpinnedCommit(t *testing.T) {
	if _, _, err := resolveOracle(false, "deadbeef", pinnedOracleRelease); err == nil {
		t.Fatal("an unpinned commit was accepted")
	}
	if _, _, err := resolveOracle(false, "", ""); err == nil {
		t.Fatal("a new fixture without commit and release was accepted")
	}
	if commit, release, err := resolveOracle(true, "", ""); err != nil || commit != pinnedOracleCommit || release != pinnedOracleRelease {
		t.Fatalf("check mode = %q %q %v", commit, release, err)
	}
}

func TestShapeCorpusIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, item := range shapeInputs() {
		if item.name == "" || item.description == "" || len(item.args) == 0 {
			t.Fatalf("incomplete shape %+v", item)
		}
		if seen[item.name] {
			t.Fatalf("duplicate shape %q", item.name)
		}
		seen[item.name] = true
		for name := range item.files {
			if strings.ContainsAny(name, `/\`) {
				t.Fatalf("shape %q: file %q escapes the sandbox working directory", item.name, name)
			}
		}
	}
	// The three argument forms of --pairing-file and the unset shapes must stay.
	for _, want := range []string{
		"join_pairing_file_equals_token", "join_pairing_file_separate_token", "join_pairing_file_path_only",
		"join_pairing_file_equals_double_dash_token", "join_no_flag_one_positional", "join_no_flag_three_positionals",
		"group_help_agent_skill",
	} {
		if !seen[want] {
			t.Fatalf("shape %q was dropped", want)
		}
	}
}

func TestRunWritesFilesIntoTheSandboxWorkingDirectory(t *testing.T) {
	script := filepath.Join(t.TempDir(), "oracle.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat \"$1\"\n"), 0o700); err != nil { // #nosec G306 -- test script
		t.Fatal(err)
	}
	res, err := run(script, []string{"note.txt"}, map[string]string{"note.txt": "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if res.obs.Stdout != "hello" || res.obs.ExitCode != 0 {
		t.Fatalf("observation = %+v", res.obs)
	}
}
