package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTypedFlagInputsAreUniqueAndStateful(t *testing.T) {
	seen := map[string]bool{}
	states := map[string]int{}
	for _, in := range typedFlagInputs() {
		if seen[in.name] {
			t.Errorf("duplicate %s", in.name)
		}
		seen[in.name] = true
		states[in.state]++
		if !strings.HasPrefix(in.name, "typed_") || !strings.HasSuffix(in.name, "_"+in.state) {
			t.Errorf("%s does not name its state %s", in.name, in.state)
		}
		if in.description == "" || len(in.args) == 0 {
			t.Errorf("%s needs a description and arguments", in.name)
		}
	}
	if states[stateUninitialized] == 0 || states[stateInitialized] == 0 {
		t.Fatalf("states = %v", states)
	}
}

// Each residual class of CLI-003 must stay in the corpus: a generator edit that
// silently dropped one would leave the replay green.
func TestTypedFlagInputsCoverEveryResidualClass(t *testing.T) {
	want := map[string]func(args []string) bool{
		"file add --max-size hex":      func(a []string) bool { return has(a, "--max-size") && has(a, "0x10") },
		"file add --max-size negative": func(a []string) bool { return has(a, "--max-size") && has(a, "-1") },
		"file add --max-size min":      func(a []string) bool { return has(a, "-9223372036854775808") },
		"file add --max-size repeated": func(a []string) bool { return count(a, "--max-size") == 2 },
		"doctor --only empty value":    func(a []string) bool { return has(a, "doctor") && has(a, "--only") && has(a, "") },
		"doctor --only quoted comma":   func(a []string) bool { return has(a, "--only") && has(a, `"vault.config.*,vault.initialized"`) },
		"doctor --exclude":             func(a []string) bool { return has(a, "--exclude") && has(a, "vault.config.parses,vault.initialized") },
		"token --tools empty":          func(a []string) bool { return has(a, "token") && has(a, "--tools") && has(a, "") },
		"token --tools repeated":       func(a []string) bool { return has(a, "token") && count(a, "--tools") == 2 },
		"run --timeout negative":       func(a []string) bool { return has(a, "run") && has(a, "-5s") },
		"run --timeout expired":        func(a []string) bool { return has(a, "run") && has(a, "1ns") },
		"file use --timeout":           func(a []string) bool { return has(a, "use") && has(a, "-t") },
		"unlock --ttl":                 func(a []string) bool { return has(a, "unlock") && has(a, "--ttl") },
		"intake watch --interval":      func(a []string) bool { return has(a, "watch") && has(a, "--interval") },
		"intake watch --debounce":      func(a []string) bool { return has(a, "watch") && has(a, "--debounce") },
		"dynamic generate --ttl":       func(a []string) bool { return has(a, "dynamic") && has(a, "--ttl") },
	}
	covered := map[string]bool{}
	for _, in := range typedFlagInputs() {
		for name, match := range want {
			if match(in.args) {
				covered[name] = true
			}
		}
	}
	for name := range want {
		if !covered[name] {
			t.Errorf("no typed-flag scenario covers %s", name)
		}
	}
}

func has(args []string, word string) bool { return count(args, word) > 0 }

func count(args []string, word string) int {
	n := 0
	for _, arg := range args {
		if arg == word {
			n++
		}
	}
	return n
}

// Every scenario that reads a named source brings it.
func TestTypedFlagInputsBringTheirSources(t *testing.T) {
	for _, in := range typedFlagInputs() {
		if has(in.args, typedSourceName) {
			if got := len(in.files[typedSourceName]); got != typedSourceSize {
				t.Errorf("%s: %s is %d bytes, want %d", in.name, typedSourceName, got, typedSourceSize)
			}
		}
		if has(in.args, "inbox") {
			if _, ok := in.files["inbox/.keep"]; !ok {
				t.Errorf("%s watches an inbox that does not exist", in.name)
			}
		}
	}
}

func TestNormalizeTokenText(t *testing.T) {
	got, err := applyNormalizers([]string{normalizeTokenValues}, observation{
		Stdout: "Token created successfully.\n  ID:    tok-20261103-9dc781fc\n  Expires: 2026-11-04T06:48:37Z\n\nRaw token (copy now — shown once): 7cc5ce8b\n  Tools: tok-1-x, tok-20261103-ZZZZZZZZ\n",
		Stderr: "WARNING: (id=tok-20261103-ef3b1dc9) revoke legacy tok-20261103-ef3b1dc9\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantOut := "Token created successfully.\n  ID:    tok-__ID__\n  Expires: __TIME__\n\nRaw token (copy now — shown once): __TOKEN__\n  Tools: tok-1-x, tok-20261103-ZZZZZZZZ\n"
	if got.Stdout != wantOut {
		t.Errorf("stdout = %q, want %q", got.Stdout, wantOut)
	}
	if want := "WARNING: (id=tok-__ID__) revoke legacy tok-__ID__\n"; got.Stderr != want {
		t.Errorf("stderr = %q, want %q", got.Stderr, want)
	}
}

// A scenario's files are written below the working directory, parents included,
// and recorded with the case.
func TestRecordedScenarioCarriesItsFiles(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "oracle.sh")
	body := "#!/bin/sh\nif [ -f nested/dir/data.txt ]; then echo present; else echo missing; fi\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"nested/dir/data.txt": "x"}
	cases, err := recordScenarios(script, nil, []scenarioInput{{name: "files", description: "d", state: stateUninitialized, args: []string{"go"}, files: files}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].Observation.Stdout != "present\n" || cases[0].Files["nested/dir/data.txt"] != "x" {
		t.Fatalf("cases = %+v", cases)
	}
}
