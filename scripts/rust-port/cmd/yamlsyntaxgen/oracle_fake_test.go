package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeOracle writes a POSIX shell stand-in for the Go binary. It echoes its
// arguments (which carry sandbox paths) to stderr, rewrites the file passed to
// `config set`, and answers `doctor` with one JSON result per doctor ID, so the
// recording, normalization and capture paths run without building the pinned
// oracle. It does not replace the real oracle check (`--check`).
func fakeOracle(t *testing.T, doctorJSON bool) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell oracle stand-in needs a POSIX shell")
	}
	results := make([]string, 0, len(doctorIDs))
	for _, id := range doctorIDs {
		results = append(results, `{"id":"`+id+`","name":"n","status":"fail","message":"load $1 $2 $3","hint":"under $HOME","fixable":false}`)
	}
	doctor := `printf '%s\n' 'not json'`
	if doctorJSON {
		// Double-quoted so the shell expands $1/$2/$HOME into sandbox paths.
		payload := strings.ReplaceAll(`{"results":[`+strings.Join(results, ",")+`]}`, `"`, `\"`)
		doctor = `printf '%s\n' "` + payload + `"`
	}
	script := `#!/bin/sh
for a in "$@"; do
  if [ "$a" = doctor ]; then ` + doctor + `; exit 1; fi
done
prev=""; file=""
for a in "$@"; do
  if [ "$prev" = "--file" ]; then file="$a"; fi
  prev="$a"
done
if [ "$2" = set ] && [ -n "$file" ]; then printf 'x' >> "$file"; fi
printf 'out %s\n' "$PWD"
printf 'Error: %s\n' "$*" >&2
exit 1
`
	path := filepath.Join(t.TempDir(), "symvault-go")
	// #nosec G306 -- test-only executable in a private temp dir.
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRecordingAgainstFakeOracleNormalizesAndCaptures(t *testing.T) {
	oracle := fakeOracle(t, true)
	cases, err := buildCases(oracle)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(inputs()) {
		t.Fatalf("recorded %d cases, want %d", len(cases), len(inputs()))
	}
	agentLists, sets := 0, 0
	for _, built := range cases {
		if len(built.Doctor.Results) != len(doctorIDs) || built.Doctor.ExitCode != 1 {
			t.Fatalf("case %s doctor %+v", built.Name, built.Doctor)
		}
		for _, result := range built.Doctor.Results {
			if strings.Contains(result.Hint, os.TempDir()) || !strings.Contains(result.Hint, rootMarker) {
				t.Fatalf("case %s doctor hint not normalized: %q", built.Name, result.Hint)
			}
		}
		for _, observed := range built.Observations {
			if observed.ExitCode != 1 || !strings.Contains(observed.Stderr, configMarker) || !strings.Contains(observed.Stdout, rootMarker) {
				t.Fatalf("case %s %s not normalized: %+v", built.Name, observed.Command, observed)
			}
			if observed.Command == "set" {
				sets++
				if observed.Unchanged == nil || *observed.Unchanged {
					t.Fatalf("case %s set did not capture the rewrite", built.Name)
				}
			}
		}
		if built.AgentList != nil {
			agentLists++
			if !strings.Contains(built.AgentList.Stderr, vaultMarker) {
				t.Fatalf("case %s agent list not normalized: %q", built.Name, built.AgentList.Stderr)
			}
		}
	}
	if agentLists != len(agentListCases) || sets == 0 {
		t.Fatalf("agent list %d (want %d), set %d", agentLists, len(agentListCases), sets)
	}

	divergences, err := buildDivergences(oracle)
	if err != nil {
		t.Fatal(err)
	}
	if len(divergences) != len(openInputs()) {
		t.Fatalf("recorded %d open divergences, want %d", len(divergences), len(openInputs()))
	}
}

func TestRecordingFailsClosed(t *testing.T) {
	if _, err := buildCases(fakeOracle(t, false)); err == nil || !strings.Contains(err.Error(), "doctor JSON") {
		t.Fatalf("malformed doctor output accepted: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := buildCases(missing); err == nil {
		t.Fatal("missing oracle binary accepted")
	}
	if _, err := buildDivergences(missing); err == nil {
		t.Fatal("missing oracle binary accepted for open divergences")
	}
	if _, ok := lookupSpec("set_nested"); !ok {
		t.Fatal("open-only spec not found")
	}
	if _, ok := lookupSpec("unknown"); ok {
		t.Fatal("unknown spec found")
	}
	if got := replaceArgs([]string{"a", configMarker + "/x"}, configMarker, "/p"); got[0] != "a" || got[1] != "/p/x" {
		t.Fatalf("replaceArgs %q", got)
	}
	if root, err := repositoryRoot(); err != nil || filepath.Base(filepath.Dir(root)) == "" {
		t.Fatalf("repository root %q %v", root, err)
	}
}
