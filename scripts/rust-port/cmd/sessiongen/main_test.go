package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

// The helper is a subprocess probe of the harness, not a replacement Go oracle.
func TestMain(m *testing.M) {
	if os.Getenv("SESSIONGEN_ISOLATION_PROBE") == "1" {
		home := os.Getenv("HOME")
		if os.Getenv("CI") != "1" || os.Getenv("SYMVAULT_PROFILE") != "" || home == "inherited-home" || home != os.Getenv("USERPROFILE") {
			fmt.Fprintln(os.Stderr, "isolation failed")
			os.Exit(91)
		}
		fmt.Fprint(os.Stdout, home)
		if strings.Contains(strings.Join(os.Args[1:], " "), "unlock") {
			fmt.Fprintln(os.Stderr, "No active session")
			os.Exit(7)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestHarnessIsolatesHomeAndPreservesFailureAndBytes(t *testing.T) {
	t.Setenv("SESSIONGEN_ISOLATION_PROBE", "1")
	t.Setenv("HOME", "inherited-home")
	t.Setenv("SYMVAULT_PROFILE", "inherited-profile")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	// Generate only into a disposable test directory; committed oracle
	// fixtures must never be replaced by this subprocess probe.
	fixturePath := filepath.Join(t.TempDir(), "session.json")
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
	for _, check := range []bool{false, true} {
		flag.CommandLine = flag.NewFlagSet("probe", flag.ExitOnError)
		os.Args = []string{"probe", "-go-binary", binary, "-output", fixturePath}
		if check {
			os.Args = append(os.Args, "-check")
		}
		main()
	}
	content, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var generated fixture
	if err := json.Unmarshal(content, &generated); err != nil {
		t.Fatal(err)
	}
	cases := generated.Cases
	if len(cases) != len(inputs()) {
		t.Fatalf("lost cases: %d", len(cases))
	}
	for _, tc := range cases {
		expectedExit := 0
		if strings.Contains(strings.Join(tc.Args, " "), "unlock") {
			expectedExit = 7
		}
		if tc.Expected.ExitCode != expectedExit {
			t.Fatalf("%s: exit %d", tc.Name, tc.Expected.ExitCode)
		}
		expectedHome := bytesToInts([]byte(filepath.Join(rootMarker, "home")))
		if fmt.Sprint(tc.Expected.StdoutBytes) != fmt.Sprint(expectedHome) {
			t.Fatalf("%s: output not normalized: %v", tc.Name, tc.Expected.StdoutBytes)
		}
		if expectedExit == 7 && tc.Expected.StderrContains != "no active session" {
			t.Fatalf("%s lost diagnostic", tc.Name)
		}
	}
	if _, err := buildCases(filepath.Join(t.TempDir(), "missing-oracle"), root); err == nil {
		t.Fatal("missing subprocess accepted")
	}
}

// Windows rejects the angle brackets the escaping case uses in a file name.
// The Rust differential strips exactly these two characters from synthetic
// paths, so the generator must not keep them without that transformation.
func TestWindowsSafePathComponentKeepsEscapingRelevantBytes(t *testing.T) {
	if got := windowsSafePathComponent("special-<&>-\u2028"); got != "special-&-\u2028" {
		t.Fatalf("windows-safe component = %q", got)
	}
	want := filepath.FromSlash("special-<&>-\u2028")
	if runtime.GOOS == "windows" {
		want = filepath.FromSlash("special-&-\u2028")
	}
	if got := vaultPathComponent("special-<&>-\u2028"); got != want {
		t.Fatalf("vault path component = %q, want %q", got, want)
	}
}

// The committed fixture records the digest of this generator, but no Makefile
// or workflow target regenerates or checks it, so a generator edit used to
// leave the recorded provenance stale and invisible. Compare it here instead of
// trusting the file: this needs no Go oracle binary and runs on every platform.
func TestCommittedFixtureRecordsTheCurrentGenerator(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	current, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/sessiongen/main.go"})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(root, "testdata", "port", "cli", "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	var committed fixture
	if err := json.Unmarshal(content, &committed); err != nil {
		t.Fatal(err)
	}
	if committed.Oracle.GeneratorDigest != current {
		t.Fatalf("committed generator digest %q does not match %q; regenerate the fixture deliberately",
			committed.Oracle.GeneratorDigest, current)
	}
}
