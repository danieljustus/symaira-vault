package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// This subprocess probes isolation and byte capture; it is not a Go oracle.
func TestMain(m *testing.M) {
	if os.Getenv("CONFIGGEN_CAPTURE_PROBE") == "1" {
		home := os.Getenv("HOME")
		if home == "inherited-home" || home != os.Getenv("USERPROFILE") {
			os.Exit(91)
		}
		args := os.Args[1:]
		if slices.Contains(args, "set") {
			path := filepath.Join(home, ".symvault", "config.yaml")
			for i, arg := range args {
				if arg == "--file" && i+1 < len(args) {
					path = args[i+1]
				}
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				os.Exit(92)
			}
			if err := os.WriteFile(path, []byte("captured: changed\n"), 0600); err != nil {
				os.Exit(93)
			}
		}
		_, _ = os.Stdout.Write([]byte{'o', 'k', 0xff})
		fmt.Fprintln(os.Stderr, "cannot load config")
		os.Exit(7)
	}
	os.Exit(m.Run())
}

func TestHarnessCapturesRawBytesAndChangedConfig(t *testing.T) {
	t.Setenv("CONFIGGEN_CAPTURE_PROBE", "1")
	t.Setenv("HOME", "inherited-home")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := buildCases(binary, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(inputs()) {
		t.Fatalf("lost cases: %d", len(cases))
	}
	for _, tc := range cases {
		if tc.Expected.ExitCode != 7 || !slices.Equal(tc.Expected.StdoutBytes, []int{111, 107, 255}) || tc.Expected.StderrContains != "cannot load config" {
			t.Fatalf("%s lost raw output or subprocess error: %+v", tc.Name, tc.Expected)
		}
		if tc.CaptureConfigAfter && !slices.Equal(tc.ConfigAfterBytes, byteValues([]byte("captured: changed\n"))) {
			t.Fatalf("%s did not capture written config", tc.Name)
		}
	}
	if _, err := buildCases(filepath.Join(t.TempDir(), "missing-oracle"), root); err == nil {
		t.Fatal("missing subprocess accepted")
	}
	if err := validateGoBinary(binary); err == nil {
		t.Fatal("test helper accepted as production oracle")
	}
	if err := validateGoBinary(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing oracle accepted")
	}
}

func TestOraclePinningAndFixtureEncoding(t *testing.T) {
	if got := errorNeedle([]byte(`Using file-based grant signing key storage`), 0); got != "" {
		t.Fatalf("successful platform warning became oracle error: %q", got)
	}
	if got := errorNeedle([]byte(`cannot load config`), 7); got != "cannot load config" {
		t.Fatalf("failed command lost oracle error: %q", got)
	}
	for _, tc := range []struct {
		check           bool
		commit, release string
		valid           bool
	}{
		{true, "", "", true}, {false, "", "", false},
		{false, pinnedOracleCommit, pinnedOracleRelease, true},
		{true, "untrusted", "", false}, {true, "", "untrusted", false},
	} {
		commit, release, err := resolveOracle(tc.check, tc.commit, tc.release)
		if (err == nil) != tc.valid {
			t.Fatalf("pin acceptance mismatch: %+v", tc)
		}
		if tc.valid && (commit != pinnedOracleCommit || release != pinnedOracleRelease) {
			t.Fatal("unpinned metadata")
		}
	}
	value, err := marshalJSON(map[string]string{"key": "<&>"})
	if err != nil || !bytes.Contains(value, []byte("<&>")) || !bytes.HasSuffix(value, []byte("\n")) {
		t.Fatalf("fixture encoding: %q %v", value, err)
	}
	if _, err := marshalJSON(make(chan int)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if got := strings.Join(setEnv([]string{"A=one", "A=two", "B=keep"}, "A", "new"), ";"); got != "B=keep;A=new" {
		t.Fatal(got)
	}
}
