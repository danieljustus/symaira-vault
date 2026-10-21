package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCorpusIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	classes := map[string]int{}
	all := inputs()
	for _, item := range all {
		if item.name == "" || item.description == "" {
			t.Fatalf("incomplete case %+v", item)
		}
		if seen[item.name] {
			t.Fatalf("duplicate case name %q", item.name)
		}
		seen[item.name] = true
		switch item.class {
		case "scanner", "parser", "reader", "loader", "accepted":
			classes[item.class]++
		default:
			t.Fatalf("%s: unknown class %q", item.name, item.class)
		}
	}
	for _, class := range []string{"scanner", "parser", "reader", "loader", "accepted"} {
		if classes[class] == 0 {
			t.Fatalf("corpus has no %s case", class)
		}
	}
	for _, entry := range openInputs() {
		if seen[entry.name] {
			t.Fatalf("open divergence %q also appears in the corpus", entry.name)
		}
		if entry.reason == "" {
			t.Fatalf("open divergence %q has no reason", entry.name)
		}
	}
}

func TestOraclePinningAndEncoding(t *testing.T) {
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
	if err != nil || !strings.Contains(string(value), "<&>") || !strings.HasSuffix(string(value), "\n") {
		t.Fatalf("fixture encoding: %q %v", value, err)
	}
	if err := validateGoBinary(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing oracle accepted")
	}
}

func TestSandboxNormalizesRootsAndRejectsNonUTF8(t *testing.T) {
	box, err := newSandbox()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = box.close() })
	for _, env := range box.env {
		if strings.HasPrefix(env, "SYMVAULT_") {
			t.Fatalf("sandbox leaks %s", env)
		}
	}
	text := "open " + filepath.Join(box.root, "config.yaml") + " in " + filepath.Join(box.root, "vault") + " under " + box.root
	got, err := box.normalize([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if want := "open " + configMarker + " in " + vaultMarker + " under " + rootMarker; got != want {
		t.Fatalf("normalized %q, want %q", got, want)
	}
	if _, err := box.normalize([]byte{0xff}); err == nil {
		t.Fatal("non-UTF-8 oracle output accepted")
	}
}
