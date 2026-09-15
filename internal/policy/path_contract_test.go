package policy

import (
	"path/filepath"
	"runtime"
	"testing"
)

// The policy matcher is defined over slash-separated logical paths and is
// OS-independent. Every case below must produce the same answer on every host;
// the native separator is interpreted once, by ToLogicalPath, at the runtime
// boundary.

func TestMatchPathGlobContract(t *testing.T) {
	tests := []struct {
		name, pattern, value string
		want                 bool
	}{
		{"unicode star", "fixture/café/*", "fixture/café/秘密", true},
		{"unicode question", "fixture/?", "fixture/é", true},
		{"unicode class", "fixture/[α-γ]", "fixture/β", true},
		{"star does not cross separator", "fixture/*", "fixture/nested/file", false},
		{"dot dot is cleaned", "fixture/café/*", "fixture/other/../café/file", true},
		{"backslash escapes a metacharacter", `fixture\*`, "fixture*", true},
		{"backslash is never a separator", "fixture/*", `fixture\child`, false},
		{"literal directory prefix", "fixture/dir", "fixture/dir/secret", true},
		{"recursive suffix", "fixture/dir/**", "fixture/dir/a/b", true},
		{"trailing slash prefix", "fixture/dir/", "fixture/dir/a", true},
		{"prefix sibling is not matched", "fixture/dir", "fixture/dirx/secret", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchPath(tt.pattern, tt.value, ""); got != tt.want {
				t.Fatalf("matchPath(%q, %q) = %v, want %v on %s", tt.pattern, tt.value, got, tt.want, runtime.GOOS)
			}
		})
	}
}

// A pattern carrying a glob metacharacter is matched as a glob and nothing
// else. Under the previous semantics the bare directory-prefix branch was
// gated only on "*", so "fixture/?" was simultaneously a glob and a literal.
func TestMetacharacterPatternsAreNeverAlsoLiteralPrefixes(t *testing.T) {
	for _, pattern := range []string{"fixture/?", "fixture/[ab]"} {
		if matchPath(pattern, pattern+"/secret", "") {
			t.Fatalf("metacharacter pattern %q matched its own literal directory prefix", pattern)
		}
	}
	// The glob meaning itself is unaffected.
	if !matchPath("fixture/?", "fixture/a", "") {
		t.Fatal("glob meaning of fixture/? was lost")
	}
}

// Home expansion is driven by the caller-supplied HomeDir, never by runtime
// discovery, so evaluation is deterministic.
func TestHomeExpansionUsesSuppliedHomeOnly(t *testing.T) {
	if !matchPath("~/secure/*", "/home/probe/secure/secret", "/home/probe") {
		t.Fatal("~/ pattern did not expand against the supplied home")
	}
	if matchPath("~/secure/*", "/home/other/secure/secret", "/home/probe") {
		t.Fatal("~/ pattern matched a path outside the supplied home")
	}
	// With no home supplied the pattern stays literal rather than silently
	// resolving against the process environment.
	if matchPath("~/secure/*", "/home/probe/secure/secret", "") {
		t.Fatal("~/ pattern expanded without a supplied home")
	}
	if !matchPath("~/secure/*", "~/secure/secret", "") {
		t.Fatal("unexpanded ~/ pattern lost its literal meaning")
	}
}

func TestToLogicalPathInterpretsTheNativeSeparator(t *testing.T) {
	native := filepath.Join("fixture", "child")
	if got := ToLogicalPath(native); got != "fixture/child" {
		t.Fatalf("ToLogicalPath(%q) = %q, want fixture/child on %s", native, got, runtime.GOOS)
	}
	if got := ToLogicalPath(""); got != "" {
		t.Fatalf("ToLogicalPath(\"\") = %q, want empty", got)
	}
	// A slash-written rule therefore matches a native path once the boundary
	// conversion has run. Before this contract the pattern silently stopped
	// matching on Windows, which failed open for deny rules.
	if !matchPath("fixture/*", ToLogicalPath(native), "") {
		t.Fatalf("slash pattern did not match converted native path on %s", runtime.GOOS)
	}
}
