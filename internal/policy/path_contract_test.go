package policy

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestMatchPathMatchesNativeFilepathGlob(t *testing.T) {
	tests := []struct {
		name, pattern, value string
		want                 bool
	}{
		{"unicode star", filepath.Join("fixture", "café", "*"), filepath.Join("fixture", "café", "秘密"), true},
		{"unicode question", filepath.Join("fixture", "?"), filepath.Join("fixture", "é"), true},
		{"unicode class", filepath.Join("fixture", "[α-γ]"), filepath.Join("fixture", "β"), true},
		{"star does not cross separator", filepath.Join("fixture", "*"), filepath.Join("fixture", "nested", "file"), false},
		{"dot dot is cleaned", filepath.Join("fixture", "café", "*"), "fixture" + string(filepath.Separator) + "other" + string(filepath.Separator) + ".." + string(filepath.Separator) + "café" + string(filepath.Separator) + "file", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchPath(tt.pattern, tt.value); got != tt.want {
				t.Fatalf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchPathPreservesTargetSeparatorSemantics(t *testing.T) {
	nativePattern := filepath.Join("fixture", "*")
	nativeValue := filepath.Join("fixture", "child")
	if !matchPath(nativePattern, nativeValue) {
		t.Fatalf("native pattern %q did not match native path %q on %s", nativePattern, nativeValue, runtime.GOOS)
	}

	// A slash pattern and a backslash-containing value must not be made
	// equivalent by a platform-independent normalization pass.
	if matchPath("fixture/*", `fixture\child`) {
		t.Fatalf("slash pattern unexpectedly matched backslash path on %s", runtime.GOOS)
	}

	if runtime.GOOS == "windows" {
		if matchPath("fixture/*", nativeValue) {
			t.Fatal("Windows slash pattern unexpectedly matched a native backslash path")
		}
	} else if matchPath(`fixture\*`, "fixture*") == false {
		t.Fatal("Unix filepath.Match escaping was not preserved")
	}
}
