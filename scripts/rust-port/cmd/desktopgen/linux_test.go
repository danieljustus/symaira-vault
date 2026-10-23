//go:build linux

package main

import (
	"os"
	"testing"
)

// TestBuildFixtureOnLinux runs every scenario against the production Go code.
// It is the in-package proof that the generator executes (not skips) its cases.
func TestBuildFixtureOnLinux(t *testing.T) {
	f, err := buildFixture()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Clipboard) != len(clipboardScenarios()) || len(f.Autotype) != len(autotypeScenarios()) {
		t.Fatalf("executed %d/%d clipboard and %d/%d autotype cases", len(f.Clipboard), len(clipboardScenarios()), len(f.Autotype), len(autotypeScenarios()))
	}
	for _, c := range f.Autotype {
		if c.Name == "x11_focus_changed_aborts_before_typing" && c.Error == "" {
			t.Fatal("focus change did not abort typing")
		}
	}
}

// TestRelativePathHitsAreNeverExecuted pins Go's exec.ErrDot behavior: a tool
// found through a relative or empty PATH entry is "not installed", so the
// planted executable receives nothing.
func TestRelativePathHitsAreNeverExecuted(t *testing.T) {
	f, err := buildFixture()
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]bool{
		"x11_relative_path_xdotool_is_refused":         true,
		"x11_dot_path_xdotool_is_refused":              true,
		"x11_empty_entry_xdotool_in_cwd_is_refused":    true,
		"x11_empty_path_searches_nothing":              true,
		"x11_relative_hit_shadows_absolute_xdotool":    true,
		"x11_relative_xdotool_strict_refuses_on_focus": true,
		"wayland_relative_wtype_is_refused":            true,
	}
	seen := 0
	for _, c := range f.Autotype {
		if !refused[c.Name] {
			continue
		}
		seen++
		if len(c.Calls) != 0 || c.Error == "" {
			t.Errorf("%s: relative hit was executed or no error: calls=%v error=%q", c.Name, c.Calls, c.Error)
		}
		if c.Name == "x11_relative_path_xdotool_is_refused" && c.Error != "autotype failed: xdotool not installed" {
			t.Errorf("unexpected error text %q", c.Error)
		}
	}
	if seen != len(refused) {
		t.Fatalf("saw %d of %d relative-path autotype scenarios", seen, len(refused))
	}
	for _, c := range f.Clipboard {
		switch c.Name {
		case "relative_path_xclip_is_not_used", "dot_path_xclip_is_not_used", "empty_entry_xclip_in_cwd_is_not_used", "empty_path_searches_nothing", "relative_hit_shadows_absolute_same_tool":
			if len(c.Calls) != 0 || c.CopyError == "" {
				t.Errorf("%s: relative hit was executed: %+v", c.Name, c)
			}
		}
	}
}

// TestMain gives the test binary the same child-process contract as main():
// buildFixture re-executes os.Executable() with childFlag, and under `go test`
// that executable is this test binary.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == childFlag {
		os.Exit(runChild(os.Args[2:]))
	}
	os.Exit(m.Run())
}
