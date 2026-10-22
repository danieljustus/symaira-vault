//go:build linux

package main

import "testing"

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
