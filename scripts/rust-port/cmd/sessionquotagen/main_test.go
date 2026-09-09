package main

import (
	"path/filepath"
	"testing"
)

func TestFixturePathIsBounded(t *testing.T) {
	root := repositoryRoot()
	if got, err := fixturePath(root, "testdata/port/session/contract.json"); err != nil || got != filepath.Join("session", "contract.json") {
		t.Fatalf("fixture path = %q, %v", got, err)
	}
	for _, path := range []string{"../outside.json", "testdata/port/../outside.json", "/tmp/outside.json"} {
		if _, err := fixturePath(root, path); err == nil {
			t.Fatalf("fixture path %q unexpectedly accepted", path)
		}
	}
}
