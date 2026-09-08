package main

import (
	"path/filepath"
	"testing"
)

func TestConfinedFixturePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "contract fixture", path: filepath.Join("testdata", "port", "store", "reopen.json"), want: true},
		{name: "absolute path", path: filepath.Join(string(filepath.Separator), "tmp", "fixture.json")},
		{name: "parent escape", path: filepath.Join("testdata", "port", "store", "..", "..", "outside.json")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := confinedFixturePath(test.path)
			if (err == nil) != test.want {
				t.Fatalf("confinedFixturePath(%q) error=%v, want allowed=%t", test.path, err, test.want)
			}
		})
	}
}
