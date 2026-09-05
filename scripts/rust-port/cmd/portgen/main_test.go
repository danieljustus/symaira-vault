package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	vaultcmd "github.com/danieljustus/symaira-vault/cmd"
)

func TestBuildDocumentIsDeterministic(t *testing.T) {
	meta := oracle{Commit: "test-commit", Release: "v0.0.0"}
	first, err := marshalDocument(buildDocument(vaultcmd.NewRootCmd(), meta))
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalDocument(buildDocument(vaultcmd.NewRootCmd(), meta))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("command tree generation is not deterministic")
	}
}

func TestBuildDocumentCapturesCriticalContracts(t *testing.T) {
	doc := buildDocument(vaultcmd.NewRootCmd(), oracle{Commit: "test", Release: "test"})
	if len(doc.Commands) < 50 {
		t.Fatalf("unexpectedly small command tree: %d", len(doc.Commands))
	}
	byPath := make(map[string]commandSpec, len(doc.Commands))
	for _, command := range doc.Commands {
		byPath[command.Path] = command
	}
	serve, ok := byPath["symvault serve"]
	if !ok || !serve.Hidden {
		t.Fatalf("hidden serve alias not captured: %#v", serve)
	}
	root := byPath["symvault"]
	if !hasFlag(root.PersistentFlags, "vault") || !hasFlag(root.PersistentFlags, "output") {
		t.Fatalf("root persistent flags incomplete: %#v", root.PersistentFlags)
	}
	profileAdd, ok := byPath["symvault profile add"]
	if !ok || !flagHasAnnotation(profileAdd.LocalFlags, "vault") {
		t.Fatalf("required flag annotation not captured: %#v", profileAdd)
	}
}

func TestReadDocumentRejectsUnknownSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDocument(path); err == nil {
		t.Fatal("expected schema rejection")
	}
}

func hasFlag(flags []flagSpec, name string) bool {
	for _, item := range flags {
		if item.Name == name {
			return true
		}
	}
	return false
}

func flagHasAnnotation(flags []flagSpec, name string) bool {
	for _, item := range flags {
		if item.Name == name && len(item.Annotations) > 0 {
			return true
		}
	}
	return false
}
