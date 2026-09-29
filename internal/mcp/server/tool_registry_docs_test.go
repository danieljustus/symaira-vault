package server

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestToolRegistryDocumentation(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate documentation relative to test source")
	}
	root := filepath.Join(filepath.Dir(source), "..", "..", "..")
	definitions := toolDefinitions()
	for _, file := range []string{"docs/mcp-api.md", "ARCHITECTURE.md"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, file))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.ReplaceAll(string(data), "\r\n", "\n")
			start, end, pattern := "### Available Tools\n", "\n---", "(?m)^\\| `([^`]+)` \\|"
			if file == "ARCHITECTURE.md" {
				start, end, pattern = "**Available tools (", "\n### `internal/audit/`", "(?m)^- `([^`]+)`"
				capClaim := fmt.Sprintf("`MaxToolDefinitions` (%d, defined in", MaxToolDefinitions)
				if !strings.Contains(text, capClaim) {
					t.Errorf("architecture cap must match %d", MaxToolDefinitions)
				}
			}
			_, section, found := strings.Cut(text, start)
			if !found {
				t.Fatalf("missing tool inventory heading %q", start)
			}
			section, _, found = strings.Cut(section, end)
			if !found {
				t.Fatalf("missing inventory boundary %q", end)
			}
			names := make(map[string]bool)
			for _, match := range regexp.MustCompile(pattern).FindAllStringSubmatch(section, -1) {
				if names[match[1]] {
					t.Errorf("duplicate documented tool %q", match[1])
				}
				names[match[1]] = true
			}
			for _, def := range definitions {
				if !names[def.Name] {
					t.Errorf("missing registered tool %q", def.Name)
				}
				delete(names, def.Name)
			}
			for name := range names {
				t.Errorf("documented tool %q is not registered", name)
			}
		})
	}
}
