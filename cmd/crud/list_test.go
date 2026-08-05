package crud

import (
	"strings"
	"testing"
)

func TestListCommand_Empty(t *testing.T) {
	setupTestVault(t)

	cmd := newListCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestListCommand_ListsEntries(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "a"})
	addTestEntry(t, "work/aws", map[string]any{"password": "b"})

	cmd := newListCmd()
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	if !strings.Contains(out, "github") || !strings.Contains(out, "work/aws") {
		t.Errorf("list output = %q, want both entries", out)
	}
}

func TestListCommand_Prefix(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "a"})
	addTestEntry(t, "work/aws", map[string]any{"password": "b"})

	cmd := newListCmd()
	cmd.SetArgs([]string{"work/"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	if strings.Contains(out, "github") {
		t.Errorf("prefix list output = %q, want only work/ entries", out)
	}
	if !strings.Contains(out, "aws") {
		t.Errorf("prefix list output = %q, want work/aws", out)
	}
}

func TestListCommand_JSONOutput(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "a"})

	setJSONOutput(t)
	cmd := newListCmd()
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	if !strings.Contains(out, "github") {
		t.Errorf("JSON list output = %q, want entry path", out)
	}
}
