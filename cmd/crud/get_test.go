package crud

import (
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

func TestGetCommand_ExactPath(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	cmd := newGetCmd()
	cmd.SetArgs([]string{"github"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestGetCommand_Field(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	cmd := newGetCmd()
	cmd.SetArgs([]string{"github.username"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestGetCommand_NotFound(t *testing.T) {
	setupTestVault(t)

	cmd := newGetCmd()
	cmd.SetArgs([]string{"missing"})
	cmd.SetOut(&strings.Builder{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() = nil, want not-found error")
	}
	if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "not exist") {
		t.Errorf("error = %q, want not-found message", err)
	}
}

func TestGetCommand_JSONOutput(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	setJSONOutput(t)
	cmd := newGetCmd()
	GetPrint = true
	t.Cleanup(func() { GetPrint = false })
	cmd.SetArgs([]string{"github"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	if !strings.Contains(out, `"Path"`) {
		t.Errorf("JSON output = %q, want path field", out)
	}
}

func TestGetCommand_JSONFlag(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	cmd := newGetCmd()
	GetPrint = true
	t.Cleanup(func() { GetPrint = false })
	cmd.SetArgs([]string{"github"})
	var out strings.Builder
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestNewGetCmd_Flags(t *testing.T) {
	cmd := newGetCmd()
	if cmd.Flags().Lookup("print") == nil {
		t.Error("--print flag missing")
	}
	if cmd.GroupID != cli.GroupIDEssentials {
		t.Errorf("GroupID = %q, want %q", cmd.GroupID, cli.GroupIDEssentials)
	}
}
