package crud

import (
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

func TestDeleteCommand_ConfirmYes(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	cmd := newDeleteCmd()
	cmd.SetArgs([]string{"github"})
	withStdin(t, "y\n", func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})

	if entryExists(t) {
		t.Error("entry still exists after confirmed delete")
	}
}

func TestDeleteCommand_Cancel(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "s3cret"})

	cmd := newDeleteCmd()
	cmd.SetArgs([]string{"github"})
	stderr := captureStderr(t, func() {
		withStdin(t, "n\n", func() {
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
		})
	})
	if !strings.Contains(stderr, "Canceled") {
		t.Errorf("stderr = %q, want cancellation notice", stderr)
	}

	if !entryExists(t) {
		t.Error("entry was deleted despite cancel")
	}
}

func TestDeleteCommand_YesFlag(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "s3cret"})

	cmd := newDeleteCmd()
	DeleteYes = true
	t.Cleanup(func() { DeleteYes = false })
	cmd.SetArgs([]string{"github"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if entryExists(t) {
		t.Error("entry still exists after --yes delete")
	}
}

func TestDeleteCommand_JSONOutput(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "s3cret"})

	setJSONOutput(t)
	cmd := newDeleteCmd()
	DeleteYes = true
	t.Cleanup(func() { DeleteYes = false })
	cmd.SetArgs([]string{"github"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestDeleteCommand_JSONCancel(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "s3cret"})

	setJSONOutput(t)
	cmd := newDeleteCmd()
	cmd.SetArgs([]string{"github"})
	withStdin(t, "n\n", func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})

	if !entryExists(t) {
		t.Error("entry was deleted despite JSON-format cancel")
	}
}

func TestDeleteCommand_NotFound(t *testing.T) {
	setupTestVault(t)

	cmd := newDeleteCmd()
	DeleteYes = true
	t.Cleanup(func() { DeleteYes = false })
	cmd.SetArgs([]string{"missing"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() = nil, want not-found error")
	}
	if !strings.Contains(err.Error(), "cannot delete") {
		t.Errorf("error = %q, want write-failure message", err)
	}
}

func TestNewCommands_Assembly(t *testing.T) {
	cmds := NewCommands()
	got := make(map[string]bool, len(cmds))
	for _, c := range cmds {
		got[c.Name()] = true
	}
	for _, want := range []string{"add", "delete", "edit", "find", "get", "list", "set"} {
		if !got[want] {
			t.Errorf("NewCommands() missing %q", want)
		}
	}
	for _, c := range cmds {
		if c.GroupID != cli.GroupIDEssentials {
			t.Errorf("command %q GroupID = %q, want %q", c.Name(), c.GroupID, cli.GroupIDEssentials)
		}
	}
}
