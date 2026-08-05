package crud

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/secureedit"
)

// skipOnWindows aborts the test on Windows where the fake-editor shell
// scripts cannot be executed (no POSIX shell), mirroring cmd/file/use_test.go.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: fake editor relies on a POSIX shell")
	}
}

// fakeEditor returns an OSCreateTemp and EDITOR that make secureedit write the
// given updated JSON body to a temp file and exit successfully, mimicking a
// user editing an entry and saving.
func fakeEditor(t *testing.T, updatedJSON string) {
	t.Helper()
	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.json")
	if err := os.WriteFile(bodyPath, []byte(updatedJSON), 0o600); err != nil {
		t.Fatalf("write fake body: %v", err)
	}

	script := "#!/bin/sh\ncp " + bodyPath + " \"$1\"\n"
	scriptPath := filepath.Join(dir, "editor.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write editor script: %v", err)
	}

	origCreateTemp := OSCreateTemp
	origEditor := EditorFlag
	t.Cleanup(func() {
		OSCreateTemp = origCreateTemp
		EditorFlag = origEditor
	})
	OSCreateTemp = secureedit.CreateTemp
	EditorFlag = scriptPath
}

func TestEditCommand_UpdatesEntry(t *testing.T) {
	skipOnWindows(t)
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "oldpass"})

	updated := `{"data":{"username":"octocat","password":"newpass"},"meta":{"created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z","version":2}}`

	cmd := newEditCmd()
	fakeEditor(t, updated) // must run after newEditCmd(): flag registration resets EditorFlag
	cmd.SetArgs([]string{"github"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	entry := getTestEntry(t, "github")
	if got, _ := entry.GetField("password"); got != "newpass" {
		t.Errorf("password after edit = %q, want %q", got, "newpass")
	}
}

func TestEditCommand_NotFound(t *testing.T) {
	setupTestVault(t)

	cmd := newEditCmd()
	cmd.SetArgs([]string{"missing"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() = nil, want not-found error")
	}
	if !strings.Contains(err.Error(), "entry not found") {
		t.Errorf("error = %q, want not-found message", err)
	}
}

func TestEditCommand_EditorFailure(t *testing.T) {
	skipOnWindows(t)
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"password": "s3cret"})

	dir := t.TempDir()
	script := "#!/bin/sh\nexit 3\n"
	scriptPath := filepath.Join(dir, "editor.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write editor script: %v", err)
	}

	cmd := newEditCmd()
	origEditor := EditorFlag
	t.Cleanup(func() { EditorFlag = origEditor })
	EditorFlag = scriptPath // must run after newEditCmd(): flag registration resets EditorFlag

	cmd.SetArgs([]string{"github"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() = nil, want editor error")
	}

	// The entry must be unchanged.
	entry := getTestEntry(t, "github")
	if got, _ := entry.GetField("password"); got != "s3cret" {
		t.Errorf("password after failed edit = %q, want %q", got, "s3cret")
	}
}

func TestNewEditCmd_Flags(t *testing.T) {
	cmd := newEditCmd()
	flag := cmd.Flags().Lookup("editor")
	if flag == nil {
		t.Fatal("--editor flag missing")
	}
	if cmd.GroupID != cli.GroupIDEssentials {
		t.Errorf("GroupID = %q, want %q", cmd.GroupID, cli.GroupIDEssentials)
	}
}
