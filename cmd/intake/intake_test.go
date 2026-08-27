package intakecmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/intake"
)

// resetIntakeFlags restores the package-level flag globals after a test so
// cobra flag parsing in one test cannot leak into the next.
func resetIntakeFlags(t *testing.T) {
	t.Helper()
	prev := []any{intakeDryRun, intakeJSON, intakeBatchLimit, intakeFileLimit, intakeMoveTrash, intakeOCRText}
	prevQuiet := cli.QuietMode
	t.Cleanup(func() {
		intakeDryRun = prev[0].(bool)
		intakeJSON = prev[1].(bool)
		intakeBatchLimit = prev[2].(int64)
		intakeFileLimit = prev[3].(int)
		intakeMoveTrash = prev[4].(bool)
		intakeOCRText = prev[5].(string)
		cli.QuietMode = prevQuiet
	})
	cli.QuietMode = true
}

// runIntakeCmd executes the intake command tree with the given args.
func runIntakeCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newIntakeCmd()
	root.SetArgs(args)
	out := &strings.Builder{}
	root.SetOut(out)
	root.SetErr(out)
	err := root.Execute()
	return out.String(), err
}

func writeEnvFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "creds.env")
	if err := os.WriteFile(src, []byte("USERNAME=alice\nPASSWORD=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return src
}

func TestNewCommandsShape(t *testing.T) {
	cmds := NewCommands()
	if len(cmds) != 1 {
		t.Fatalf("NewCommands() returned %d commands, want 1", len(cmds))
	}
	root := cmds[0]
	if root.Name() != "intake" {
		t.Fatalf("root command = %q, want %q", root.Name(), "intake")
	}
	if root.GroupID != cli.GroupIDSharingSync {
		t.Fatalf("GroupID = %q, want %q", root.GroupID, cli.GroupIDSharingSync)
	}
	var watchFound bool
	for _, c := range root.Commands() {
		if c.Name() == "watch" {
			watchFound = true
			var disableFound bool
			for _, sub := range c.Commands() {
				if sub.Name() == "disable" {
					disableFound = true
				}
			}
			if !disableFound {
				t.Error("watch command misses the disable subcommand")
			}
		}
	}
	if !watchFound {
		t.Error("intake command misses the watch subcommand")
	}
}

func TestRunIntakeDryRunText(t *testing.T) {
	resetIntakeFlags(t)
	src := writeEnvFile(t)
	if _, err := runIntakeCmd(t, src, "--dry-run"); err != nil {
		t.Fatalf("dry-run intake: %v", err)
	}
	if !intakeDryRun {
		t.Error("intakeDryRun flag was not parsed")
	}
}

func TestRunIntakeDryRunJSON(t *testing.T) {
	resetIntakeFlags(t)
	src := writeEnvFile(t)
	out, err := runIntakeCmd(t, src, "--dry-run", "--json")
	if err != nil {
		t.Fatalf("dry-run intake --json: %v", err)
	}
	var parsed struct {
		ImportID string `json:"import_id"`
		Results  []struct {
			File   string `json:"file"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(parsed.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(parsed.Results))
	}
	if parsed.Results[0].Status != "ok" {
		t.Fatalf("result status = %q, want ok", parsed.Results[0].Status)
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "alice") {
		t.Fatalf("JSON output leaks secret values:\n%s", out)
	}
}

func TestRunIntakeRequiresArgs(t *testing.T) {
	resetIntakeFlags(t)
	if _, err := runIntakeCmd(t); err == nil {
		t.Fatal("intake without files should fail (MinimumNArgs)")
	}
}

func TestEmitTextStatuses(t *testing.T) {
	resetIntakeFlags(t)
	long := strings.Repeat("a", 32)
	results := []intake.FileResult{
		{
			File:   "ok.env",
			Status: "ok",
			Provenance: &intake.Provenance{
				SourceType: "env",
				Size:       42,
				SHA256:     long,
			},
			Suggestions: []intake.SanitizedSuggestion{
				{Field: "password", Confidence: 0.9},
				{Field: "id_ed25519", Confidence: 0.7, Attachment: true, Warning: "private key material"},
			},
		},
		{File: "skip.png", Status: "skipped", Reason: "unsupported"},
		{File: "bad.json", Status: "error", Reason: "unreadable"},
	}

	intakeDryRun = true
	if err := emitText(results, ""); err != nil {
		t.Fatalf("emitText dry-run: %v", err)
	}

	intakeDryRun = false
	if err := emitText(results, "intake-20260827-deadbeef"); err != nil {
		t.Fatalf("emitText with ok result: %v", err)
	}

	intakeDryRun = false
	if err := emitText(results[1:], ""); err == nil {
		t.Fatal("emitText without accepted files should fail")
	}
}

func TestEmitJSONSanitizesValues(t *testing.T) {
	resetIntakeFlags(t)
	results := []intake.FileResult{
		{
			File:   "ok.env",
			Status: "ok",
			Provenance: &intake.Provenance{
				SourceType: "env",
				Size:       42,
				SHA256:     "abc123",
			},
		},
	}
	out := &strings.Builder{}
	if err := emitJSON(out, results, "intake-20260827-deadbeef"); err != nil {
		t.Fatalf("emitJSON: %v", err)
	}
	if !strings.Contains(out.String(), "intake-20260827-deadbeef") {
		t.Fatalf("emitJSON output misses import id:\n%s", out.String())
	}
	if !json.Valid([]byte(out.String())) {
		t.Fatalf("emitJSON produced invalid JSON:\n%s", out.String())
	}
}

func TestShortSHA(t *testing.T) {
	if got := shortSHA("abc123"); got != "abc123" {
		t.Fatalf("shortSHA short input = %q", got)
	}
	long := strings.Repeat("b", 64)
	if got := shortSHA(long); len(got) != 12 {
		t.Fatalf("shortSHA long input = %q (len %d), want 12 chars", got, len(got))
	}
}

func TestMoveToTrashAfterWriteSkipsNonOK(t *testing.T) {
	results := []intake.FileResult{
		{File: "skip.png", Status: "skipped", Reason: "unsupported"},
		{File: "ok-no-prov", Status: "ok"},
	}
	if err := moveToTrashAfterWrite(results); err != nil {
		t.Fatalf("moveToTrashAfterWrite with nothing to trash: %v", err)
	}
}
