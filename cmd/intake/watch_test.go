package intakecmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

// resetWatchFlags restores the watch flag globals after a test.
func resetWatchFlags(t *testing.T) {
	t.Helper()
	prevInterval, prevDebounce, prevOnce, prevJSON := watchInterval, watchDebounce, watchOnce, watchJSON
	prevQuiet := cli.QuietMode
	t.Cleanup(func() {
		watchInterval, watchDebounce, watchOnce, watchJSON = prevInterval, prevDebounce, prevOnce, prevJSON
		cli.QuietMode = prevQuiet
	})
	cli.QuietMode = true
}

// runWatchCmd executes `intake watch ...` through the real command tree.
func runWatchCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newIntakeCmd()
	root.SetArgs(append([]string{"watch"}, args...))
	out := &strings.Builder{}
	root.SetOut(out)
	root.SetErr(out)
	err := root.Execute()
	return out.String(), err
}

func TestWatchOnceEmptyDir(t *testing.T) {
	resetWatchFlags(t)
	dir := t.TempDir()
	if _, err := runWatchCmd(t, dir, "--once"); err != nil {
		t.Fatalf("watch --once on empty dir: %v", err)
	}
	if !watchOnce {
		t.Error("--once flag was not parsed")
	}
}

func TestWatchOnceJSONEmptyDir(t *testing.T) {
	resetWatchFlags(t)
	dir := t.TempDir()
	out, err := runWatchCmd(t, dir, "--once", "--json")
	if err != nil {
		t.Fatalf("watch --once --json on empty dir: %v", err)
	}
	var res struct {
		Scanned int `json:"scanned"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("watch --json output is not valid JSON: %v\n%s", err, out)
	}
	if res.Scanned != 0 {
		t.Fatalf("scanned = %d, want 0 for an empty dir", res.Scanned)
	}
}

func TestWatchInvalidDir(t *testing.T) {
	resetWatchFlags(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := runWatchCmd(t, missing, "--once"); err == nil {
		t.Fatal("watch on a nonexistent directory should fail")
	}
}

func TestWatchRequiresDirArg(t *testing.T) {
	resetWatchFlags(t)
	if _, err := runWatchCmd(t); err == nil {
		t.Fatal("watch without a directory should fail (ExactArgs)")
	}
}

func TestWatchIntervalFlagParsed(t *testing.T) {
	resetWatchFlags(t)
	dir := t.TempDir()
	if _, err := runWatchCmd(t, dir, "--once", "--interval", "15s", "--debounce", "1s"); err != nil {
		t.Fatalf("watch --once with custom intervals: %v", err)
	}
	if watchInterval != 15*time.Second {
		t.Fatalf("watchInterval = %s, want 15s", watchInterval)
	}
	if watchDebounce != time.Second {
		t.Fatalf("watchDebounce = %s, want 1s", watchDebounce)
	}
}

func TestWatchDisableNoPlist(t *testing.T) {
	resetWatchFlags(t)
	// Point HOME at an empty temp dir so no LaunchAgent plist exists.
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, err := runWatchCmd(t, "disable"); err != nil {
		t.Fatalf("watch disable without plist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "Library", "LaunchAgents", "com.symaira.vault-intake.plist")); !os.IsNotExist(err) {
		t.Fatal("disable must not create a plist")
	}
}
