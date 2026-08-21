package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/git"
)

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it. cliout.Warnf writes directly to os.Stderr with
// no injectable writer, so this is the only way to observe it from a test.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	os.Stderr = orig
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(data)
}

// TestMaybeAutoPullWarnsWhenSetLastSyncTimeFails covers the warning branch
// that fires when the sync-time marker file cannot be written: MaybeAutoPull
// must still complete (rather than crash) and must surface the failure as a
// warning rather than swallow it silently.
func TestMaybeAutoPullWarnsWhenSetLastSyncTimeFails(t *testing.T) {
	localDir := t.TempDir()
	if err := git.Init(localDir); err != nil {
		t.Fatalf("git.Init: %v", err)
	}
	repo, err := gogit.PlainOpen(localDir)
	if err != nil {
		t.Fatalf("PlainOpen: %v", err)
	}
	// hasRemote only needs a configured remote, not a reachable one — the
	// pull attempt itself is allowed to fail; SetLastSyncTime still runs
	// unconditionally afterward (see git.MaybeAutoPull).
	if _, err := repo.CreateRemote(&gogitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{filepath.Join(t.TempDir(), "unreachable.git")},
	}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}

	// Force SetLastSyncTime's own write to fail in a way that is reliable
	// across platforms: pre-create a directory at the exact marker path, so
	// os.WriteFile fails with "is a directory" everywhere. A chmod'd
	// read-only ".git" directory is not portable — Windows does not enforce
	// POSIX directory write permissions the same way, so that approach
	// silently no-ops there instead of failing the write.
	markerPath := filepath.Join(localDir, ".git", "symvault-last-sync")
	if err := os.MkdirAll(markerPath, 0o755); err != nil {
		t.Fatalf("pre-create colliding directory: %v", err)
	}

	cfg := &configpkg.Config{Git: &configpkg.GitConfig{
		AutoPull:         true,
		AutoPullInterval: time.Hour,
	}}

	out := captureStderr(t, func() { MaybeAutoPull(localDir, cfg) })
	if !strings.Contains(out, "could not record sync time") {
		t.Errorf("stderr = %q, want it to contain a warning about the failed sync-time write", out)
	}
}
