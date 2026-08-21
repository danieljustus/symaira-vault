package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/git"
)

func TestIsOfflineErr_NoRouteToHost(t *testing.T) {
	err := &testError{msg: "dial tcp: no route to host"}
	if !git.IsOfflineError(err) {
		t.Error("IsOfflineError() = false for 'no route to host', want true")
	}
}

func TestIsOfflineErr_ConnectionRefused(t *testing.T) {
	err := &testError{msg: "dial tcp: connection refused"}
	if !git.IsOfflineError(err) {
		t.Error("IsOfflineError() = false for 'connection refused', want true")
	}
}

func TestIsOfflineErr_ConnectionTimedOut(t *testing.T) {
	err := &testError{msg: "dial tcp: connection timed out"}
	if !git.IsOfflineError(err) {
		t.Error("IsOfflineError() = false for 'connection timed out', want true")
	}
}

func TestIsOfflineErr_IOTimeout(t *testing.T) {
	err := &testError{msg: "i/o timeout"}
	if !git.IsOfflineError(err) {
		t.Error("IsOfflineError() = false for 'i/o timeout', want true")
	}
}

func TestIsOfflineErr_SSHOperationTimedOut(t *testing.T) {
	err := &testError{msg: "ssh: connect to host github.com port 22: Operation timed out"}
	if !git.IsOfflineError(err) {
		t.Error("IsOfflineError() = false for 'Operation timed out', want true")
	}
}

func TestIsOfflineErr_NonOfflineError(t *testing.T) {
	err := &testError{msg: "permission denied"}
	if git.IsOfflineError(err) {
		t.Error("IsOfflineError() = true for 'permission denied', want false")
	}
}

func TestIsOfflineErr_EmptyMessage(t *testing.T) {
	err := &testError{msg: ""}
	if git.IsOfflineError(err) {
		t.Error("IsOfflineError() = true for empty message, want false")
	}
}

func TestContainsConflict_ConflictPrefix(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{".conflict-something.txt", true},
		{"config.conflict-something.txt", false},
		{"normal-file.txt", false},
		{"config.yaml", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsConflict(tt.name)
			if got != tt.want {
				t.Errorf("containsConflict(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestFindConflictFiles_NoConflicts(t *testing.T) {
	dir := t.TempDir()
	entriesDir := filepath.Join(dir, "entries")
	createTestDir(t, entriesDir)
	createTestFiles(t, dir, "config.yaml", "identity.age")
	createTestFiles(t, entriesDir, "github.age")

	files := findConflictFiles(dir)
	if len(files) != 0 {
		t.Errorf("findConflictFiles() = %v, want empty", files)
	}
}

func TestFindConflictFiles_WithConflicts(t *testing.T) {
	dir := t.TempDir()
	createTestFiles(t, dir, ".conflict-abc123.txt", "normal.txt")

	files := findConflictFiles(dir)
	if len(files) != 1 {
		t.Fatalf("findConflictFiles() returned %d files, want 1", len(files))
	}

	if files[0] != ".conflict-abc123.txt" {
		t.Errorf("conflict file = %q, want .conflict-abc123.txt", files[0])
	}
}

func TestFindConflictFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	files := findConflictFiles(dir)
	if len(files) != 0 {
		t.Errorf("findConflictFiles() = %v, want empty", files)
	}
}

func TestFindConflictFiles_NestedConflicts(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "subdir")
	createTestDir(t, subdir)
	createTestFiles(t, subdir, ".conflict-nested.txt")

	files := findConflictFiles(dir)
	if len(files) != 1 {
		t.Fatalf("findConflictFiles() returned %d files, want 1", len(files))
	}
	want := filepath.ToSlash("subdir/.conflict-nested.txt")
	got := filepath.ToSlash(files[0])
	if got != want {
		t.Errorf("conflict file = %q, want %q", got, want)
	}
}

// TestMaybeAutoPullRecordsAttemptOnFailure is the regression test for
// acceptance criterion 4 of #831: a failed pull must still record enough
// state that the next invocation does not repeat the identical pull attempt.
// Before the fix, MaybeAutoPull returned on any pull error before ever
// calling SetLastSyncTime, so ShouldAutoPull kept firing on every command.
func TestMaybeAutoPullRecordsAttemptOnFailure(t *testing.T) {
	localDir, remoteBareDir := autoPullVaultPair(t)
	_ = remoteBareDir

	cfg := &configpkg.Config{Git: &configpkg.GitConfig{
		AutoPull:         true,
		AutoPullInterval: time.Hour,
	}}

	if git.ShouldAutoPull(localDir, time.Hour) != true {
		t.Fatalf("expected ShouldAutoPull to be true before any attempt")
	}

	MaybeAutoPull(localDir, cfg)

	lastSync, err := git.LastSyncTime(localDir)
	if err != nil {
		t.Fatalf("LastSyncTime: %v", err)
	}
	if lastSync.IsZero() {
		t.Fatal("SetLastSyncTime was not recorded although the pull attempt completed (with a failure)")
	}
	if git.ShouldAutoPull(localDir, time.Hour) {
		t.Error("ShouldAutoPull is still true immediately after a failed attempt — the retry loop is not fixed")
	}
}

// autoPullVaultPair builds a local vault clone whose next pull is guaranteed
// to fail with a non-fast-forward error: the local and remote histories have
// independently committed different content for the same tracked file.
func autoPullVaultPair(t *testing.T) (localDir, remoteBareDir string) {
	t.Helper()
	remoteBareDir = t.TempDir()
	if _, err := gogit.PlainInit(remoteBareDir, true); err != nil {
		t.Fatalf("PlainInit bare remote: %v", err)
	}

	seedDir := t.TempDir()
	if err := git.Init(seedDir); err != nil {
		t.Fatalf("Init seed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(seedDir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	if err := os.WriteFile(filepath.Join(seedDir, "entries", "a.age"), []byte("v1"), 0o600); err != nil {
		t.Fatalf("write seed entry: %v", err)
	}
	if err := git.AutoCommit(seedDir, "initial"); err != nil {
		t.Fatalf("AutoCommit seed: %v", err)
	}
	seedRepo, err := gogit.PlainOpen(seedDir)
	if err != nil {
		t.Fatalf("PlainOpen seed: %v", err)
	}
	if _, err := seedRepo.CreateRemote(&gogitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteBareDir},
	}); err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}
	if err := seedRepo.Push(&gogit.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("push seed: %v", err)
	}

	localDir = t.TempDir()
	if _, err := gogit.PlainClone(localDir, false, &gogit.CloneOptions{URL: remoteBareDir}); err != nil {
		t.Fatalf("PlainClone local: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "entries", "a.age"), []byte("local-version"), 0o600); err != nil {
		t.Fatalf("write local entry: %v", err)
	}
	if err := git.AutoCommit(localDir, "local edit"); err != nil {
		t.Fatalf("AutoCommit local: %v", err)
	}

	otherDir := t.TempDir()
	if _, err := gogit.PlainClone(otherDir, false, &gogit.CloneOptions{URL: remoteBareDir}); err != nil {
		t.Fatalf("PlainClone other device: %v", err)
	}
	if err := os.WriteFile(filepath.Join(otherDir, "entries", "a.age"), []byte("remote-version"), 0o600); err != nil {
		t.Fatalf("write remote entry: %v", err)
	}
	if err := git.AutoCommit(otherDir, "remote edit"); err != nil {
		t.Fatalf("AutoCommit other device: %v", err)
	}
	otherRepo, err := gogit.PlainOpen(otherDir)
	if err != nil {
		t.Fatalf("PlainOpen other device: %v", err)
	}
	if err := otherRepo.Push(&gogit.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("push other device: %v", err)
	}

	return localDir, remoteBareDir
}

// testError is a simple error implementation for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func createTestFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("test content"), 0600); err != nil {
			t.Fatalf("createTestFiles: write %s: %v", name, err)
		}
	}
}

func createTestDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("createTestDir: %v", err)
	}
}
