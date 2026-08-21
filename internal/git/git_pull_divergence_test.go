package git

import (
	"os"
	"path/filepath"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"
)

// remoteVaultPair creates a bare "remote" repository and a "local" vault
// clone of it, both starting from one commit that has entries/a.age = "v1"
// and config.yaml = "cfg1".
func remoteVaultPair(t *testing.T) (localDir, remoteBareDir string) {
	t.Helper()
	remoteBareDir = t.TempDir()
	if _, err := gogit.PlainInit(remoteBareDir, true); err != nil {
		t.Fatalf("PlainInit bare remote: %v", err)
	}

	seedDir := t.TempDir()
	if err := Init(seedDir); err != nil {
		t.Fatalf("Init seed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(seedDir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	writeFile(t, seedDir, "entries/a.age", []byte("v1"))
	writeFile(t, seedDir, "config.yaml", []byte("cfg1"))
	if err := AutoCommit(seedDir, "initial"); err != nil {
		t.Fatalf("AutoCommit seed: %v", err)
	}
	seedRepo, err := openRepo(seedDir)
	if err != nil {
		t.Fatalf("openRepo seed: %v", err)
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
	return localDir, remoteBareDir
}

// pushFromFreshClone clones remoteBareDir into a scratch directory, applies
// mutate, commits and pushes — simulating another device syncing a change.
func pushFromFreshClone(t *testing.T, remoteBareDir, message string, mutate func(dir string)) {
	t.Helper()
	dir := t.TempDir()
	if _, err := gogit.PlainClone(dir, false, &gogit.CloneOptions{URL: remoteBareDir}); err != nil {
		t.Fatalf("PlainClone other device: %v", err)
	}
	mutate(dir)
	if err := AutoCommit(dir, message); err != nil {
		t.Fatalf("AutoCommit other device: %v", err)
	}
	repo, err := openRepo(dir)
	if err != nil {
		t.Fatalf("openRepo other device: %v", err)
	}
	if err := repo.Push(&gogit.PushOptions{RemoteName: "origin"}); err != nil {
		t.Fatalf("push other device: %v", err)
	}
}

func conflictCopyPath(vaultDir, path string) string {
	ext := filepath.Ext(path)
	base := path[:len(path)-len(ext)]
	return filepath.Join(vaultDir, base+ConflictMarker+DeviceIdentity(vaultDir)+ext)
}

// TestPullWithResultDirtyUnrelatedFileWritesNoConflictCopy is the regression
// test for acceptance criterion 1 of #831: a failed pull whose only local
// change is an unrelated dirty file (the remote never touched it) must not
// produce a conflict copy for that file, even though the pull itself failed.
func TestPullWithResultDirtyUnrelatedFileWritesNoConflictCopy(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)

	// config.yaml is dirty locally but the remote never touches it — only a
	// different tracked file changes on the remote side, which is what
	// makes the incoming pull fail with "worktree contains unstaged changes"
	// (go-git's Pull moves HEAD before it discovers the worktree is dirty).
	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))
	pushFromFreshClone(t, remoteBareDir, "add b", func(dir string) {
		writeFile(t, dir, "entries/b.age", []byte("new-entry"))
	})

	result := PullWithResult(localDir)
	if result.Error == nil {
		t.Fatalf("expected the pull to fail (dirty worktree blocks the incoming merge), got success")
	}

	copyPath := conflictCopyPath(localDir, "config.yaml")
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Errorf("conflict copy written for config.yaml although the remote never touched it (stat error = %v)", err)
	}
	if len(result.Conflicts) != 0 {
		t.Errorf("result.Conflicts = %v, want empty", result.Conflicts)
	}
}

// TestPullWithResultGenuineConflictPreservesLocalVersion is the regression
// test for acceptance criterion 2 of #831: when the same entry is changed
// both locally (auto-committed, as symvault does for every entry write) and
// on the remote, the failed pull must still preserve exactly one conflict
// copy holding the local version.
func TestPullWithResultGenuineConflictPreservesLocalVersion(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)

	writeFile(t, localDir, "entries/a.age", []byte("local-version"))
	if err := AutoCommit(localDir, "local edit"); err != nil {
		t.Fatalf("AutoCommit local: %v", err)
	}
	pushFromFreshClone(t, remoteBareDir, "remote edit", func(dir string) {
		writeFile(t, dir, "entries/a.age", []byte("remote-version"))
	})

	result := PullWithResult(localDir)
	if result.Error == nil {
		t.Fatalf("expected the pull to fail (diverged history), got success")
	}

	copyPath := conflictCopyPath(localDir, "entries/a.age")
	data, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("expected a conflict copy at %s: %v", copyPath, err)
	}
	if string(data) != "local-version" {
		t.Errorf("conflict copy content = %q, want %q", data, "local-version")
	}
	if len(result.Conflicts) != 1 {
		t.Errorf("result.Conflicts = %v, want exactly one entry", result.Conflicts)
	}
}

// TestPullWithResultNoopSuccessIsNotMarkedUpdated guards the Updated flag a
// caller relies on to decide whether a conflict sweep is even meaningful: a
// pull that fetched nothing new (already up to date) must not report Updated,
// otherwise a permanently dirty config.yaml (never staged by AutoCommit)
// would still be swept and copied on every trivial no-op sync.
func TestPullWithResultNoopSuccessIsNotMarkedUpdated(t *testing.T) {
	localDir, _ := remoteVaultPair(t)
	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))

	result := PullWithResult(localDir)
	if result.Error != nil {
		t.Fatalf("PullWithResult: unexpected error %v", result.Error)
	}
	if !result.Success {
		t.Fatalf("expected Success=true for an already-up-to-date pull")
	}
	if result.Updated {
		t.Errorf("Updated=true for a no-op pull that fetched nothing new")
	}
}

// TestPullWithResultRealUpdateIsMarkedUpdated is the positive counterpart:
// a pull that actually fast-forwards must report Updated=true.
func TestPullWithResultRealUpdateIsMarkedUpdated(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)
	pushFromFreshClone(t, remoteBareDir, "add b", func(dir string) {
		writeFile(t, dir, "entries/b.age", []byte("new-entry"))
	})

	result := PullWithResult(localDir)
	if result.Error != nil {
		t.Fatalf("PullWithResult: unexpected error %v", result.Error)
	}
	if !result.Updated {
		t.Errorf("Updated=false for a pull that fast-forwarded new commits")
	}
}

// TestForcePullBacksUpDirtyWorktreeBeforeDiscarding covers the case an
// ordinary pull cannot handle: a dirty worktree that would otherwise block
// the incoming merge (see TestPullWithResultDirtyUnrelatedFileWritesNoConflictCopy).
// ForcePull must succeed anyway, discard the local edit from config.yaml —
// but not before preserving it as a conflict copy, since a hard reset must
// never silently destroy vault data a user might not have realized was
// still unpushed.
func TestForcePullBacksUpDirtyWorktreeBeforeDiscarding(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)

	writeFile(t, localDir, "config.yaml", []byte("cfg1-local-edit"))
	pushFromFreshClone(t, remoteBareDir, "add b", func(dir string) {
		writeFile(t, dir, "entries/b.age", []byte("new-entry"))
	})

	result := ForcePull(localDir)
	if result.Error != nil {
		t.Fatalf("ForcePull: unexpected error %v", result.Error)
	}
	if !result.Success {
		t.Errorf("Success=false, want true")
	}
	if !result.Updated {
		t.Errorf("Updated=false, want true (remote had a new commit)")
	}

	data, err := os.ReadFile(filepath.Join(localDir, "config.yaml"))
	if err != nil {
		t.Fatalf("read config.yaml: %v", err)
	}
	if string(data) != "cfg1" {
		t.Errorf("config.yaml = %q, want %q (local edit should have been discarded)", data, "cfg1")
	}
	if _, err := os.Stat(filepath.Join(localDir, "entries", "b.age")); err != nil {
		t.Errorf("expected entries/b.age to be pulled from remote: %v", err)
	}

	backup, err := os.ReadFile(conflictCopyPath(localDir, "config.yaml"))
	if err != nil {
		t.Fatalf("expected a backup copy of the discarded local edit: %v", err)
	}
	if string(backup) != "cfg1-local-edit" {
		t.Errorf("backup copy content = %q, want %q", backup, "cfg1-local-edit")
	}
}

// TestForcePullBacksUpDivergedLocalCommitBeforeDiscarding covers the
// diverged-history case: a local commit that conflicts with a remote commit
// on the same file. A plain pull fails here (see
// TestPullWithResultGenuineConflictPreservesLocalVersion); ForcePull must
// discard the local commit and match the remote, but the local version must
// survive as a conflict copy first — this is exactly the class of data loss
// the backup step exists to prevent.
func TestForcePullBacksUpDivergedLocalCommitBeforeDiscarding(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)

	writeFile(t, localDir, "entries/a.age", []byte("local-version"))
	if err := AutoCommit(localDir, "local edit"); err != nil {
		t.Fatalf("AutoCommit local: %v", err)
	}
	pushFromFreshClone(t, remoteBareDir, "remote edit", func(dir string) {
		writeFile(t, dir, "entries/a.age", []byte("remote-version"))
	})

	result := ForcePull(localDir)
	if result.Error != nil {
		t.Fatalf("ForcePull: unexpected error %v", result.Error)
	}
	if !result.Success {
		t.Errorf("Success=false, want true")
	}

	data, err := os.ReadFile(filepath.Join(localDir, "entries", "a.age"))
	if err != nil {
		t.Fatalf("read entries/a.age: %v", err)
	}
	if string(data) != "remote-version" {
		t.Errorf("entries/a.age = %q, want %q (local commit should have been discarded)", data, "remote-version")
	}

	backup, err := os.ReadFile(conflictCopyPath(localDir, "entries/a.age"))
	if err != nil {
		t.Fatalf("expected a backup copy of the discarded local commit: %v", err)
	}
	if string(backup) != "local-version" {
		t.Errorf("backup copy content = %q, want %q", backup, "local-version")
	}
}

// TestForcePullSkipsBackupWhenLocalMatchesRemote guards the backup step from
// over-reach: a clean worktree with no local-only commits has nothing to
// protect, so ForcePull must not litter the vault with no-op backup copies.
func TestForcePullSkipsBackupWhenLocalMatchesRemote(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)
	pushFromFreshClone(t, remoteBareDir, "add b", func(dir string) {
		writeFile(t, dir, "entries/b.age", []byte("new-entry"))
	})

	result := ForcePull(localDir)
	if result.Error != nil {
		t.Fatalf("ForcePull: unexpected error %v", result.Error)
	}

	for _, path := range []string{"entries/a.age", "config.yaml", "entries/b.age"} {
		if _, err := os.Stat(conflictCopyPath(localDir, path)); !os.IsNotExist(err) {
			t.Errorf("unexpected backup copy for %s (stat error = %v)", path, err)
		}
	}
}

// TestForcePullNoopIsNotMarkedUpdated mirrors
// TestPullWithResultNoopSuccessIsNotMarkedUpdated for the force path.
func TestForcePullNoopIsNotMarkedUpdated(t *testing.T) {
	localDir, _ := remoteVaultPair(t)

	result := ForcePull(localDir)
	if result.Error != nil {
		t.Fatalf("ForcePull: unexpected error %v", result.Error)
	}
	if !result.Success {
		t.Fatalf("expected Success=true for an already-up-to-date force pull")
	}
	if result.Updated {
		t.Errorf("Updated=true for a force pull that fetched nothing new")
	}
}

// TestSyncForceUsesForcePull is the integration point cmd/sync.go relies on:
// Sync(vaultDir, pushAfter, force=true) must route through ForcePull rather
// than the merging PullWithResult, so --force actually resets local changes
// instead of silently behaving like a plain sync (issue found in review of
// PR #834).
func TestSyncForceUsesForcePull(t *testing.T) {
	localDir, remoteBareDir := remoteVaultPair(t)

	writeFile(t, localDir, "entries/a.age", []byte("local-version"))
	if err := AutoCommit(localDir, "local edit"); err != nil {
		t.Fatalf("AutoCommit local: %v", err)
	}
	pushFromFreshClone(t, remoteBareDir, "remote edit", func(dir string) {
		writeFile(t, dir, "entries/a.age", []byte("remote-version"))
	})

	result := Sync(localDir, false, true)
	if result.Error != nil {
		t.Fatalf("Sync: unexpected error %v", result.Error)
	}

	data, err := os.ReadFile(filepath.Join(localDir, "entries", "a.age"))
	if err != nil {
		t.Fatalf("read entries/a.age: %v", err)
	}
	if string(data) != "remote-version" {
		t.Errorf("entries/a.age = %q, want %q (Sync with force=true should discard local commit)", data, "remote-version")
	}
}
