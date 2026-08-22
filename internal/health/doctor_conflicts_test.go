package health

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeConflictTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func TestCheckVaultOrphanedConflictFilesNoneIsOK(t *testing.T) {
	vaultDir := t.TempDir()
	writeConflictTestFile(t, filepath.Join(vaultDir, "config.yaml"), "vault: 1")

	r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
	if r.Status != StatusOK {
		t.Fatalf("status = %q (%s), want %q", r.Status, r.Message, StatusOK)
	}
	if r.Fixable {
		t.Error("check must not be fixable when there is nothing to remove")
	}
}

// TestCheckVaultOrphanedConflictFilesSeparatesRedundantFromUnmerged covers the
// vault left behind by the device-identity change: a hostname-named and a
// device-id-named copy of the same file, both identical to config.yaml.
func TestCheckVaultOrphanedConflictFilesSeparatesRedundantFromUnmerged(t *testing.T) {
	vaultDir := t.TempDir()
	writeConflictTestFile(t, filepath.Join(vaultDir, "config.yaml"), "vault: 1")
	writeConflictTestFile(t, filepath.Join(vaultDir, "config.conflict-macbook-2.yaml"), "vault: 1")
	writeConflictTestFile(t, filepath.Join(vaultDir, "config.conflict-MacBook-2.local.yaml"), "vault: 1")
	writeConflictTestFile(t, filepath.Join(vaultDir, "entries", "a.age"), "local")
	writeConflictTestFile(t, filepath.Join(vaultDir, "entries", "a.conflict-macbook-2.age"), "remote")

	r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
	if r.Status != StatusWarn {
		t.Fatalf("status = %q, want %q", r.Status, StatusWarn)
	}
	if !strings.Contains(r.Message, "2 orphaned conflict file(s)") {
		t.Errorf("message = %q, want 2 orphaned copies", r.Message)
	}
	if !strings.Contains(r.Message, "1 conflict file(s) with unmerged content") {
		t.Errorf("message = %q, want 1 unmerged copy", r.Message)
	}
	if !r.Fixable || r.Fix == nil {
		t.Fatal("expected the check to be fixable when orphaned copies exist")
	}

	if err := r.Fix(); err != nil {
		t.Fatalf("Fix(): %v", err)
	}
	for _, gone := range []string{"config.conflict-macbook-2.yaml", "config.conflict-MacBook-2.local.yaml"} {
		if _, err := os.Stat(filepath.Join(vaultDir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s still exists, stat error = %v", gone, err)
		}
	}
	for _, kept := range []string{"config.yaml", filepath.Join("entries", "a.age"), filepath.Join("entries", "a.conflict-macbook-2.age")} {
		if _, err := os.Stat(filepath.Join(vaultDir, kept)); err != nil {
			t.Errorf("%s must be kept, stat error = %v", kept, err)
		}
	}
}

// TestCheckVaultOrphanedConflictFilesUnmergedOnlyIsNotFixable makes sure the
// fix never deletes a copy whose content still differs.
func TestCheckVaultOrphanedConflictFilesUnmergedOnlyIsNotFixable(t *testing.T) {
	vaultDir := t.TempDir()
	writeConflictTestFile(t, filepath.Join(vaultDir, "config.yaml"), "local")
	writeConflictTestFile(t, filepath.Join(vaultDir, "config.conflict-macbook-2.yaml"), "remote")

	r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
	if r.Status != StatusWarn {
		t.Fatalf("status = %q, want %q", r.Status, StatusWarn)
	}
	if r.Fixable || r.Fix != nil {
		t.Error("a conflict file with unmerged content must not be auto-removable")
	}
}

// TestCheckVaultOrphanedConflictFilesKeepsCopyWithoutSource guards against
// deleting the only remaining copy of a file.
func TestCheckVaultOrphanedConflictFilesKeepsCopyWithoutSource(t *testing.T) {
	vaultDir := t.TempDir()
	writeConflictTestFile(t, filepath.Join(vaultDir, "entries", "gone.conflict-macbook-2.age"), "only copy")

	r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
	if r.Status != StatusWarn {
		t.Fatalf("status = %q, want %q", r.Status, StatusWarn)
	}
	if r.Fixable {
		t.Error("a conflict file whose source is gone must not be auto-removable")
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "entries", "gone.conflict-macbook-2.age")); err != nil {
		t.Errorf("copy must be kept, stat error = %v", err)
	}
}

// TestCheckVaultOrphanedConflictFilesIgnoresGitDir keeps the sweep out of the
// repository's object store.
func TestCheckVaultOrphanedConflictFilesIgnoresGitDir(t *testing.T) {
	vaultDir := t.TempDir()
	writeConflictTestFile(t, filepath.Join(vaultDir, ".git", "x.conflict-macbook-2.age"), "x")

	r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
	if r.Status != StatusOK {
		t.Fatalf("status = %q (%s), want %q", r.Status, r.Message, StatusOK)
	}
}

func TestCheckVaultOrphanedConflictFilesDryRunKeepsFiles(t *testing.T) {
	vaultDir := t.TempDir()
	writeConflictTestFile(t, filepath.Join(vaultDir, "config.yaml"), "vault: 1")
	orphan := filepath.Join(vaultDir, "config.conflict-macbook-2.yaml")
	writeConflictTestFile(t, orphan, "vault: 1")

	r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
	if r.Fix == nil {
		t.Fatal("expected a fix closure")
	}
	FixDryRun = true
	defer func() { FixDryRun = false }()
	if err := r.Fix(); err != nil {
		t.Fatalf("Fix(): %v", err)
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Errorf("dry run must not remove %s: %v", filepath.Base(orphan), err)
	}
}

func TestCheckVaultOrphanedConflictFilesUnreadableDir(t *testing.T) {
	t.Run("NonexistentDir", func(t *testing.T) {
		nonexistent := filepath.Join(t.TempDir(), "does-not-exist")
		r := checkVaultOrphanedConflictFiles(nonexistent, Options{})
		if r.Status != StatusWarn {
			t.Fatalf("status = %q, want %q", r.Status, StatusWarn)
		}
		if !strings.Contains(r.Message, "cannot inspect conflict files:") {
			t.Errorf("message = %q, want 'cannot inspect conflict files:'", r.Message)
		}
		if r.Fixable {
			t.Error("unreadable directory check must not be fixable")
		}
	})

	t.Run("UnreadableSubdir", func(t *testing.T) {
		if runtime.GOOS == osWindows {
			t.Skip("POSIX permission bits do not restrict access on Windows")
		}
		vaultDir := t.TempDir()
		unreadable := filepath.Join(vaultDir, "locked")
		if err := os.Mkdir(unreadable, 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.Chmod(unreadable, 0000); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(unreadable, 0o700) })

		r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
		if r.Status != StatusWarn {
			t.Fatalf("status = %q, want %q", r.Status, StatusWarn)
		}
		if !strings.Contains(r.Message, "cannot inspect conflict files:") {
			t.Errorf("message = %q, want 'cannot inspect conflict files:'", r.Message)
		}
	})
}

func TestCheckVaultOrphanedConflictFilesUnreadableConflictFile(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("POSIX permission bits do not restrict access on Windows")
	}
	vaultDir := t.TempDir()
	writeConflictTestFile(t, filepath.Join(vaultDir, "secret.yaml"), "local")
	conflictPath := filepath.Join(vaultDir, "secret.conflict-macbook-2.yaml")
	writeConflictTestFile(t, conflictPath, "local")

	if err := os.Chmod(conflictPath, 0000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(conflictPath, 0o600) })

	r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
	if r.Status != StatusWarn {
		t.Fatalf("status = %q, want %q", r.Status, StatusWarn)
	}
	if !strings.Contains(r.Message, "1 conflict file(s) with unmerged content") {
		t.Errorf("message = %q, want 1 unmerged conflict file", r.Message)
	}
	if r.Fixable || r.Fix != nil {
		t.Error("unreadable conflict file must not be fixable or auto-removable")
	}
}

func TestCheckVaultOrphanedConflictFilesFixDataLossGuard(t *testing.T) {
	vaultDir := t.TempDir()
	// 1. Redundant orphan: identical to original file -> should be removed by --fix
	writeConflictTestFile(t, filepath.Join(vaultDir, "config.yaml"), "vault: 1")
	orphanRedundant := filepath.Join(vaultDir, "config.conflict-macbook-1.yaml")
	writeConflictTestFile(t, orphanRedundant, "vault: 1")

	// 2. Orphan without source: original file is gone -> must NOT be removed by --fix
	orphanNoSource := filepath.Join(vaultDir, "entries", "gone.conflict-macbook-2.age")
	writeConflictTestFile(t, orphanNoSource, "original deleted")

	// 3. Unmerged copy: original file exists but content differs -> must NOT be removed by --fix
	writeConflictTestFile(t, filepath.Join(vaultDir, "entries", "note.age"), "local content")
	orphanDiffering := filepath.Join(vaultDir, "entries", "note.conflict-macbook-3.age")
	writeConflictTestFile(t, orphanDiffering, "remote content")

	r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
	if r.Status != StatusWarn {
		t.Fatalf("status = %q, want %q", r.Status, StatusWarn)
	}
	if !strings.Contains(r.Message, "1 orphaned conflict file(s) identical to the file they shadow") {
		t.Errorf("message = %q, want 1 orphaned copy reported", r.Message)
	}
	if !strings.Contains(r.Message, "2 conflict file(s) with unmerged content") {
		t.Errorf("message = %q, want 2 unmerged copies reported", r.Message)
	}
	if !r.Fixable || r.Fix == nil {
		t.Fatal("expected check to be fixable for the 1 orphaned copy")
	}
	wantHint := "run `symvault doctor --fix` to remove the orphaned copies; compare the remaining ones by hand before deleting them"
	if r.Hint != wantHint {
		t.Errorf("hint = %q, want %q", r.Hint, wantHint)
	}

	if err := r.Fix(); err != nil {
		t.Fatalf("Fix(): %v", err)
	}

	// Assert the redundant orphan was removed
	if _, err := os.Stat(orphanRedundant); !os.IsNotExist(err) {
		t.Errorf("redundant conflict copy %s must be removed, stat error = %v", orphanRedundant, err)
	}

	// Assert data loss guard: neither the copy without source nor the copy with differing content was deleted
	if _, err := os.Stat(orphanNoSource); err != nil {
		t.Errorf("conflict copy without source %s must be kept, stat error = %v", orphanNoSource, err)
	}
	if _, err := os.Stat(orphanDiffering); err != nil {
		t.Errorf("conflict copy with differing content %s must be kept, stat error = %v", orphanDiffering, err)
	}

	// Assert original files remain intact
	if _, err := os.Stat(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Errorf("config.yaml must be kept, stat error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "entries", "note.age")); err != nil {
		t.Errorf("note.age must be kept, stat error = %v", err)
	}
}

func TestCheckVaultOrphanedConflictFilesFixErrors(t *testing.T) {
	t.Run("RescanFails", func(t *testing.T) {
		if runtime.GOOS == osWindows {
			t.Skip("POSIX permission bits do not restrict access on Windows")
		}
		vaultDir := t.TempDir()
		writeConflictTestFile(t, filepath.Join(vaultDir, "config.yaml"), "vault: 1")
		writeConflictTestFile(t, filepath.Join(vaultDir, "config.conflict-macbook-1.yaml"), "vault: 1")

		r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
		if !r.Fixable || r.Fix == nil {
			t.Fatal("expected check to be fixable")
		}

		// Make directory unreadable before Fix() rescans
		locked := filepath.Join(vaultDir, "locked")
		if err := os.Mkdir(locked, 0o700); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		if err := os.Chmod(locked, 0000); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

		if err := r.Fix(); err == nil {
			t.Fatal("expected Fix() to return error when rescan fails")
		}
	})

	t.Run("RemoveFailsPermissionDenied", func(t *testing.T) {
		if runtime.GOOS == osWindows {
			t.Skip("POSIX permission bits do not restrict access on Windows")
		}
		vaultDir := t.TempDir()
		subDir := filepath.Join(vaultDir, "sub")
		writeConflictTestFile(t, filepath.Join(subDir, "config.yaml"), "vault: 1")
		writeConflictTestFile(t, filepath.Join(subDir, "config.conflict-macbook-1.yaml"), "vault: 1")

		r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
		if !r.Fixable || r.Fix == nil {
			t.Fatal("expected check to be fixable")
		}

		// Make parent directory read-only (0500) so os.Remove fails
		if err := os.Chmod(subDir, 0o500); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(subDir, 0o700) })

		err := r.Fix()
		if err == nil {
			t.Fatal("expected Fix() to fail when removing from read-only dir")
		}
		if !strings.Contains(err.Error(), "remove ") {
			t.Errorf("error = %v, want substring 'remove '", err)
		}
	})

	t.Run("ConcurrentRemovalIgnored", func(t *testing.T) {
		vaultDir := t.TempDir()
		writeConflictTestFile(t, filepath.Join(vaultDir, "config.yaml"), "vault: 1")
		orphan := filepath.Join(vaultDir, "config.conflict-macbook-1.yaml")
		writeConflictTestFile(t, orphan, "vault: 1")

		r := checkVaultOrphanedConflictFiles(vaultDir, Options{})
		if !r.Fixable || r.Fix == nil {
			t.Fatal("expected check to be fixable")
		}

		// Remove orphan file between check and Fix() execution
		if err := os.Remove(orphan); err != nil {
			t.Fatalf("os.Remove: %v", err)
		}

		if err := r.Fix(); err != nil {
			t.Fatalf("Fix() failed on concurrently removed file: %v", err)
		}
	})
}
