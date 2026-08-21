package health

import (
	"os"
	"path/filepath"
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
