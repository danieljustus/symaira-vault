package health

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckVaultStaleTempFilesReportsOnlyOldDirectChildren(t *testing.T) {
	vaultDir := t.TempDir()
	stalePath := filepath.Join(vaultDir, "manifest.age.tmp-old")
	freshPath := filepath.Join(vaultDir, "manifest.age.tmp-fresh")
	nestedDir := filepath.Join(vaultDir, "nested")
	outsidePath := filepath.Join(nestedDir, "other.age.tmp-old")

	for _, path := range []string{stalePath, freshPath} {
		if err := os.WriteFile(path, []byte("temporary"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}
	if err := os.Mkdir(nestedDir, 0o700); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	if err := os.WriteFile(outsidePath, []byte("temporary"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", outsidePath, err)
	}

	now := time.Now()
	old := now.Add(-(staleTempFileAge + time.Minute))
	if err := os.Chtimes(stalePath, old, old); err != nil {
		t.Fatalf("Chtimes(stale): %v", err)
	}
	if err := os.Chtimes(outsidePath, old, old); err != nil {
		t.Fatalf("Chtimes(outside): %v", err)
	}

	r := checkVaultStaleTempFiles(vaultDir, Options{})
	if r.Status != StatusWarn {
		t.Fatalf("status = %q, want %q", r.Status, StatusWarn)
	}
	if !strings.Contains(r.Message, filepath.Base(stalePath)) {
		t.Errorf("message = %q, want stale filename", r.Message)
	}
	if strings.Contains(r.Message, filepath.Base(freshPath)) {
		t.Errorf("message = %q, must not report fresh filename", r.Message)
	}
	if strings.Contains(r.Message, filepath.Base(outsidePath)) {
		t.Errorf("message = %q, must not inspect nested filename", r.Message)
	}
}

func TestCheckVaultStaleTempFilesFixRemovesOldLeavesFreshAndNested(t *testing.T) {
	vaultDir := t.TempDir()
	stalePath := filepath.Join(vaultDir, "manifest.age.tmp-old")
	freshPath := filepath.Join(vaultDir, "manifest.age.tmp-fresh")
	nestedDir := filepath.Join(vaultDir, "nested")
	nestedPath := filepath.Join(nestedDir, "manifest.age.tmp-old")

	for _, path := range []string{stalePath, freshPath} {
		if err := os.WriteFile(path, []byte("temporary"), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}
	if err := os.Mkdir(nestedDir, 0o700); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}
	if err := os.WriteFile(nestedPath, []byte("temporary"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", nestedPath, err)
	}

	old := time.Now().Add(-(staleTempFileAge + time.Minute))
	if err := os.Chtimes(stalePath, old, old); err != nil {
		t.Fatalf("Chtimes(stale): %v", err)
	}
	if err := os.Chtimes(nestedPath, old, old); err != nil {
		t.Fatalf("Chtimes(nested): %v", err)
	}

	r := checkVaultStaleTempFiles(vaultDir, Options{})
	if r.Fix == nil {
		t.Fatal("expected stale temp-file check to be fixable")
	}
	if err := r.Fix(); err != nil {
		t.Fatalf("Fix(): %v", err)
	}

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Errorf("stale file still exists, stat error = %v", err)
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Errorf("fresh file should remain, stat error = %v", err)
	}
	if _, err := os.Stat(nestedPath); err != nil {
		t.Errorf("nested file should remain, stat error = %v", err)
	}
}

func TestCheckVaultStaleTempFilesNoMatchesIsOK(t *testing.T) {
	r := checkVaultStaleTempFiles(t.TempDir(), Options{})
	if r.Status != StatusOK {
		t.Fatalf("status = %q, want %q", r.Status, StatusOK)
	}
}
