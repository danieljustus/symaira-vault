package admin

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreBackupRejectsOversizedFile(t *testing.T) {
	oldFileLimit := maxRestoreFileSize
	oldTotalLimit := maxRestoreTotalSize
	maxRestoreFileSize = 4
	maxRestoreTotalSize = 1024
	t.Cleanup(func() {
		maxRestoreFileSize = oldFileLimit
		maxRestoreTotalSize = oldTotalLimit
	})

	archivePath := filepath.Join(t.TempDir(), "oversized.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	content := []byte("too large")
	if err := tw.WriteHeader(&tar.Header{Name: "identity.age", Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}

	err = RestoreBackup(archivePath, t.TempDir())
	if err == nil {
		t.Fatal("expected error for oversized archive entry")
	}
	if !strings.Contains(err.Error(), "exceeds maximum file size") {
		t.Fatalf("error = %v, want file size limit rejection", err)
	}
}
