package admin

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
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

// Read real tar headers before restoring: normalizing only an observer's paths
// would hide the Windows writer bug that rejected its own nested members.
func TestCreateBackup_NormalizesTarMemberSeparators(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	files := map[string][]byte{"identity.age": []byte("synthetic identity"), "config.yaml": []byte("vault_dir: fixture\n"), "entries/nested/item.age": []byte("synthetic ciphertext")}
	for name, data := range files {
		path := filepath.Join(source, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := CreateBackup(source, archive, false); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	observed := make(map[string]bool)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(header.Name, `\`) {
			t.Fatalf("nonportable actual tar member %q", header.Name)
		}
		if header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			expected, exists := files[header.Name]
			if !exists || !bytes.Equal(data, expected) {
				t.Fatalf("unexpected tar member/content %q", header.Name)
			}
			if observed[header.Name] {
				t.Fatalf("duplicate tar member %q", header.Name)
			}
			observed[header.Name] = true
		}
	}
	if len(observed) != len(files) {
		t.Fatalf("archive has %d files, want %d", len(observed), len(files))
	}
	destination := filepath.Join(t.TempDir(), "restored")
	if err := RestoreBackup(archive, destination); err != nil {
		t.Fatal(err)
	}
	for name, expected := range files {
		data, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(data, expected) {
			t.Fatalf("restored %s changed: %v", name, err)
		}
	}
}
