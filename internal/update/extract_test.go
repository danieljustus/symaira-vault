package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildTestTarGz creates an in-memory tar.gz archive containing the given
// entries. Each entry is a path to content mapping.
func buildTestTarGz(entries map[string]string, dirMode bool) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for path, content := range entries {
		if dirMode && content == "" {
			_ = tw.WriteHeader(&tar.Header{
				Name:     path,
				Typeflag: tar.TypeDir,
				Mode:     0o755,
			})
		} else {
			_ = tw.WriteHeader(&tar.Header{
				Name:     path,
				Typeflag: tar.TypeReg,
				Mode:     0o755,
				Size:     int64(len(content)),
			})
			_, _ = tw.Write([]byte(content))
		}
	}

	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

// buildTestZip creates an in-memory zip archive containing the given entries.
func buildTestZip(entries map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for path, content := range entries {
		if content == "" && strings.HasSuffix(path, "/") {
			_, _ = zw.Create(path)
		} else {
			w, _ := zw.Create(path)
			_, _ = w.Write([]byte(content))
		}
	}

	_ = zw.Close()
	return buf.Bytes()
}

func TestExtractTarGz_Success(t *testing.T) {
	dir := t.TempDir()
	archive := buildTestTarGz(map[string]string{
		"symaira_0.5.0_darwin_arm64/":          "",
		"symaira_0.5.0_darwin_arm64/symaira":  "binary-content",
		"symaira_0.5.0_darwin_arm64/LICENSE":   "MIT",
		"symaira_0.5.0_darwin_arm64/README.md": "# Symaira Vault",
	}, true)

	binaryPath, err := ExtractTarGz(archive, dir, "symaira")
	if err != nil {
		t.Fatalf("ExtractTarGz() error = %v", err)
	}

	expectedPath := filepath.Join(dir, "symaira_0.5.0_darwin_arm64", "symaira")
	if binaryPath != expectedPath {
		t.Fatalf("binaryPath = %q, want %q", binaryPath, expectedPath)
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", binaryPath, err)
	}
	if string(data) != "binary-content" {
		t.Fatalf("binary content = %q, want %q", string(data), "binary-content")
	}
}

func TestExtractTarGz_BinaryNotFound(t *testing.T) {
	dir := t.TempDir()
	archive := buildTestTarGz(map[string]string{
		"symaira_0.5.0_darwin_arm64/":        "",
		"symaira_0.5.0_darwin_arm64/LICENSE": "MIT",
	}, true)

	_, err := ExtractTarGz(archive, dir, "symaira")
	if err == nil {
		t.Fatal("expected ErrBinaryNotFound")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractTarGz_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := buildTestTarGz(map[string]string{
		"../../../etc/passwd": "root:x:0:0:",
	}, false)

	_, err := ExtractTarGz(archive, dir, "symaira")
	if err == nil {
		t.Fatal("expected path traversal error")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractTarGz_PathTraversalWithClean(t *testing.T) {
	dir := t.TempDir()
	archive := buildTestTarGz(map[string]string{
		"subdir/../../etc/passwd": "root:x:0:0:",
	}, false)

	_, err := ExtractTarGz(archive, dir, "symaira")
	if err == nil {
		t.Fatal("expected path traversal error")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractTarGz_GzipError(t *testing.T) {
	_, err := ExtractTarGz([]byte("not-gzip-data"), t.TempDir(), "symaira")
	if err == nil {
		t.Fatal("expected gzip error")
	}
}

func TestExtractZip_Success(t *testing.T) {
	dir := t.TempDir()
	archive := buildTestZip(map[string]string{
		"symaira_0.5.0_windows_amd64/":             "",
		"symaira_0.5.0_windows_amd64/symaira.exe": "binary-content-win",
		"symaira_0.5.0_windows_amd64/LICENSE":      "MIT",
	})

	binaryPath, err := ExtractZip(archive, dir, "symaira.exe")
	if err != nil {
		t.Fatalf("ExtractZip() error = %v", err)
	}

	expectedPath := filepath.Join(dir, "symaira_0.5.0_windows_amd64", "symaira.exe")
	if binaryPath != expectedPath {
		t.Fatalf("binaryPath = %q, want %q", binaryPath, expectedPath)
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", binaryPath, err)
	}
	if string(data) != "binary-content-win" {
		t.Fatalf("binary content = %q, want %q", string(data), "binary-content-win")
	}
}

func TestExtractZip_BinaryNotFound(t *testing.T) {
	dir := t.TempDir()
	archive := buildTestZip(map[string]string{
		"symaira_0.5.0_windows_amd64/":        "",
		"symaira_0.5.0_windows_amd64/LICENSE": "MIT",
	})

	_, err := ExtractZip(archive, dir, "symaira.exe")
	if err == nil {
		t.Fatal("expected ErrBinaryNotFound")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractZip_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := buildTestZip(map[string]string{
		"../../../etc/passwd": "root:x:0:0:",
	})

	_, err := ExtractZip(archive, dir, "symaira")
	if err == nil {
		t.Fatal("expected path traversal error")
	}
	if !strings.Contains(err.Error(), "path traversal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractZip_InvalidData(t *testing.T) {
	_, err := ExtractZip([]byte("not-zip-data"), t.TempDir(), "symaira.exe")
	if err == nil {
		t.Fatal("expected zip error")
	}
}

func TestExtractZip_EmptyArchive(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	_ = zw.Close()

	_, err := ExtractZip(buf.Bytes(), dir, "symaira")
	if err == nil {
		t.Fatal("expected ErrBinaryNotFound for empty archive")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafeArchivePath_RejectsTraversal(t *testing.T) {
	_, err := safeArchivePath("/tmp/dest", "../etc/passwd")
	if err == nil {
		t.Fatal("expected path traversal error")
	}
}

func TestSafeArchivePath_AcceptsNestedPath(t *testing.T) {
	path, err := safeArchivePath("/tmp/dest", "subdir/file.txt")
	if err != nil {
		t.Fatalf("safeArchivePath() error = %v", err)
	}
	expected := filepath.Join("/tmp/dest", "subdir/file.txt")
	if path != expected {
		t.Fatalf("got %q, want %q", path, expected)
	}
}

func TestExtractTarGz_ReadsLargeBinary(t *testing.T) {
	dir := t.TempDir()
	content := strings.Repeat("A", 10000)
	archive := buildTestTarGz(map[string]string{
		"bundle/symaira": content,
	}, true)

	binaryPath, err := ExtractTarGz(archive, dir, "symaira")
	if err != nil {
		t.Fatalf("ExtractTarGz() error = %v", err)
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != content {
		t.Fatalf("content length mismatch: got %d, want %d", len(data), len(content))
	}
}

func TestExtractTarGz_PreservesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: file mode preservation not supported")
	}
	dir := t.TempDir()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{
		Name:     "symaira",
		Typeflag: tar.TypeReg,
		Mode:     0o755,
		Size:     int64(len("content")),
	})
	_, _ = tw.Write([]byte("content"))
	_ = tw.Close()
	_ = gw.Close()

	binaryPath, err := ExtractTarGz(buf.Bytes(), dir, "symaira")
	if err != nil {
		t.Fatalf("ExtractTarGz() error = %v", err)
	}

	info, err := os.Stat(binaryPath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("expected extracted binary to be executable")
	}
}

func TestExtractTarGz_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	_ = tw.WriteHeader(&tar.Header{
		Name:     "subdir/",
		Typeflag: tar.TypeDir,
		Mode:     0o755,
	})
	_ = tw.WriteHeader(&tar.Header{
		Name:     "subdir/link",
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
	})
	_ = tw.WriteHeader(&tar.Header{
		Name:     "subdir/symaira",
		Typeflag: tar.TypeReg,
		Mode:     0o755,
		Size:     int64(len("safe")),
	})
	_, _ = tw.Write([]byte("safe"))
	_ = tw.Close()
	_ = gw.Close()

	binaryPath, err := ExtractTarGz(buf.Bytes(), dir, "symaira")
	if err != nil {
		t.Fatalf("ExtractTarGz() error = %v", err)
	}

	// Verify the symlink was NOT created
	if _, err := os.Stat(filepath.Join(dir, "subdir", "link")); err == nil {
		t.Fatal("symlink should not have been extracted")
	}

	// Verify the binary IS there
	if _, err := os.Stat(binaryPath); err != nil {
		t.Fatalf("binary not found after extraction: %v", err)
	}
}

func TestExtractTarGz_EmptyArchive(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_ = gw.Close()

	_, err := ExtractTarGz(buf.Bytes(), dir, "symaira")
	if err == nil {
		t.Fatal("expected ErrBinaryNotFound for empty archive")
	}
}

func TestExtractZip_ReadsLargeBinary(t *testing.T) {
	dir := t.TempDir()
	content := strings.Repeat("B", 10000)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("bundle/symaira.exe")
	_, _ = w.Write([]byte(content))
	_ = zw.Close()

	binaryPath, err := ExtractZip(buf.Bytes(), dir, "symaira.exe")
	if err != nil {
		t.Fatalf("ExtractZip() error = %v", err)
	}

	data, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != content {
		t.Fatalf("content mismatch")
	}
}
