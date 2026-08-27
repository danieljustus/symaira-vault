package intake

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessFilesRejectsEmptyInput(t *testing.T) {
	spool, err := NewSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Remove()
	if _, err := ProcessFiles(spool, nil, DefaultOptions()); err == nil {
		t.Fatal("ProcessFiles with no paths should fail")
	}
}

func TestProcessFilesEnforcesFileLimit(t *testing.T) {
	spool, err := NewSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Remove()
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"a.env", "b.env"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("KEY=value\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	opts := DefaultOptions()
	opts.MaxFiles = 1
	if _, err := ProcessFiles(spool, paths, opts); err == nil {
		t.Fatal("ProcessFiles beyond MaxFiles should fail")
	}
}

func TestProcessFilesAppliesDefaultLimits(t *testing.T) {
	spool, err := NewSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Remove()
	dir := t.TempDir()
	src := filepath.Join(dir, "creds.env")
	if err := os.WriteFile(src, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Zero-valued limits must be replaced by the documented defaults.
	results, err := ProcessFiles(spool, []string{src}, Options{})
	if err != nil {
		t.Fatalf("ProcessFiles with zero limits: %v", err)
	}
	if len(results) != 1 || results[0].Status != StatusOK {
		t.Fatalf("results = %+v, want one ok result", results)
	}
}

func TestProcessFilesEnforcesBatchByteLimit(t *testing.T) {
	spool, err := NewSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Remove()
	dir := t.TempDir()
	var paths []string
	for _, name := range []string{"a.env", "b.env"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("KEY=value\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	opts := DefaultOptions()
	opts.MaxBatchSize = 1 // first file alone blows the batch budget
	results, err := ProcessFiles(spool, paths, opts)
	if err != nil {
		t.Fatalf("ProcessFiles: %v", err)
	}
	var skipped int
	for _, r := range results {
		if r.Status == StatusSkipped {
			skipped++
			if !strings.Contains(r.Reason, "byte total limit") {
				t.Fatalf("skip reason = %q, want batch byte limit", r.Reason)
			}
		}
	}
	if skipped == 0 {
		t.Fatalf("expected at least one skipped file, got %+v", results)
	}
}

func TestProcessFileClassifiesErrors(t *testing.T) {
	spool, err := NewSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Remove()

	// Deliberate rejection (nonexistent file → "stat ..." prefix) is a skip,
	// not a hard failure.
	res, err := ProcessFile(spool, filepath.Join(t.TempDir(), "missing.env"), DefaultOptions())
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if res.Status != StatusSkipped {
		t.Fatalf("status = %q, want skipped", res.Status)
	}
}

func TestIsRejectError(t *testing.T) {
	if isRejectError(nil) {
		t.Fatal("nil error is not a rejection")
	}
	for msg, want := range map[string]bool{
		"reject symlink":      true,
		"stat /nope":          true,
		"rejections are fine": false,
		"hash mismatch":       false,
	} {
		if got := isRejectError(errString(msg)); got != want {
			t.Fatalf("isRejectError(%q) = %t, want %t", msg, got, want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestProcessFileOCRText(t *testing.T) {
	spool, err := NewSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Remove()
	dir := t.TempDir()

	// Minimal valid PNG header so Sniff classifies it as an image.
	png := filepath.Join(dir, "shot.png")
	pngBytes := append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, make([]byte, 64)...)
	if err := os.WriteFile(png, pngBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	// Missing OCR text file is a hard per-file error.
	opts := DefaultOptions()
	opts.OCRText = filepath.Join(dir, "missing-ocr.txt")
	res, err := ProcessFile(spool, png, opts)
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if res.Status != StatusError || !strings.Contains(res.Reason, "read OCR text") {
		t.Fatalf("status = %q reason = %q, want OCR read error", res.Status, res.Reason)
	}

	// Present OCR text replaces the suggestion source.
	ocr := filepath.Join(dir, "ocr.txt")
	if err := os.WriteFile(ocr, []byte("username: carol\npassword: s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts.OCRText = ocr
	res, err = ProcessFile(spool, png, opts)
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if res.Status != StatusOK {
		t.Fatalf("status = %q, want ok", res.Status)
	}
}

func TestCleanupResultFiles(t *testing.T) {
	spool, err := NewSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Remove()
	dir := t.TempDir()
	src := filepath.Join(dir, "creds.env")
	if err := os.WriteFile(src, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ProcessFile(spool, src, DefaultOptions())
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	staged := res.spoolPath
	if staged == "" {
		t.Fatal("expected a staged spool path")
	}
	// Mixed slice: one result with a staged copy, one without.
	CleanupResultFiles([]FileResult{res, {File: "nope"}})
	if _, err := os.Lstat(staged); !os.IsNotExist(err) {
		t.Fatal("staged copy should be removed")
	}
	// The source file is never touched.
	if _, err := os.Lstat(src); err != nil {
		t.Fatal("source file must not be touched")
	}
}

func TestDirExistsAndBaseName(t *testing.T) {
	if !DirExists(t.TempDir()) {
		t.Fatal("DirExists on a real dir should be true")
	}
	if DirExists(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("DirExists on a missing path should be false")
	}
	file := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if DirExists(file) {
		t.Fatal("DirExists on a regular file should be false")
	}
	if got := BaseName("/some/dir/creds.env"); got != "creds.env" {
		t.Fatalf("BaseName = %q, want creds.env", got)
	}
}
