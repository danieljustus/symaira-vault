package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/danieljustus/OpenPass/internal/pathutil"
)

var (
	// ErrBinaryNotFound is returned when the expected binary is not found
	// inside the archive.
	ErrBinaryNotFound = errors.New("binary not found in archive")

	// ErrPathTraversal is returned when an archive entry attempts to escape
	// the destination directory.
	ErrPathTraversal = errors.New("archive entry attempts path traversal")
)

// maxExtractSize limits the total bytes extracted from an archive to prevent
// decompression bomb attacks (G110).
const maxExtractSize = 100 * 1024 * 1024 // 100 MB

// safeArchivePath validates that entryPath does not escape destDir. It checks
// for parent-directory traversal segments and verifies that the cleaned,
// resolved path is a child of destDir.
func safeArchivePath(destDir, entryPath string) (string, error) {
	if pathutil.HasTraversal(entryPath) {
		return "", fmt.Errorf("%w: %q", ErrPathTraversal, entryPath)
	}

	cleanDest := filepath.Clean(destDir)
	fullPath := filepath.Clean(filepath.Join(cleanDest, entryPath))

	// Ensure the resolved path is within destDir (or is destDir itself for
	// the root directory entry).
	if !strings.HasPrefix(fullPath, cleanDest+string(filepath.Separator)) && fullPath != cleanDest {
		return "", fmt.Errorf("%w: %q resolves outside %q", ErrPathTraversal, entryPath, destDir)
	}

	return fullPath, nil
}

// ExtractTarGz extracts a gzip-compressed tar archive to destDir and returns
// the path to the extracted binary matching expectedBinaryName. It protects
// against path traversal attacks and skips symlinks for safety.
func ExtractTarGz(data []byte, destDir, expectedBinaryName string) (string, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("decompress gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	var binaryPath string
	var totalSize int64

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar header: %w", err)
		}

		safePath, err := safeArchivePath(destDir, header.Name)
		if err != nil {
			return "", err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(safePath, 0o750); err != nil {
				return "", fmt.Errorf("create directory %q: %w", safePath, err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(safePath), 0o750); err != nil {
				return "", fmt.Errorf("create parent dir for %q: %w", safePath, err)
			}

			var mode os.FileMode
			if header.Mode < 0 || header.Mode > math.MaxUint32 {
				mode = 0o600
			} else {
				mode = os.FileMode(header.Mode)
			}

			f, err := os.OpenFile(filepath.Clean(safePath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return "", fmt.Errorf("create file %q: %w", safePath, err)
			}

			n, err := io.Copy(f, io.LimitReader(tr, maxExtractSize-totalSize))
			totalSize += n
			_ = f.Close()
			if err != nil {
				return "", fmt.Errorf("write file %q: %w", safePath, err)
			}
			if totalSize >= maxExtractSize {
				return "", fmt.Errorf("archive exceeds maximum extraction size of %d bytes", maxExtractSize)
			}

			if filepath.Base(header.Name) == expectedBinaryName {
				binaryPath = safePath
			}

		default:
			// Skip symlinks, hard links, special devices, etc.
			continue
		}
	}

	if binaryPath == "" {
		return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, expectedBinaryName)
	}

	return binaryPath, nil
}

// ExtractZip extracts a zip archive to destDir and returns the path to the
// extracted binary matching expectedBinaryName. It protects against path
// traversal attacks.
func ExtractZip(data []byte, destDir, expectedBinaryName string) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open zip archive: %w", err)
	}

	var binaryPath string
	var totalSize int64

	for _, f := range zr.File {
		safePath, err := safeArchivePath(destDir, f.Name)
		if err != nil {
			return "", err
		}

		if f.FileInfo().IsDir() {
			if mkdirErr := os.MkdirAll(safePath, 0o750); mkdirErr != nil {
				return "", fmt.Errorf("create directory %q: %w", safePath, mkdirErr)
			}
			continue
		}

		if mkdirErr := os.MkdirAll(filepath.Dir(safePath), 0o750); mkdirErr != nil {
			return "", fmt.Errorf("create parent dir for %q: %w", safePath, mkdirErr)
		}

		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}

		out, err := os.OpenFile(filepath.Clean(safePath), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			_ = rc.Close()
			return "", fmt.Errorf("create file %q: %w", safePath, err)
		}

		n, err := io.Copy(out, io.LimitReader(rc, maxExtractSize-totalSize))
		totalSize += n
		_ = out.Close()
		_ = rc.Close()
		if err != nil {
			return "", fmt.Errorf("write file %q: %w", safePath, err)
		}
		if totalSize >= maxExtractSize {
			return "", fmt.Errorf("archive exceeds maximum extraction size of %d bytes", maxExtractSize)
		}

		if filepath.Base(f.Name) == expectedBinaryName {
			binaryPath = safePath
		}
	}

	if binaryPath == "" {
		return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, expectedBinaryName)
	}

	return binaryPath, nil
}
