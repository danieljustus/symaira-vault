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

	"github.com/danieljustus/symaira-vault/internal/fsutil"
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

// validateArchiveEntryName rejects archive entry names that reference an
// absolute path or contain a parent-directory traversal segment before they
// ever reach a filesystem call. Containment is additionally enforced at the
// syscall level by os.Root in ExtractTarGz/ExtractZip, which refuses any
// access that would escape the destination directory even if this check were
// bypassed (e.g. via a symlinked path component).
func validateArchiveEntryName(entryPath string) error {
	// Archive entries use POSIX-style forward slashes regardless of the host
	// OS, so a leading slash means "rooted" even on Windows, where
	// filepath.IsAbs requires a drive letter and would otherwise miss it.
	if entryPath == "" || filepath.IsAbs(entryPath) ||
		strings.HasPrefix(filepath.ToSlash(entryPath), "/") || fsutil.HasTraversal(entryPath) {
		return fmt.Errorf("%w: %q", ErrPathTraversal, entryPath)
	}
	return nil
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

	root, err := os.OpenRoot(destDir)
	if err != nil {
		return "", fmt.Errorf("open destination directory %q: %w", destDir, err)
	}
	defer func() { _ = root.Close() }()

	tr := tar.NewReader(gr)
	var binaryName string
	var totalSize int64

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read tar header: %w", err)
		}

		if err := validateArchiveEntryName(header.Name); err != nil {
			return "", err
		}
		name := filepath.Clean(filepath.ToSlash(header.Name))

		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o750); err != nil {
				return "", fmt.Errorf("create directory %q: %w", name, err)
			}

		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(name), 0o750); err != nil {
				return "", fmt.Errorf("create parent dir for %q: %w", name, err)
			}

			var mode os.FileMode
			if header.Mode < 0 || header.Mode > math.MaxUint32 {
				mode = 0o600
			} else {
				mode = os.FileMode(header.Mode).Perm()
			}

			f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return "", fmt.Errorf("create file %q: %w", name, err)
			}

			n, err := io.Copy(f, io.LimitReader(tr, maxExtractSize-totalSize))
			totalSize += n
			_ = f.Close()
			if err != nil {
				return "", fmt.Errorf("write file %q: %w", name, err)
			}
			if totalSize >= maxExtractSize {
				return "", fmt.Errorf("archive exceeds maximum extraction size of %d bytes", maxExtractSize)
			}

			if filepath.Base(name) == expectedBinaryName {
				binaryName = name
			}

		default:
			// Skip symlinks, hard links, special devices, etc.
			continue
		}
	}

	if binaryName == "" {
		return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, expectedBinaryName)
	}

	return filepath.Join(destDir, binaryName), nil
}

// ExtractZip extracts a zip archive to destDir and returns the path to the
// extracted binary matching expectedBinaryName. It protects against path
// traversal attacks.
func ExtractZip(data []byte, destDir, expectedBinaryName string) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open zip archive: %w", err)
	}

	root, err := os.OpenRoot(destDir)
	if err != nil {
		return "", fmt.Errorf("open destination directory %q: %w", destDir, err)
	}
	defer func() { _ = root.Close() }()

	var binaryName string
	var totalSize int64

	for _, f := range zr.File {
		if err := validateArchiveEntryName(f.Name); err != nil {
			return "", err
		}
		name := filepath.Clean(filepath.ToSlash(f.Name))

		if f.FileInfo().IsDir() {
			if mkdirErr := root.MkdirAll(name, 0o750); mkdirErr != nil {
				return "", fmt.Errorf("create directory %q: %w", name, mkdirErr)
			}
			continue
		}

		if mkdirErr := root.MkdirAll(filepath.Dir(name), 0o750); mkdirErr != nil {
			return "", fmt.Errorf("create parent dir for %q: %w", name, mkdirErr)
		}

		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}

		out, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm())
		if err != nil {
			_ = rc.Close()
			return "", fmt.Errorf("create file %q: %w", name, err)
		}

		n, err := io.Copy(out, io.LimitReader(rc, maxExtractSize-totalSize))
		totalSize += n
		_ = out.Close()
		_ = rc.Close()
		if err != nil {
			return "", fmt.Errorf("write file %q: %w", name, err)
		}
		if totalSize >= maxExtractSize {
			return "", fmt.Errorf("archive exceeds maximum extraction size of %d bytes", maxExtractSize)
		}

		if filepath.Base(name) == expectedBinaryName {
			binaryName = name
		}
	}

	if binaryName == "" {
		return "", fmt.Errorf("%w: %s", ErrBinaryNotFound, expectedBinaryName)
	}

	return filepath.Join(destDir, binaryName), nil
}
