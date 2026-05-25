package importer

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/envfilter"
)

type passImporter struct {
	dir string
}

// NewPassImporter creates an importer for a pass (password-store) directory.
// The Parse reader is ignored when dir is set; pass stores are directory trees.
func NewPassImporter(dir string) Importer {
	return &passImporter{dir: dir}
}

// ImportPass imports entries from a pass (password-store) directory.
func ImportPass(dir string) ([]ImportedEntry, error) {
	return NewPassImporter(dir).Parse(nil)
}

func (i *passImporter) Parse(r io.Reader) ([]ImportedEntry, error) {
	dir := i.dir
	if dir == "" {
		file, ok := r.(*os.File)
		if !ok {
			return nil, fmt.Errorf("pass import requires a directory path")
		}
		dir = file.Name()
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("open pass store: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pass store is not a directory: %s", dir)
	}

	var entries []ImportedEntry
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk pass store: %w", err)
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".gpg") {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("resolve pass entry path: %w", err)
		}

		content, err := decryptPassFile(path)
		if err != nil {
			return err
		}

		entries = append(entries, ImportedEntry{
			Path: passEntryPath(relPath),
			Data: parsePassEntry(content),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func decryptPassFile(path string) (string, error) {
	cmd := exec.Command("gpg", "--decrypt", "--batch", "--yes", path)
	envfilter.PrepareCmd(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("decrypt pass entry %s: %s", path, message)
	}

	return string(output), nil
}

func passEntryPath(relPath string) string {
	path := strings.TrimSuffix(relPath, ".gpg")
	path = filepath.ToSlash(path)
	return NormalizePath(path)
}

func parsePassEntry(content string) map[string]any {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	content = strings.TrimSuffix(content, "\n")

	lines := strings.Split(content, "\n")
	data := map[string]any{"password": ""}
	if len(lines) == 0 {
		return data
	}

	data["password"] = lines[0]
	var notes []string
	for _, line := range lines[1:] {
		switch {
		case strings.HasPrefix(line, "url: "):
			data["url"] = strings.TrimSpace(strings.TrimPrefix(line, "url: "))
		case strings.HasPrefix(line, "username: "):
			data["username"] = strings.TrimSpace(strings.TrimPrefix(line, "username: "))
		case strings.HasPrefix(line, "otpauth://"):
			data["totp"] = strings.TrimSpace(line)
		default:
			notes = append(notes, line)
		}
	}

	if len(notes) > 0 {
		data["notes"] = strings.Join(notes, "\n")
	}
	return data
}
