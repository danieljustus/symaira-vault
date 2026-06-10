package secureedit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/danieljustus/symaira-vault/internal/secrets"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

var CreateTemp = os.CreateTemp

func DefaultStreams() Streams {
	return Streams{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

func EditEntry(entry *vaultpkg.Entry, preferredEditor string, streams Streams) (*vaultpkg.Entry, error) {
	if entry == nil {
		return nil, fmt.Errorf("nil entry")
	}

	tmp, err := CreateTemp("", "symvault-edit-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = SecureDeleteFile(tmpPath) }()

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("set temp file permissions: %w", err)
	}

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(entry); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("encode entry: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("close temp file: %w", err)
	}

	editor, err := ResolveEditor(preferredEditor)
	if err != nil {
		return nil, err
	}

	//#nosec G204 -- editor path validated via exec.LookPath in ResolveEditor.
	cmd := exec.Command(editor, tmpPath)
	secrets.PrepareCmd(cmd)
	cmd.Stdin = streams.Stdin
	cmd.Stdout = streams.Stdout
	cmd.Stderr = streams.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("editor failed: %w", err)
	}

	data, err := os.ReadFile(filepath.Clean(tmpPath)) //#nosec G304 -- tmpPath was created by this process.
	if err != nil {
		return nil, fmt.Errorf("read edited file: %w", err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty file, changes discarded")
	}

	var edited vaultpkg.Entry
	if err := json.Unmarshal(data, &edited); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if edited.Data == nil {
		edited.Data = map[string]any{}
	}
	return &edited, nil
}

func ResolveEditor(preferred string) (string, error) {
	if preferred != "" {
		return resolveEditorPath(preferred)
	}

	if envEditor := os.Getenv("EDITOR"); envEditor != "" {
		return resolveEditorPath(envEditor)
	}

	candidates := []string{"vim", "nano", "vi"}
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no editor found on PATH (tried %v); set $EDITOR to a valid editor", candidates)
}

func resolveEditorPath(editor string) (string, error) {
	path, err := exec.LookPath(editor)
	if err != nil {
		return "", fmt.Errorf("editor %q not found in PATH", editor)
	}
	return path, nil
}

func SecureDeleteFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //#nosec G304 -- path comes from CreateTemp in EditEntry.
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}

	zeros := make([]byte, 4096)
	remaining := fi.Size()
	for remaining > 0 {
		chunk := zeros
		if remaining < int64(len(chunk)) {
			chunk = chunk[:remaining]
		}
		n, err := f.Write(chunk)
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return err
		}
		if n == 0 {
			_ = f.Close()
			_ = os.Remove(path)
			return io.ErrShortWrite
		}
		remaining -= int64(n)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}

	_ = f.Close()
	return os.Remove(path)
}
