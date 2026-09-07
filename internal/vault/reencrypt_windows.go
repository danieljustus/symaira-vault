//go:build windows

package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type windowsReencryptCandidate struct {
	path        string
	entriesPath string
	parentPath  string
	parentInfo  os.FileInfo
}

type windowsReencryptStaged struct {
	tempPath   string
	backupPath string
}

func prepareReencryptCandidate(entriesPath, path string, walked os.FileInfo) (*reencryptCandidate, error) {
	rel, err := filepath.Rel(entriesPath, path)
	if err != nil || rel == "." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return nil, fmt.Errorf("entry path escapes entries directory: %q", path)
	}
	if err := rejectWindowsAncestors(entriesPath, filepath.Dir(rel)); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat entry %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("entry %q is not a regular file", path)
	}
	if !os.SameFile(walked, info) {
		return nil, fmt.Errorf("entry %q changed during preflight", path)
	}
	file, openedInfo, err := openWindowsRegular(path)
	if err != nil {
		return nil, fmt.Errorf("open entry %q: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("entry %q changed while opening", path)
	}
	data, err := io.ReadAll(file)
	closeErr := file.Close()
	if err != nil {
		return nil, fmt.Errorf("read entry %q: %w", path, err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close entry %q: %w", path, closeErr)
	}
	parentPath := filepath.Dir(path)
	parentInfo, err := os.Stat(parentPath)
	if err != nil {
		return nil, fmt.Errorf("stat entry directory %q: %w", parentPath, err)
	}
	return &reencryptCandidate{
		path:     path,
		logical:  strings.TrimSuffix(filepath.ToSlash(rel), entryExtAge),
		raw:      data,
		mode:     openedInfo.Mode().Perm(),
		mtime:    openedInfo.ModTime(),
		platform: &windowsReencryptCandidate{path: path, entriesPath: entriesPath, parentPath: parentPath, parentInfo: parentInfo},
	}, nil
}

func openWindowsRegular(path string) (*os.File, os.FileInfo, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = file.Close()
		return nil, nil, fmt.Errorf("path is a reparse point")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("path is not a regular file")
	}
	return file, info, nil
}

func rejectWindowsAncestors(entriesPath, relativeDir string) error {
	current := entriesPath
	if info, err := os.Lstat(current); err != nil {
		return fmt.Errorf("stat entries directory: %w", err)
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("entries directory is not a real directory")
	}
	if relativeDir == "." {
		return nil
	}
	for _, part := range strings.Split(filepath.ToSlash(relativeDir), "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("invalid entry directory")
		}
		current = filepath.Join(current, filepath.FromSlash(part))
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("stat entry directory %q: %w", current, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("entry ancestor %q is not a real directory", current)
		}
	}
	return nil
}

func stageReencryptFile(candidate *reencryptCandidate, ciphertext []byte) (*reencryptStaged, error) {
	c := candidate.platform.(*windowsReencryptCandidate)
	parent := filepath.Dir(c.path)
	rel, err := filepath.Rel(c.entriesPath, c.path)
	if err != nil {
		return nil, err
	}
	if err := rejectWindowsAncestors(c.entriesPath, filepath.Dir(rel)); err != nil {
		// The candidate's preflight already checked the full ancestor chain;
		// retain this final check immediately before creating the stage file.
		return nil, err
	}
	file, err := os.CreateTemp(parent, ".reencrypt-*")
	if err != nil {
		return nil, err
	}
	tempPath := file.Name()
	removeTemp := func() {
		_ = file.Close()
		_ = os.Remove(tempPath)
	}
	if err := file.Chmod(candidate.mode.Perm()); err != nil {
		removeTemp()
		return nil, err
	}
	if _, err := file.Write(ciphertext); err != nil {
		removeTemp()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		removeTemp()
		return nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return nil, err
	}
	item := &reencryptStaged{candidate: candidate, platform: &windowsReencryptStaged{tempPath: tempPath}}
	if err := recordReencryptStage(item, ciphertext); err != nil {
		_ = os.Remove(tempPath)
		return nil, err
	}
	return item, nil
}

func verifyWindowsReencryptParent(c *windowsReencryptCandidate) error {
	if rel, err := filepath.Rel(c.entriesPath, c.parentPath); err != nil {
		return err
	} else if err := rejectWindowsAncestors(c.entriesPath, rel); err != nil {
		return err
	}
	info, err := os.Stat(c.parentPath)
	if err != nil {
		return err
	}
	if !os.SameFile(c.parentInfo, info) {
		return fmt.Errorf("entry ancestor changed during operation")
	}
	return nil
}

func commitReencryptFile(item *reencryptStaged) error {
	c := item.candidate.platform.(*windowsReencryptCandidate)
	staged := item.platform.(*windowsReencryptStaged)
	if err := verifyWindowsReencryptParent(c); err != nil {
		return fmt.Errorf("verify target directory: %w", err)
	}
	info, err := os.Lstat(c.path)
	if err != nil {
		return fmt.Errorf("stat target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("target is not a regular file")
	}
	// SameFile detects a final-name replacement between preflight and commit.
	original, err := os.Stat(c.path)
	if err != nil || !os.SameFile(info, original) {
		return fmt.Errorf("target changed during commit")
	}
	staged.backupPath = c.path + ".reencrypt-backup"
	for i := 0; i < 10; i++ {
		if _, statErr := os.Lstat(staged.backupPath); os.IsNotExist(statErr) {
			break
		}
		staged.backupPath = fmt.Sprintf("%s.%d", c.path+".reencrypt-backup", i)
	}
	if err := recordReencryptBackup(item); err != nil {
		staged.backupPath = ""
		return fmt.Errorf("record original backup: %w", err)
	}
	if err := os.Rename(c.path, staged.backupPath); err != nil {
		return fmt.Errorf("move original to backup: %w", err)
	}
	if err := os.Rename(staged.tempPath, c.path); err != nil {
		_ = os.Rename(staged.backupPath, c.path)
		staged.backupPath = ""
		return fmt.Errorf("install staged file: %w", err)
	}
	staged.tempPath = ""
	item.committed = true
	if err := recordReencryptInstalled(item); err != nil {
		return fmt.Errorf("record installed file: %w", err)
	}
	if err := verifyWindowsReencryptParent(c); err != nil {
		if rollbackErr := rollbackReencryptFile(item); rollbackErr != nil {
			return fmt.Errorf("verify target directory: %w (rollback: %v)", err, rollbackErr)
		}
		return err
	}
	return nil
}

func rollbackReencryptFile(item *reencryptStaged) error {
	c := item.candidate.platform.(*windowsReencryptCandidate)
	staged := item.platform.(*windowsReencryptStaged)
	if staged.backupPath == "" {
		return nil
	}
	if err := verifyWindowsReencryptParent(c); err != nil {
		return fmt.Errorf("verify rollback directory: %w", err)
	}
	matches, err := verifyReencryptDigest(c.path, item.candidate.digest)
	if err != nil {
		return fmt.Errorf("verify installed target: %w", err)
	}
	if !matches {
		return fmt.Errorf("installed target changed during rollback")
	}
	if exists, err := reencryptRegularExists(staged.backupPath); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("original backup disappeared during rollback")
	}
	if err := os.Remove(c.path); err != nil {
		return fmt.Errorf("remove installed target: %w", err)
	}
	if err := os.Rename(staged.backupPath, c.path); err != nil {
		return fmt.Errorf("restore original target: %w", err)
	}
	staged.backupPath = ""
	item.committed = false
	return nil
}

func cleanupReencryptFile(item *reencryptStaged) error {
	staged := item.platform.(*windowsReencryptStaged)
	var firstErr error
	if staged.tempPath != "" {
		if err := os.Remove(staged.tempPath); err != nil && !os.IsNotExist(err) {
			firstErr = err
		} else {
			staged.tempPath = ""
		}
	}
	if staged.backupPath != "" {
		if err := os.Remove(staged.backupPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		} else if err == nil || os.IsNotExist(err) {
			staged.backupPath = ""
		}
	}
	return firstErr
}

func closeReencryptCandidates(_ []*reencryptCandidate) {}
