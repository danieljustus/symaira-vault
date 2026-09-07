//go:build !windows

package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type unixReencryptCandidate struct {
	parent     *os.File
	parentInfo os.FileInfo
	parentPath string
	name       string
	dev        uint64
	ino        uint64
}

type unixReencryptStaged struct {
	parent     *os.File
	tempName   string
	backupName string
	stagedDev  uint64
	stagedIno  uint64
}

func prepareReencryptCandidate(entriesPath, path string, walked os.FileInfo) (*reencryptCandidate, error) {
	rel, err := filepath.Rel(entriesPath, path)
	if err != nil || rel == "." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return nil, fmt.Errorf("entry path escapes entries directory: %q", path)
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid entry path: %q", path)
	}

	parent, err := openDirNoFollow(entriesPath)
	if err != nil {
		return nil, fmt.Errorf("open entries directory: %w", err)
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			_ = parent.Close()
			return nil, fmt.Errorf("invalid entry path: %q", path)
		}
		fd, openErr := unix.Openat(int(parent.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			_ = parent.Close()
			return nil, fmt.Errorf("open entry directory %q: %w", path, openErr)
		}
		next := os.NewFile(uintptr(fd), part)
		_ = parent.Close()
		parent = next
	}

	name := parts[len(parts)-1]
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("open entry %q without following links: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("stat entry %q: %w", path, err)
	}
	if !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("entry %q is not a regular file", path)
	}
	if !os.SameFile(walked, openedInfo) {
		_ = file.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("entry %q changed during preflight", path)
	}
	data, err := io.ReadAll(file)
	closeErr := file.Close()
	if err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("read entry %q: %w", path, err)
	}
	if closeErr != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("close entry %q: %w", path, closeErr)
	}
	stat, ok := openedInfo.Sys().(*syscall.Stat_t)
	if !ok {
		_ = parent.Close()
		return nil, fmt.Errorf("stat entry %q has unsupported metadata", path)
	}
	parentInfo, err := parent.Stat()
	if err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("stat entry directory %q: %w", path, err)
	}
	parentPath, err := resolveTrustedSymlinks(filepath.Dir(path))
	if err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("resolve entry directory %q: %w", path, err)
	}
	return &reencryptCandidate{
		path:     path,
		logical:  strings.TrimSuffix(filepath.ToSlash(rel), entryExtAge),
		raw:      data,
		mode:     openedInfo.Mode().Perm(),
		mtime:    openedInfo.ModTime(),
		platform: &unixReencryptCandidate{parent: parent, parentInfo: parentInfo, parentPath: parentPath, name: name, dev: uint64(stat.Dev), ino: stat.Ino},
	}, nil
}

func resolveTrustedSymlinks(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, lstatErr := os.Lstat(current)
		if lstatErr != nil {
			return "", lstatErr
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return "", fmt.Errorf("untrusted symlink in path %q", current)
		}
	}
	return filepath.EvalSymlinks(absolute)
}

func openDirNoFollow(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute, err = resolveTrustedSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(absolute)
	if volume != "" {
		return nil, fmt.Errorf("unsupported volume path %q", path)
	}
	root, err := os.Open(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	current := root
	parts := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		fd, openErr := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open directory component %q: %w", part, openErr)
		}
		next := os.NewFile(uintptr(fd), filepath.Join(current.Name(), part))
		_ = current.Close()
		current = next
	}
	return current, nil
}

func newReencryptTempName(base string) (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf(".%s.reencrypt-%s", base, hex.EncodeToString(random[:])), nil
}

func stageReencryptFile(candidate *reencryptCandidate, ciphertext []byte) (*reencryptStaged, error) {
	c, ok := candidate.platform.(*unixReencryptCandidate)
	if !ok {
		return nil, fmt.Errorf("invalid Unix re-encryption candidate")
	}
	var file *os.File
	var tempName string
	for attempt := 0; attempt < 10; attempt++ {
		name, err := newReencryptTempName(filepath.Base(candidate.path))
		if err != nil {
			return nil, err
		}
		fd, openErr := unix.Openat(int(c.parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(candidate.mode.Perm()))
		if openErr == unix.EEXIST {
			continue
		}
		if openErr != nil {
			return nil, openErr
		}
		file = os.NewFile(uintptr(fd), name)
		tempName = name
		break
	}
	if file == nil {
		return nil, fmt.Errorf("could not allocate staging file")
	}
	removeTemp := func() {
		_ = file.Close()
		_ = unix.Unlinkat(int(c.parent.Fd()), tempName, 0)
	}
	if _, err := file.Write(ciphertext); err != nil {
		removeTemp()
		return nil, err
	}
	if err := file.Chmod(candidate.mode.Perm()); err != nil {
		removeTemp()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		removeTemp()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		removeTemp()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		removeTemp()
		return nil, fmt.Errorf("staging file has unsupported metadata")
	}
	if err := file.Close(); err != nil {
		_ = unix.Unlinkat(int(c.parent.Fd()), tempName, 0)
		return nil, err
	}
	return &reencryptStaged{
		candidate: candidate,
		platform:  &unixReencryptStaged{parent: c.parent, tempName: tempName, stagedDev: uint64(stat.Dev), stagedIno: stat.Ino},
	}, nil
}

func statAtNoFollow(parent *os.File, name string) (dev, ino uint64, mode uint32, err error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, 0, 0, err
	}
	return uint64(stat.Dev), stat.Ino, uint32(stat.Mode), nil
}

func verifyReencryptParent(c *unixReencryptCandidate) error {
	current, err := openDirNoFollow(c.parentPath)
	if err != nil {
		return fmt.Errorf("open target directory: %w", err)
	}
	defer func() { _ = current.Close() }()
	info, err := current.Stat()
	if err != nil {
		return fmt.Errorf("stat target directory: %w", err)
	}
	if !os.SameFile(c.parentInfo, info) {
		return fmt.Errorf("entry ancestor changed during operation")
	}
	return nil
}

func commitReencryptFile(item *reencryptStaged) error {
	c, ok := item.candidate.platform.(*unixReencryptCandidate)
	if !ok {
		return fmt.Errorf("invalid Unix re-encryption candidate")
	}
	staged, ok := item.platform.(*unixReencryptStaged)
	if !ok {
		return fmt.Errorf("invalid Unix re-encryption staging state")
	}
	if err := verifyReencryptParent(c); err != nil {
		return err
	}
	dev, ino, mode, err := statAtNoFollow(c.parent, c.name)
	if err != nil {
		return fmt.Errorf("stat target: %w", err)
	}
	if mode&unix.S_IFMT != unix.S_IFREG || dev != c.dev || ino != c.ino {
		return fmt.Errorf("target changed during commit")
	}
	var backupName string
	for attempt := 0; attempt < 10; attempt++ {
		name, nameErr := newReencryptTempName(filepath.Base(c.name) + ".backup")
		if nameErr != nil {
			return nameErr
		}
		if _, _, _, statErr := statAtNoFollow(c.parent, name); errors.Is(statErr, unix.ENOENT) {
			backupName = name
			break
		}
	}
	if backupName == "" {
		return fmt.Errorf("could not allocate backup file")
	}
	if err := unix.Renameat(int(c.parent.Fd()), c.name, int(c.parent.Fd()), backupName); err != nil {
		return fmt.Errorf("move original to backup: %w", err)
	}
	staged.backupName = backupName
	if err := unix.Renameat(int(c.parent.Fd()), staged.tempName, int(c.parent.Fd()), c.name); err != nil {
		_ = unix.Renameat(int(c.parent.Fd()), backupName, int(c.parent.Fd()), c.name)
		staged.backupName = ""
		return fmt.Errorf("install staged file: %w", err)
	}
	staged.tempName = ""
	item.committed = true
	if err := verifyReencryptParent(c); err != nil {
		if rollbackErr := rollbackReencryptFile(item); rollbackErr != nil {
			return fmt.Errorf("verify target directory: %w (rollback: %w)", err, rollbackErr)
		}
		return err
	}
	return nil
}

func rollbackReencryptFile(item *reencryptStaged) error {
	c, ok := item.candidate.platform.(*unixReencryptCandidate)
	if !ok {
		return fmt.Errorf("invalid Unix re-encryption candidate")
	}
	staged, ok := item.platform.(*unixReencryptStaged)
	if !ok {
		return fmt.Errorf("invalid Unix re-encryption staging state")
	}
	if staged.backupName == "" {
		return nil
	}
	dev, ino, mode, err := statAtNoFollow(c.parent, c.name)
	if err != nil {
		return fmt.Errorf("stat installed target: %w", err)
	}
	if mode&unix.S_IFMT != unix.S_IFREG || dev != staged.stagedDev || ino != staged.stagedIno {
		return fmt.Errorf("installed target changed during rollback")
	}
	if err := unix.Unlinkat(int(c.parent.Fd()), c.name, 0); err != nil {
		return fmt.Errorf("remove installed target: %w", err)
	}
	if err := unix.Renameat(int(c.parent.Fd()), staged.backupName, int(c.parent.Fd()), c.name); err != nil {
		return fmt.Errorf("restore original target: %w", err)
	}
	staged.backupName = ""
	item.committed = false
	return nil
}

func recordReencryptCleanupError(firstErr *error, err error) {
	if errors.Is(err, unix.ENOENT) || *firstErr != nil {
		return
	}
	*firstErr = err
}

func cleanupReencryptFile(item *reencryptStaged) error {
	c, ok := item.candidate.platform.(*unixReencryptCandidate)
	if !ok {
		return fmt.Errorf("invalid Unix re-encryption candidate")
	}
	staged, ok := item.platform.(*unixReencryptStaged)
	if !ok {
		return fmt.Errorf("invalid Unix re-encryption staging state")
	}
	var firstErr error
	if staged.tempName != "" {
		if err := unix.Unlinkat(int(c.parent.Fd()), staged.tempName, 0); err != nil {
			recordReencryptCleanupError(&firstErr, err)
		}
		staged.tempName = ""
	}
	if staged.backupName != "" {
		if err := unix.Unlinkat(int(c.parent.Fd()), staged.backupName, 0); err != nil {
			recordReencryptCleanupError(&firstErr, err)
		}
		staged.backupName = ""
	}
	return firstErr
}

func closeReencryptCandidates(candidates []*reencryptCandidate) {
	for _, candidate := range candidates {
		if c, ok := candidate.platform.(*unixReencryptCandidate); ok && c.parent != nil {
			_ = c.parent.Close()
			c.parent = nil
		}
	}
}
