//go:build !windows

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// secureCopyEntry copies using directory file descriptors. Every lookup is
// relative to an already-open directory and uses O_NOFOLLOW.
func secureCopyEntry(src, dst string) error {
	srcFile, err := openMigrationSource(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()
	var srcStat unix.Stat_t
	if statErr := unix.Fstat(int(srcFile.Fd()), &srcStat); statErr != nil {
		return statErr
	}
	dstParent, err := secureMkdirOpen(filepath.Dir(dst), 0o700)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dstParent) }()
	return copyMigrationNode(int(srcFile.Fd()), dstParent, filepath.Base(dst), uint32(srcStat.Mode)) //nolint:unconvert // unix.Stat_t.Mode is uint32 on Linux but uint16 on Darwin; the conversion is a no-op on one GOOS and required on the other
}

func secureMkdirOpen(path string, mode uint32) (int, error) {
	clean, err := migrationAbsolutePath(path)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			if openErr != unix.ENOENT {
				_ = unix.Close(fd)
				return -1, openErr
			}
			if openErr = unix.Mkdirat(fd, part, mode); openErr != nil && openErr != unix.EEXIST {
				_ = unix.Close(fd)
				return -1, openErr
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if openErr != nil {
				_ = unix.Close(fd)
				return -1, openErr
			}
		}
		_ = unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func copyMigrationNode(srcFD, dstParent int, name string, srcMode uint32) error {
	if srcMode&unix.S_IFMT == unix.S_IFDIR {
		if err := unix.Mkdirat(dstParent, name, 0o700); err != nil {
			return err
		}
		dstDir, err := unix.Openat(dstParent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(dstDir) }()
		dup, err := unix.Dup(srcFD)
		if err != nil {
			return err
		}
		stream := os.NewFile(uintptr(dup), "source directory")
		if stream == nil {
			_ = unix.Close(dup)
			return fmt.Errorf("invalid source directory")
		}
		entries, err := stream.Readdirnames(-1)
		_ = stream.Close()
		if err != nil {
			return err
		}
		for _, child := range entries {
			var st unix.Stat_t
			if err := unix.Fstatat(srcFD, child, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			childFD, err := unix.Openat(srcFD, child, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			copyErr := copyMigrationNode(childFD, dstDir, child, uint32(st.Mode)) //nolint:unconvert // see the conversion note in secureCopyEntry above
			_ = unix.Close(childFD)
			if copyErr != nil {
				return copyErr
			}
		}
		return nil
	}
	if srcMode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("refusing non-regular source")
	}
	dup, err := unix.Dup(srcFD)
	if err != nil {
		return err
	}
	src := os.NewFile(uintptr(dup), "source")
	if src == nil {
		_ = unix.Close(dup)
		return fmt.Errorf("invalid source file")
	}
	data, err := io.ReadAll(io.LimitReader(src, maxMigrationBytes+1))
	_ = src.Close()
	if err != nil {
		return err
	}
	if int64(len(data)) > maxMigrationBytes {
		return fmt.Errorf("source exceeds migration size limit")
	}
	fd, err := unix.Openat(dstParent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	outFile := os.NewFile(uintptr(fd), name)
	if outFile == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("invalid destination")
	}
	written, writeErr := outFile.Write(data)
	closeErr := outFile.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func secureReadFile(path string) ([]byte, error) {
	file, err := openMigrationSource(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return io.ReadAll(io.LimitReader(file, maxMigrationBytes+1))
}

func secureRemovePath(path string) error {
	parent, err := secureOpenExisting(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	return removeAt(parent, filepath.Base(path))
}

func secureOpenExisting(path string) (int, error) {
	clean, err := migrationAbsolutePath(path)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, openErr
		}
		fd = next
	}
	return fd, nil
}

func removeAt(parent int, name string) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			return fmt.Errorf("invalid directory")
		}
		entries, readErr := file.Readdirnames(-1)
		if readErr == nil {
			for _, child := range entries {
				if childErr := removeAt(fd, child); childErr != nil {
					readErr = childErr
					break
				}
			}
		}
		_ = file.Close()
		if readErr != nil {
			return readErr
		}
		return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
	}
	if err == unix.ENOTDIR {
		return unix.Unlinkat(parent, name, 0)
	}
	if err == unix.ENOENT {
		return nil
	}
	return err
}

var migrationTempCounter uint64

func secureWriteJSONAtomic(path string, data []byte) error {
	parent, err := secureOpenExisting(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	base := filepath.Base(path)
	var tmp string
	var fd int
	for i := 0; i < 10; i++ {
		tmp = fmt.Sprintf(".migration-tmp-%d-%d", unix.Getpid(), atomic.AddUint64(&migrationTempCounter, 1))
		fd, err = unix.Openat(parent, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if !errors.Is(err, unix.EEXIST) {
			break
		}
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), tmp)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parent, tmp, 0)
		return fmt.Errorf("invalid temporary migration file")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(parent, tmp, 0)
		}
	}()
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = unix.Renameat(parent, tmp, parent, base); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func closeMigrationFD(fd int) error { return unix.Close(fd) }
