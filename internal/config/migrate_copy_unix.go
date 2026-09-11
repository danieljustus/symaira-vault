//go:build !windows

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// secureCopyEntry copies using directory file descriptors. Every lookup is
// relative to an already-open directory and uses O_NOFOLLOW, so replacing a
// path component after validation cannot redirect the copy.
func secureCopyEntry(src, dst string) error {
	srcFile, err := openMigrationSource(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	var srcStat unix.Stat_t
	if err := unix.Fstat(int(srcFile.Fd()), &srcStat); err != nil {
		return err
	}
	dstParent, err := secureMkdirOpen(filepath.Dir(dst), 0o700)
	if err != nil {
		return err
	}
	defer unix.Close(dstParent)
	return copyMigrationNode(int(srcFile.Fd()), dstParent, filepath.Base(dst), srcStat.Mode)
}

func secureMkdirOpen(path string, mode uint32) (int, error) {
	clean, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return -1, err
	}
	// Resolve only macOS's system-owned /var alias. Never EvalSymlinks the
	// complete user path: doing that would turn a user-controlled symlink into
	// an apparently safe path and reintroduce the escape.
	if info, statErr := os.Lstat(string(filepath.Separator) + "var"); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		if resolved, resolveErr := filepath.EvalSymlinks(string(filepath.Separator) + "var"); resolveErr == nil && resolved == string(filepath.Separator)+"private/var" {
			clean = string(filepath.Separator) + "private" + clean
		}
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			if openErr != unix.ENOENT {
				unix.Close(fd)
				return -1, openErr
			}
			if openErr = unix.Mkdirat(fd, part, mode); openErr != nil && openErr != unix.EEXIST {
				unix.Close(fd)
				return -1, openErr
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if openErr != nil {
				unix.Close(fd)
				return -1, openErr
			}
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func copyMigrationNode(srcFD, dstParent int, name string, srcMode uint16) error {
	if srcMode&unix.S_IFMT == unix.S_IFDIR {
		if err := unix.Mkdirat(dstParent, name, 0o700); err != nil {
			return err
		}
		dstDir, err := unix.Openat(dstParent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer unix.Close(dstDir)
		dup, err := unix.Dup(srcFD)
		if err != nil {
			return err
		}
		stream := os.NewFile(uintptr(dup), "source directory")
		if stream == nil {
			unix.Close(dup)
			return fmt.Errorf("invalid source directory")
		}
		entries, err := stream.Readdirnames(-1)
		stream.Close()
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
			copyErr := copyMigrationNode(childFD, dstDir, child, st.Mode)
			unix.Close(childFD)
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
		unix.Close(dup)
		return fmt.Errorf("invalid source file")
	}
	data, err := io.ReadAll(io.LimitReader(src, maxMigrationBytes+1))
	src.Close()
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
		unix.Close(fd)
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
