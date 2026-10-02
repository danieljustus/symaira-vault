package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func validateArchiveName(name string) error {
	if name == "" || strings.IndexByte(name, 0) >= 0 || strings.HasPrefix(name, "/") || filepath.IsAbs(name) || filepath.VolumeName(name) != "" || strings.ContainsRune(name, '\\') {
		return fmt.Errorf("unsafe oracle archive path %q", name)
	}
	if len(name) >= 2 && name[1] == ':' && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) {
		return fmt.Errorf("unsafe oracle archive path %q", name)
	}
	for _, component := range strings.Split(name, "/") {
		if component == ".." {
			return fmt.Errorf("unsafe oracle archive path %q", name)
		}
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" {
		return fmt.Errorf("unsafe oracle archive path %q", name)
	}
	return nil
}

func extractArchive(source io.Reader, destination string, maxMemberBytes int64, preserveArchiveMode bool) error {
	root, err := os.OpenRoot(destination)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	reader := tar.NewReader(source)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if header.Typeflag == tar.TypeXGlobalHeader || header.Typeflag == tar.TypeXHeader {
			continue
		}

		name := header.Name
		if err = validateArchiveName(name); err != nil {
			return err
		}
		name = filepath.Clean(filepath.FromSlash(name))

		out := filepath.Join(destination, name)
		relative, err := filepath.Rel(destination, out)
		if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("oracle archive path %q escapes extraction root", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			err = root.MkdirAll(name, 0750)
		case tar.TypeReg:
			if header.Size < 0 || (maxMemberBytes > 0 && header.Size > maxMemberBytes) {
				return fmt.Errorf("oracle archive member %q exceeds %d bytes", name, maxMemberBytes)
			}
			parent := filepath.Dir(name)
			if parent != "." {
				err = root.MkdirAll(parent, 0750)
			}
			if err != nil {
				return err
			}
			mode := os.FileMode(0600)
			if preserveArchiveMode {
				if header.Mode < 0 || header.Mode > int64(^uint32(0)) {
					return fmt.Errorf("invalid archive mode %d", header.Mode)
				}
				mode = os.FileMode(uint32(header.Mode))
			}
			file, openErr := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if openErr != nil {
				return openErr
			}
			var dataReader io.Reader = reader
			if maxMemberBytes > 0 {
				dataReader = io.LimitReader(reader, maxMemberBytes+1)
			}
			written, copyErr := io.Copy(file, dataReader)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if maxMemberBytes > 0 && written > maxMemberBytes {
				return fmt.Errorf("oracle archive member %q exceeds %d bytes", name, maxMemberBytes)
			}
		default:
			return fmt.Errorf("unsupported oracle archive entry type %d for %q", header.Typeflag, header.Name)
		}
		if err != nil {
			return err
		}
	}
}
