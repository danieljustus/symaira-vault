package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ManifestEntry captures observable filesystem state without timestamps or owners.
type ManifestEntry struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
}

func buildManifest(root string) ([]ManifestEntry, error) {
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	entries := make([]ManifestEntry, 0)
	walkErr := fs.WalkDir(rootHandle.FS(), ".", func(path string, entry fs.DirEntry, entryErr error) error {
		if entryErr != nil {
			return entryErr
		}
		if path == "." {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		item := ManifestEntry{
			Path: path,
			Mode: uint32(info.Mode().Perm()),
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			item.Type = "symlink"
			item.LinkTarget, err = rootHandle.Readlink(path)
			if err != nil {
				return err
			}
			if filepath.IsAbs(item.LinkTarget) {
				targetRel, relErr := filepath.Rel(root, item.LinkTarget)
				if relErr == nil && targetRel != ".." && !strings.HasPrefix(targetRel, ".."+string(filepath.Separator)) {
					item.LinkTarget = filepath.ToSlash(filepath.Join("<SANDBOX>", targetRel))
				}
			}
		case info.IsDir():
			item.Type = "directory"
		case info.Mode().IsRegular():
			item.Type = "file"
			item.Size = info.Size()
			file, openErr := rootHandle.Open(path)
			if openErr != nil {
				return openErr
			}
			hasher := sha256.New()
			_, copyErr := io.Copy(hasher, file)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			item.SHA256 = hex.EncodeToString(hasher.Sum(nil))
		default:
			item.Type = fmt.Sprintf("mode:%s", info.Mode().Type())
		}
		entries = append(entries, item)
		return nil
	})
	closeErr := rootHandle.Close()
	if walkErr != nil {
		return nil, walkErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
