package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/config"
)

// ExternalGitDirPath returns the path where the git repository for vaultDir
// should live when the vault is replicated by a filesystem sync engine (e.g.
// iCloud Drive). It is deliberately outside the synced folder so the .git
// history is never replicated by the sync engine.
//
// The location is derived deterministically from the vault path and rooted under
// the XDG data home (a local-only directory), which guarantees it sits outside
// any iCloud Drive container.
func ExternalGitDirPath(vaultDir string) string {
	if dir := config.XDGDataHome(); dir != "" {
		key := strings.ReplaceAll(filepath.Clean(vaultDir), string(filepath.Separator), "_")
		// Windows drive letters (and any other colon in the path) are not
		// valid in directory names; strip them so the derived key is usable
		// as a directory component on every platform.
		key = strings.ReplaceAll(key, ":", "_")
		key = strings.TrimPrefix(key, "_")
		return filepath.Join(dir, "symaira-vault-git", key+".git")
	}
	// Fallback when XDG data home is unavailable: a hidden sibling directory
	// next to the vault. This is still outside the vault's synced contents.
	base := filepath.Base(vaultDir)
	return filepath.Join(filepath.Dir(vaultDir), "."+base+".syncgit")
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// EnsureGitOutside relocates the git repository for vaultDir out of the synced
// folder when the vault uses filesystem sync. If the repository already lives
// outside (no .git directory remains inside the vault), it is a no-op. The
// in-tree .git directory is moved (renamed) so no git objects remain in the
// synced folder; the repository is thereafter opened via the external path with
// an explicit worktree (see openRepo), so no .git file is needed inside the
// vault either.
func EnsureGitOutside(vaultDir string) error {
	if vaultDir == "" {
		return nil
	}
	gitInTree := filepath.Join(vaultDir, ".git")
	info, err := os.Lstat(gitInTree)
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing to relocate: the repo is already external or absent.
			return nil
		}
		return err
	}
	if !info.IsDir() {
		// A .git file (pointer) or other entry: relocation only handles a real
		// .git directory, so leave it untouched.
		return nil
	}

	ext := ExternalGitDirPath(vaultDir)
	if dirExists(ext) {
		// External already exists: drop the in-tree copy to avoid clobbering
		// the existing history.
		if err := os.RemoveAll(gitInTree); err != nil {
			return fmt.Errorf("remove in-tree .git: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(ext), 0o700); err != nil {
		return fmt.Errorf("create external git dir parent: %w", err)
	}
	if err := os.Rename(gitInTree, ext); err != nil {
		return fmt.Errorf("relocate .git outside synced folder: %w", err)
	}
	return nil
}

// IsGitExternal reports whether vaultDir's git repository is held outside the
// synced folder (i.e. a .git directory is not present in-tree but the external
// git directory exists).
func IsGitExternal(vaultDir string) bool {
	if dirExists(filepath.Join(vaultDir, ".git")) {
		return false
	}
	return dirExists(ExternalGitDirPath(vaultDir))
}
