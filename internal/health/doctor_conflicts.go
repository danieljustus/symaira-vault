package health

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/git"
)

// conflictFile is one `<name>.conflict-<device><ext>` copy found in the vault.
type conflictFile struct {
	// path is the absolute path of the conflict copy.
	path string
	// rel is the vault-relative path, used in messages.
	rel string
	// redundant reports whether the copy carries no information: the file it
	// shadows exists and holds byte-identical content, so there is nothing
	// left to compare or merge.
	redundant bool
}

// findConflictCopies walks vaultDir and returns every conflict copy it finds,
// classified by whether it still shadows a differing file. The .git directory
// is never inspected.
func findConflictCopies(vaultDir string) ([]conflictFile, error) {
	var found []conflictFile
	err := filepath.WalkDir(vaultDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		shadowed, _, ok := git.ParseConflictName(d.Name())
		if !ok {
			return nil
		}
		rel, relErr := filepath.Rel(vaultDir, path)
		if relErr != nil {
			rel = d.Name()
		}
		found = append(found, conflictFile{
			path:      path,
			rel:       rel,
			redundant: sameContent(path, filepath.Join(filepath.Dir(path), shadowed)),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool { return found[i].rel < found[j].rel })
	return found, nil
}

// sameContent reports whether both paths are readable regular files with
// byte-identical content.
func sameContent(a, b string) bool {
	dataA, err := os.ReadFile(a) //#nosec G304 -- path produced by walking the vault directory
	if err != nil {
		return false
	}
	dataB, err := os.ReadFile(b) //#nosec G304 -- sibling of the walked path inside the vault directory
	if err != nil {
		return false
	}
	return bytes.Equal(dataA, dataB)
}

// checkVaultOrphanedConflictFiles reports git-sync conflict copies that no
// longer shadow anything: their content is byte-identical to the file they
// were made from, so there is nothing to merge or recover. Older releases
// rewrote such a copy on every sync attempt, and the device-identity change
// (#806/#811) additionally left hostname-named copies next to device-id-named
// ones. `doctor --fix` removes only the redundant copies; a conflict copy that
// still differs from its file holds unmerged content and is reported for
// manual review instead.
func checkVaultOrphanedConflictFiles(vaultDir string, _ Options) Result {
	r := Result{ID: "vault.conflict_files", Name: "Orphaned git-sync conflict files"}

	found, err := findConflictCopies(vaultDir)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot inspect conflict files: " + err.Error()
		return r
	}

	var redundant, pending []string
	for _, c := range found {
		if c.redundant {
			redundant = append(redundant, c.rel)
		} else {
			pending = append(pending, c.rel)
		}
	}

	if len(redundant) == 0 && len(pending) == 0 {
		r.Status = StatusOK
		r.Message = "no git-sync conflict files"
		return r
	}

	var parts []string
	if len(redundant) > 0 {
		parts = append(parts, fmt.Sprintf("%d orphaned conflict file(s) identical to the file they shadow: %s",
			len(redundant), strings.Join(redundant, ", ")))
	}
	if len(pending) > 0 {
		parts = append(parts, fmt.Sprintf("%d conflict file(s) with unmerged content: %s",
			len(pending), strings.Join(pending, ", ")))
	}
	r.Status = StatusWarn
	r.Message = strings.Join(parts, "; ")

	switch {
	case len(redundant) > 0 && len(pending) > 0:
		r.Hint = "run `symvault doctor --fix` to remove the orphaned copies; compare the remaining ones by hand before deleting them"
	case len(redundant) > 0:
		r.Hint = "run `symvault doctor --fix` to remove the orphaned copies"
	default:
		r.Hint = "compare each conflict file with the file it shadows, then delete it by hand"
	}

	if len(redundant) == 0 {
		return r
	}

	r.Fixable = true
	r.Fix = func() error {
		if FixDryRun {
			return nil
		}
		// Re-scan: the vault may have changed since the check ran, and a copy
		// that is no longer redundant must not be deleted.
		current, err := findConflictCopies(vaultDir)
		if err != nil {
			return err
		}
		for _, c := range current {
			if !c.redundant {
				continue
			}
			if err := os.Remove(c.path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove %s: %w", c.rel, err)
			}
		}
		return nil
	}
	return r
}
