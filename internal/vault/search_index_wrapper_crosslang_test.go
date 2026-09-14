//go:build unix

package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// Errors with platform/crypto-library-specific diagnostics are projected by
// classification. The stable stale-index contract is also compared verbatim.
// Every observation comes from the process store's real loader/search methods.
func TestSearchIndexWrapperNegativeGoRust(t *testing.T) {
	adapter := searchIndexAdapter(t)
	for _, name := range []string{"absent", "corrupt", "wrong-identity", "stale", "list-failure", "delete-failure"} {
		t.Run(name, func(t *testing.T) {
			identity := testutil.TempIdentity(t)
			wrong := testutil.TempIdentity(t)
			fixture := func() string {
				root := t.TempDir()
				t.Cleanup(func() {
					_ = os.Chmod(root, 0700)
					_ = os.Chmod(entriesDir(root), 0700)
				})
				cfg := vaultconfig.Default()
				cfg.VaultDir = root
				if err := Init(root, identity, cfg); err != nil {
					t.Fatal(err)
				}
				mustWriteEntry(t, root, identity, "doc", map[string]any{"value": "Synthetic Marker"})
				FlushManifestUpdates()
				if err := searchIndexForVault(root).Build(root, identity); err != nil {
					t.Fatal(err)
				}
				// Force List through the filesystem in both runtimes.
				if err := os.Remove(filepath.Join(root, manifestFileName)); err != nil {
					t.Fatal(err)
				}
				listCacheFor(root).Invalidate()
				return root
			}
			root := fixture()
			rustRoot := fixture()
			idx := searchIndexForVault(root)
			if err := idx.loadFromDisk(root, identity); err != nil {
				t.Fatal(err)
			}
			path := indexFilePath(root)
			entries := entriesDir(root)
			rootInfo, err := os.Stat(root)
			if err != nil {
				t.Fatal(err)
			}
			entriesInfo, err := os.Stat(entries)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() {
				_ = os.Chmod(root, rootInfo.Mode().Perm())
				_ = os.Chmod(entries, entriesInfo.Mode().Perm())
				idx.Invalidate()
			})
			switch name {
			case "absent":
				must(os.Remove(path))
			case "corrupt", "delete-failure":
				must(os.WriteFile(path, []byte("corrupt"), 0600))
			case "stale":
				raw, err := os.ReadFile(filepath.Join(entries, "doc.age"))
				must(err)
				must(os.WriteFile(filepath.Join(entries, "extra.age"), raw, 0600))
			}
			if name == "list-failure" {
				must(os.Chmod(entries, 0))
			}
			if name == "delete-failure" {
				must(os.Chmod(root, rootInfo.Mode().Perm()&^0222))
			}
			before, _ := os.ReadFile(path)
			loadIdentity := identity
			if name == "wrong-identity" {
				loadIdentity = wrong
			}
			loadErr := idx.loadFromDisk(root, loadIdentity)
			outcome, detail := "success", ""
			if loadErr != nil {
				switch {
				case errors.Is(loadErr, os.ErrPermission):
					outcome = "permission"
				case errors.Is(loadErr, vaultcrypto.ErrDecryptionFailed), loadErr.Error() == "ciphertext too short":
					outcome = "decryption"
				case loadErr.Error() == "stale index":
					outcome, detail = "stale", loadErr.Error()
				default:
					outcome, detail = "unexpected", loadErr.Error()
				}
			}
			expectedClass := map[string]string{"absent": "success", "corrupt": "decryption", "wrong-identity": "decryption", "stale": "stale", "list-failure": "permission", "delete-failure": "decryption"}[name]
			if outcome != expectedClass {
				t.Fatalf("fixture did not exercise %s: %v", name, loadErr)
			}
			observeSearch := func(query string) map[string]any {
				matches, err := idx.MatchEntries(root, identity, []string{"doc"}, query)
				if err != nil {
					return map[string]any{"outcome": "error", "error": err.Error()}
				}
				paths := make([]string, 0, len(matches))
				for path := range matches {
					paths = append(paths, path)
				}
				sort.Strings(paths)
				projected := make([]any, len(paths))
				for i, path := range paths {
					projected[i] = path
				}
				state := "empty"
				if len(paths) > 0 {
					state = "nonempty"
				}
				return map[string]any{"outcome": state, "matches": projected}
			}
			after, afterErr := os.ReadFile(path)
			want := map[string]any{
				"load_outcome": outcome, "load_detail": detail,
				"loaded": idx.IsBuilt(), "search": observeSearch("MARKER"), "empty_search": observeSearch("no-such-value"),
				"file_exists": afterErr == nil, "bytes_retained": before != nil && bytes.Equal(before, after),
			}
			idx.Invalidate()
			invalidated, invalidatedErr := os.ReadFile(path)
			want["invalidate_ok"] = true // Go's production Invalidate has no error return.
			want["invalidated_loaded"] = idx.IsBuilt()
			want["invalidated_file_exists"] = invalidatedErr == nil
			want["invalidated_bytes_retained"] = before != nil && bytes.Equal(before, invalidated)
			if want["loaded"] != true || want["invalidated_loaded"] != false {
				t.Fatalf("Go wrapper memory transition: %v", want)
			}
			if want["search"].(map[string]any)["outcome"] != "nonempty" || want["empty_search"].(map[string]any)["outcome"] != "empty" {
				t.Fatalf("Go retained search: %v", want)
			}
			retained := name == "delete-failure"
			if want["file_exists"] != retained || want["invalidated_file_exists"] != retained {
				t.Fatalf("Go disk transition: %v", want)
			}
			must(os.Chmod(entries, entriesInfo.Mode().Perm()))
			must(os.Chmod(root, rootInfo.Mode().Perm()))
			got := runSearchIndexAdapter(t, adapter, rustRoot, identity.String(), "wrapper-negative", "--case", name, "--wrong-identity", wrong.String())
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Rust observation = %v; Go oracle = %v", got, want)
			}
		})
	}
}
