package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

var searchIndexAdapterBuild struct {
	sync.Once
	path string
	err  error
}

func searchIndexAdapter(t testing.TB) string {
	t.Helper()
	searchIndexAdapterBuild.Do(func() {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			searchIndexAdapterBuild.err = fmt.Errorf("runtime.Caller failed")
			return
		}
		repo := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
		target := filepath.Join(repo, ".worktrees", "rust-integration", "target")
		if err := os.MkdirAll(target, 0o700); err != nil {
			searchIndexAdapterBuild.err = err
			return
		}
		cmd := exec.Command("cargo", "build", "-p", "symvault-store", "--example", "search-index-adapter")
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "CARGO_TARGET_DIR="+target)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if output, err := cmd.Output(); err != nil {
			searchIndexAdapterBuild.err = fmt.Errorf("cargo build: %w: %s\n%s", err, stderr.Bytes(), output)
			return
		}
		searchIndexAdapterBuild.path = filepath.Join(target, "debug", "examples", "search-index-adapter")
	})
	if searchIndexAdapterBuild.err != nil {
		t.Fatalf("build search-index adapter: %v", searchIndexAdapterBuild.err)
	}
	return searchIndexAdapterBuild.path
}

func runSearchIndexAdapter(t testing.TB, binary, root, identity, action string, extra ...string) map[string]any {
	t.Helper()
	args := []string{"--action", action, "--root", root, "--identity", identity}
	args = append(args, extra...)
	cmd := exec.Command(binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("adapter %s: %v\nstderr=%s", action, err, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("adapter %s output %q: %v", action, output, err)
	}
	return result
}

func TestEncryptedIndexGoRustLiveAcceptance(t *testing.T) {
	searchIndexStore.invalidateAll()
	t.Cleanup(searchIndexStore.invalidateAll)
	adapter := searchIndexAdapter(t)

	// Case go_index_rust_load_search: the Go production builder writes the
	// current salted wire format; Rust must load it, not fall back to entries.
	goRoot := t.TempDir()
	goIdentity := testutil.TempIdentity(t)
	cfg := vaultconfig.Default()
	cfg.VaultDir = goRoot
	if err := Init(goRoot, goIdentity, cfg); err != nil {
		t.Fatalf("Init Go vault: %v", err)
	}
	mustWriteEntry(t, goRoot, goIdentity, "go-doc", map[string]interface{}{
		"title": "Go interoperability marker",
		"token": "go-rust-accepted",
	})
	goIndex := &EncryptedIndex{}
	if err := goIndex.Build(goRoot, goIdentity); err != nil {
		t.Fatalf("Go Build: %v", err)
	}
	loaded := runSearchIndexAdapter(t, adapter, goRoot, goIdentity.String(), "load-search", "--query", "go-rust-accepted")
	if loaded["case_id"] != "rust_load_go_index_search" {
		t.Fatalf("executed case_id = %v", loaded["case_id"])
	}
	matches, ok := loaded["matches"].([]any)
	if !ok || len(matches) != 1 || matches[0] != "go-doc" {
		t.Fatalf("Rust matches = %v, want [go-doc]", loaded["matches"])
	}

	// Case rust_index_go_load_search: Rust writes a real current index and Go
	// explicitly exercises its unexported loadFromDisk path.
	rustRoot := t.TempDir()
	trustIdentity := testutil.TempIdentity(t)
	cfg = vaultconfig.Default()
	cfg.VaultDir = rustRoot
	if err := Init(rustRoot, trustIdentity, cfg); err != nil {
		t.Fatalf("Init Rust vault: %v", err)
	}
	entryFile := filepath.Join(t.TempDir(), "entry.json")
	entry := map[string]any{"path": "rust-doc", "data": map[string]any{
		"title": "Rust interoperability marker", "token": "rust-go-accepted",
	}, "meta": map[string]any{}, "secret_meta": map[string]any{}}
	entryBytes, _ := json.Marshal(entry)
	if err := os.WriteFile(entryFile, entryBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	built := runSearchIndexAdapter(t, adapter, rustRoot, trustIdentity.String(), "write-build", "--path", "rust-doc", "--entry-file", entryFile)
	if built["case_id"] != "rust_build_index_for_go_load" {
		t.Fatalf("executed case_id = %v", built["case_id"])
	}
	goLoaded := &EncryptedIndex{}
	if err := goLoaded.loadFromDisk(rustRoot, trustIdentity); err != nil {
		t.Fatalf("Go loadFromDisk Rust index: %v", err)
	}
	goMatches, err := goLoaded.MatchEntries(rustRoot, trustIdentity, []string{"rust-doc"}, "rust-go-accepted")
	if err != nil {
		t.Fatalf("Go search Rust index: %v", err)
	}
	if !reflect.DeepEqual(goMatches, map[string]struct{}{"rust-doc": {}}) {
		t.Fatalf("Go matches = %v, want rust-doc", goMatches)
	}

	// Case wrong_identity_rejected: a valid index must not be accepted by a
	// different identity, even though the vault layout is otherwise valid.
	wrong := testutil.TempIdentity(t)
	wrongLoaded := &EncryptedIndex{}
	if err := wrongLoaded.loadFromDisk(rustRoot, wrong); err == nil {
		t.Fatal("wrong identity unexpectedly loaded encrypted index")
	}

	// Case tampered_ciphertext_rejected: authenticated corruption must fail the
	// explicit loader rather than becoming an empty successful search.
	raw, err := os.ReadFile(indexFilePath(goRoot))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(indexFilePath(goRoot), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := &EncryptedIndex{}
	if err := tampered.loadFromDisk(goRoot, goIdentity); err == nil {
		t.Fatal("tampered ciphertext unexpectedly loaded")
	}
}
