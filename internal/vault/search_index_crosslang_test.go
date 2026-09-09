package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

var searchIndexAdapterBuild struct {
	path string
	err  error
}

func searchIndexAdapter(t testing.TB) string {
	t.Helper()
	searchIndexAdapterBuildOnce.Do(func() {
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
		output, err := runSearchIndexCommand(repo, target, "cargo", "build", "-p", "symvault-store", "--example", "search-index-adapter")
		if err != nil {
			searchIndexAdapterBuild.err = fmt.Errorf("cargo build: %w: %s", err, output)
			return
		}
		searchIndexAdapterBuild.path = filepath.Join(target, "debug", "examples", "search-index-adapter")
	})
	if searchIndexAdapterBuild.err != nil {
		t.Fatalf("build search-index adapter: %v", searchIndexAdapterBuild.err)
	}
	return searchIndexAdapterBuild.path
}

var searchIndexAdapterBuildOnce = new(sync.Once)

func runSearchIndexAdapterExpectError(t testing.TB, binary, root, identity, action, caseID string, extra ...string) {
	t.Helper()
	output, err := runSearchIndexCommand(root, "", binary, append([]string{"--action", action, "--root", root, "--identity", identity, "--case-id", caseID}, extra...)...)
	if err == nil {
		t.Fatalf("adapter %s unexpectedly succeeded", caseID)
	}
	if strings.Contains(err.Error(), "deadline exceeded") || strings.Contains(err.Error(), "WaitDelay") {
		t.Fatalf("adapter %s was not a bounded loader rejection: %v", caseID, err)
	}
	if !strings.Contains(output, caseID+": search index missing or rejected") {
		t.Fatalf("adapter %s error = %q, want explicit rejection diagnostic", caseID, output)
	}
}

func runSearchIndexAdapter(t testing.TB, binary, root, identity, action string, extra ...string) map[string]any {
	t.Helper()
	result, err := runSearchIndexCommand(root, "", binary, append([]string{"--action", action, "--root", root, "--identity", identity}, extra...)...)
	if err != nil {
		t.Fatalf("adapter %s: %v\nstderr=%s", action, err, result)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("adapter %s output %q: %v", action, result, err)
	}
	return parsed
}

func publicKeyDerivedIndexCiphertext(t testing.TB, identity *age.X25519Identity, salt []byte) []byte {
	t.Helper()
	key := make([]byte, chacha20poly1305.KeySize)
	kdf := hkdf.New(sha256.New, []byte(identity.Recipient().String()), salt, []byte("symvault-search-index-v1"))
	if _, err := io.ReadFull(kdf, key); err != nil {
		t.Fatal(err)
	}
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"v":{"go-doc":["go-rust-accepted"]},"c":1,"s":"` + base64.StdEncoding.EncodeToString(salt) + `"}`)
	encrypted := cipher.Seal(nil, nonce, plaintext, nil)
	return append(append(append([]byte{1}, salt...), nonce...), encrypted...)
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

	// Keep both the Go and Rust loader negatives. Recreate the fixture after
	// each rejection because both implementations fail closed by deleting it.
	wrong := testutil.TempIdentity(t)
	raw, err := os.ReadFile(indexFilePath(goRoot))
	if err != nil {
		t.Fatal(err)
	}
	if err := (&EncryptedIndex{}).loadFromDisk(goRoot, wrong); err == nil {
		t.Fatal("go_wrong_identity_rejected: Go loader unexpectedly accepted")
	}
	if err := os.WriteFile(indexFilePath(goRoot), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	runSearchIndexAdapterExpectError(t, adapter, goRoot, wrong.String(), "load-search", "rust_wrong_identity_rejected", "--query", "go-rust-accepted")
	if err := os.WriteFile(indexFilePath(goRoot), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	tamperedRaw := append([]byte(nil), raw...)
	tamperedRaw[len(tamperedRaw)-1] ^= 1
	if err := os.WriteFile(indexFilePath(goRoot), tamperedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&EncryptedIndex{}).loadFromDisk(goRoot, goIdentity); err == nil {
		t.Fatal("go_tampered_ciphertext_rejected: Go loader unexpectedly accepted")
	}
	if err := os.WriteFile(indexFilePath(goRoot), tamperedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	runSearchIndexAdapterExpectError(t, adapter, goRoot, goIdentity.String(), "load-search", "rust_tampered_ciphertext_rejected", "--query", "go-rust-accepted")

	// Case public_key_derived_ciphertext_rejected: a malicious fixture made
	// with the recipient public bytes (rather than the private identity) must
	// fail both loaders even when its decrypted JSON shape is otherwise valid.
	publicSalt := []byte("public-derived-16")
	publicDerived := publicKeyDerivedIndexCiphertext(t, goIdentity, publicSalt)
	if err := os.WriteFile(indexFilePath(goRoot), publicDerived, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&EncryptedIndex{}).loadFromDisk(goRoot, goIdentity); err == nil {
		t.Fatal("go_public_key_derived_ciphertext_rejected: Go loader unexpectedly accepted")
	}
	if err := os.WriteFile(indexFilePath(goRoot), publicDerived, 0o600); err != nil {
		t.Fatal(err)
	}
	runSearchIndexAdapterExpectError(t, adapter, goRoot, goIdentity.String(), "load-search", "rust_public_key_derived_ciphertext_rejected", "--query", "go-rust-accepted")
}
