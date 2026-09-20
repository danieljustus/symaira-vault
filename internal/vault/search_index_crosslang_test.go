package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

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

// crosslangBuildTimeout bounds a cold Cargo build of the workspace example
// adapters. Hosted runners compile the whole dependency graph without a cache,
// which exceeded the two-minute adapter timeout and failed the macOS test job;
// the bound is large enough not to depend on a warm cache and still catches a
// hang well inside the package test timeout.
const crosslangBuildTimeout = 15 * time.Minute

func cargoTargetDir(repo string) string {
	target := os.Getenv("CARGO_TARGET_DIR")
	if target == "" {
		return filepath.Join(repo, "target")
	}
	if !filepath.IsAbs(target) {
		// Cargo resolves a relative CARGO_TARGET_DIR from its working directory
		// (repo below); make the adapter path absolute before invoking it from
		// the Go package test process.
		return filepath.Join(repo, target)
	}
	return target
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
		target := cargoTargetDir(repo)
		if err := os.MkdirAll(target, 0o700); err != nil {
			searchIndexAdapterBuild.err = err
			return
		}
		// A cold Cargo build is intentionally allowed more time than the adapter
		// operations themselves. The latter use runSearchIndexCommand's bounded
		// two-minute timeout; applying it to dependency compilation makes the
		// differential test depend on a warm cache rather than adapter behavior.
		output, err := runSearchIndexCommandWithTimeout(crosslangBuildTimeout, repo, target, "cargo", "build", "--manifest-path", filepath.Join(repo, "Cargo.toml"), "--locked", "-p", "symvault-store", "--example", "search-index-adapter")
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

func TestCargoTargetDirResolution(t *testing.T) {
	repo := filepath.Join(string(filepath.Separator)+"tmp", "vault repo")
	for _, tc := range []struct {
		name, env, want string
	}{
		{name: "unset", want: filepath.Join(repo, "target")},
		{name: "relative", env: filepath.Join("external", "target dir"), want: filepath.Join(repo, "external", "target dir")},
		{name: "absolute with spaces", env: filepath.Join(string(filepath.Separator)+"tmp", "external target dir"), want: filepath.Join(string(filepath.Separator)+"tmp", "external target dir")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CARGO_TARGET_DIR", tc.env)
			if got := cargoTargetDir(repo); got != tc.want {
				t.Fatalf("cargoTargetDir(%q) = %q, want %q", tc.env, got, tc.want)
			}
		})
	}
}

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

func TestEncryptedIndexLoadInvalidateGoRust(t *testing.T) {
	adapter := searchIndexAdapter(t)
	root := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := vaultconfig.Default()
	cfg.VaultDir = root
	if err := Init(root, identity, cfg); err != nil {
		t.Fatal(err)
	}
	mustWriteEntry(t, root, identity, "concurrent-doc", map[string]any{
		"value": "Concurrent marker",
	})
	goIndex := searchIndexForVault(root)
	if err := goIndex.Build(root, identity); err != nil {
		t.Fatal(err)
	}
	sameIndex := searchIndexForVault(root)
	if goIndex != sameIndex {
		t.Fatal("Go index store returned separate instances for one vault")
	}
	rawBefore, err := os.ReadFile(filepath.Join(root, ".search-index"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rawBefore) == 0 || rawBefore[0] != indexFormatVersion {
		t.Fatalf("unexpected search-index format byte: %x", rawBefore)
	}
	ciphertextNonempty := len(rawBefore) > 1+indexSaltLen
	if !ciphertextNonempty {
		t.Fatalf("search-index ciphertext is empty: %x", rawBefore)
	}
	plaintextAbsent := !bytes.Contains(rawBefore, []byte("Concurrent marker"))

	// Force the first load to populate memory from the persisted bytes. This
	// makes the load-before-invalidate handoff observable instead of treating
	// the just-built in-memory index as evidence of a successful load.
	goIndex.ClearMemory()
	if goIndex.IsBuilt() {
		t.Fatal("Go ClearMemory retained the just-built index")
	}
	t.Cleanup(goIndex.Invalidate)

	// Go loadFromDisk reads before taking idx.mu for commit. Its oracle
	// contract here is sequential; Rust's stronger serialization is tested at
	// the read/commit boundary in the private Rust regression test.
	if err := sameIndex.loadFromDisk(root, identity); err != nil {
		t.Fatal(err)
	}
	if !sameIndex.IsBuilt() {
		t.Fatal("load did not commit")
	}
	goIndex.Invalidate()

	// Observe the production invalidation before test cleanup.
	if goIndex.IsBuilt() {
		t.Fatal("Go index remained loaded after invalidation")
	}
	if _, err := os.Stat(filepath.Join(root, ".search-index")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Go index file remained after invalidation: %v", err)
	}

	want := map[string]any{
		"index_absent":        true,
		"index_unloaded":      true,
		"format_version":      float64(indexFormatVersion),
		"ciphertext_nonempty": ciphertextNonempty,
		"plaintext_absent":    plaintextAbsent,
	}
	got := runSearchIndexAdapter(t, adapter, root, identity.String(), "load-invalidate")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Rust observation = %v; Go oracle = %v", got, want)
	}
}
