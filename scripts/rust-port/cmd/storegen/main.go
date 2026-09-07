// Command storegen freezes the read-only vault layout and entry contract.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"filippo.io/age"
	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	oracleCommit  = "caadd5e"
	oracleRelease = "v0.22.1"
	identityText  = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL"
)

var sourceFiles = []string{
	"internal/config/config.go", "internal/config/config_load.go", "internal/config/config_save.go",
	"internal/config/paths.go", "internal/config/schema.go", "internal/fsutil/reexport.go",
	"internal/vault/entry.go", "internal/vault/entry_readwrite.go", "internal/vault/entry_validate.go",
	"internal/vault/recipients.go", "internal/vault/types.go", "internal/vault/vault.go",
}
var generatorFiles = []string{"scripts/rust-port/cmd/storegen/main.go", "scripts/rust-port/cmd/storegen/main_test.go"}
var requiredVaults = []string{"fresh", "legacy"}
var requiredEntries = []string{"minimal", "full", "nested/large"}

type fixture struct {
	SchemaVersion int             `json:"schema_version"`
	Oracle        oracle          `json:"oracle"`
	Vaults        []vaultFixture  `json:"vaults"`
	Malformed     []malformedCase `json:"malformed_cases"`
}
type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}
type vaultFixture struct {
	Name        string             `json:"name"`
	Layout      string             `json:"layout"`
	Files       []fileFixture      `json:"files"`
	Directories []directoryFixture `json:"directories"`
	Entries     []entryFixture     `json:"entries"`
	Presence    presence           `json:"presence"`
}
type presence struct {
	Config     bool `json:"config"`
	Identity   bool `json:"identity"`
	Recipients bool `json:"recipients"`
}
type directoryFixture struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}
type fileFixture struct {
	Path    string `json:"path"`
	Mode    uint32 `json:"mode"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}
type entryFixture struct {
	Name        string          `json:"name"`
	Path        string          `json:"path"`
	StoragePath string          `json:"storage_path"`
	Expected    json.RawMessage `json:"expected"`
}
type malformedCase struct {
	Name  string `json:"name"`
	Input string `json:"input"`
}

type entrySpec struct {
	name, path string
	data       map[string]any
	secretMeta map[string]any
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate storegen")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}
func b64(value []byte) string                                  { return base64.StdEncoding.EncodeToString(value) }
func digestFiles(root string, names []string) (string, error)  { return digest(root, names, false) }
func pinnedDigest(root string, names []string) (string, error) { return digest(root, names, true) }
func digest(root string, names []string, pinned bool) (string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, name := range sorted {
		var data []byte
		var err error
		if pinned {
			data, err = exec.Command("git", "-C", root, "show", oracleCommit+":"+name).Output()
		} else {
			data, err = os.ReadFile(filepath.Join(root, name))
		}
		if err != nil {
			return "", fmt.Errorf("digest %s: %w", name, err)
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func authoritative(root string) (oracle, error) {
	sourceDigest, err := pinnedDigest(root, sourceFiles)
	if err != nil {
		return oracle{}, err
	}
	generatorDigest, err := digestFiles(root, generatorFiles)
	if err != nil {
		return oracle{}, err
	}
	return oracle{Commit: oracleCommit, Release: oracleRelease, SourceFiles: append([]string(nil), sourceFiles...), SourceDigest: sourceDigest, GeneratorFiles: append([]string(nil), generatorFiles...), GeneratorDigest: generatorDigest}, nil
}
func fixedIdentity() (*age.X25519Identity, error) { return age.ParseX25519Identity(identityText) }

func specs() []entrySpec {
	return []entrySpec{
		{name: "minimal", path: "minimal", data: map[string]any{"username": "fixture-user", "password": "fake-password-v1"}},
		{name: "full", path: "full", data: map[string]any{
			"username": "fixture-full-user", "url": "https://example.invalid/fixture", "api_key": "AKIAAAAAAAAAAAAAAAAA",
			"nested": map[string]any{"region": "test-region", "flags": []any{true, false, 7}},
			"items":  []any{"one", map[string]any{"two": "three"}},
		}, secretMeta: map[string]any{"type": "custom", "usage_hint": "fixture only", "auto_rotate": true}},
		{name: "nested/large", path: "nested/large", data: map[string]any{
			"payload": strings.Repeat("large-fixture-value-", 5000), "count": 5000, "enabled": true,
			"nested": map[string]any{"leaf": "deep-fixture-value"},
		}},
	}
}

func buildVault(name string, legacy bool) (vaultFixture, error) {
	dir, err := os.MkdirTemp("", "symvault-storegen-")
	if err != nil {
		return vaultFixture{}, err
	}
	defer os.RemoveAll(dir)
	identity, err := fixedIdentity()
	if err != nil {
		return vaultFixture{}, err
	}
	legacyMode := legacy
	cfg := vaultconfig.Default()
	cfg.VaultDir = dir
	cfg.Vault = &vaultconfig.VaultConfig{FormatVersion: 2, LegacyMode: &legacyMode, SearchIndex: false}
	if err := vaultpkg.Init(dir, identity, cfg); err != nil {
		return vaultFixture{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "recipients.txt"), []byte(identity.Recipient().String()+"\n"), 0o600); err != nil {
		return vaultFixture{}, err
	}
	entries := make([]entryFixture, 0, len(specs()))
	for _, spec := range specs() {
		entry := &vaultpkg.Entry{Data: spec.data}
		if spec.secretMeta != nil {
			raw, _ := json.Marshal(spec.secretMeta)
			_ = json.Unmarshal(raw, &entry.SecretMetadata)
		}
		if err := vaultpkg.WriteEntry(dir, spec.path, entry, identity); err != nil {
			return vaultFixture{}, fmt.Errorf("write %s: %w", spec.path, err)
		}
		stored := filepath.Join(dir, "entries", filepath.FromSlash(spec.path)+".age")
		logical := spec.path
		if legacy {
			target := filepath.Join(dir, filepath.FromSlash(spec.path)+".age")
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return vaultFixture{}, err
			}
			if err := os.Rename(stored, target); err != nil {
				return vaultFixture{}, err
			}
			stored = target
		}
		loaded, err := vaultpkg.ReadEntry(dir, logical, identity)
		if err != nil {
			return vaultFixture{}, err
		}
		expected, err := json.Marshal(loaded)
		if err != nil {
			return vaultFixture{}, err
		}
		rel, _ := filepath.Rel(dir, stored)
		entries = append(entries, entryFixture{Name: spec.name, Path: logical, StoragePath: filepath.ToSlash(rel), Expected: expected})
	}
	if legacy {
		if err := os.RemoveAll(filepath.Join(dir, "entries")); err != nil {
			return vaultFixture{}, err
		}
	}
	// Keep the fixture independent of the generator's temporary path.
	cfg.VaultDir = ""
	if err := cfg.SaveTo(filepath.Join(dir, "config.yaml")); err != nil {
		return vaultFixture{}, err
	}
	files, dirs, err := snapshot(dir)
	if err != nil {
		return vaultFixture{}, err
	}
	return vaultFixture{Name: name, Layout: map[bool]string{true: "legacy", false: "fresh"}[legacy], Files: files, Directories: dirs, Entries: entries, Presence: presence{Config: true, Identity: true, Recipients: true}}, nil
}

func snapshot(root string) ([]fileFixture, []directoryFixture, error) {
	var files []fileFixture
	var dirs []directoryFixture
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.Clean(rel)
		mode := uint32(info.Mode().Perm())
		if info.IsDir() {
			dirs = append(dirs, directoryFixture{Path: filepath.ToSlash(rel), Mode: mode})
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("fixture contains non-regular file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files = append(files, fileFixture{Path: filepath.ToSlash(rel), Mode: mode, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Content: b64(data)})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Path < dirs[j].Path })
	return files, dirs, err
}

func validate(value fixture, expected oracle) error {
	if value.SchemaVersion != 1 || value.Oracle.Commit != expected.Commit || value.Oracle.Release != expected.Release || value.Oracle.SourceDigest != expected.SourceDigest || value.Oracle.GeneratorDigest != expected.GeneratorDigest {
		return errors.New("store fixture provenance changed")
	}
	if len(value.Vaults) != 2 {
		return fmt.Errorf("vault cardinality %d, want 2", len(value.Vaults))
	}
	for i, vault := range value.Vaults {
		if vault.Name != requiredVaults[i] {
			return fmt.Errorf("vault %d name %q", i, vault.Name)
		}
		if len(vault.Entries) != len(requiredEntries) {
			return fmt.Errorf("%s entry cardinality %d", vault.Name, len(vault.Entries))
		}
		for j, entry := range vault.Entries {
			if entry.Name != requiredEntries[j] {
				return fmt.Errorf("%s entry %d name %q", vault.Name, j, entry.Name)
			}
			if entry.Path == "" || entry.StoragePath == "" || len(entry.Expected) == 0 {
				return fmt.Errorf("incomplete %s entry %s", vault.Name, entry.Name)
			}
		}
		if len(vault.Files) != 8 {
			return fmt.Errorf("%s file cardinality %d, want 8", vault.Name, len(vault.Files))
		}
	}
	if len(value.Malformed) != 3 || value.Malformed[0].Name != "empty" || value.Malformed[1].Name != "not_age" || value.Malformed[2].Name != "bad_stanza" {
		return errors.New("malformed case cardinality or order changed")
	}
	return nil
}

func verify(root, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var value fixture
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	expected, err := authoritative(root)
	if err != nil {
		return err
	}
	return validate(value, expected)
}

func build(root string) (fixture, error) {
	meta, err := authoritative(root)
	if err != nil {
		return fixture{}, err
	}
	fresh, err := buildVault("fresh", false)
	if err != nil {
		return fixture{}, err
	}
	legacy, err := buildVault("legacy", true)
	if err != nil {
		return fixture{}, err
	}
	return fixture{SchemaVersion: 1, Oracle: meta, Vaults: []vaultFixture{fresh, legacy}, Malformed: []malformedCase{{Name: "empty", Input: ""}, {Name: "not_age", Input: "not an age envelope\n"}, {Name: "bad_stanza", Input: "age-encryption.org/v1\n-> bad\n--- header end\n"}}}, nil
}

func main() {
	output := flag.String("output", "testdata/port/store/store.json", "fixture path")
	check := flag.Bool("check", false, "verify fixture provenance and cardinalities")
	flag.Parse()
	root := rootDir()
	if *check {
		if err := verify(root, *output); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL store fixture:", err)
			os.Exit(1)
		}
		fmt.Println("PASS store fixture (2 vaults, 6 entries, 3 malformed)")
		return
	}
	value, err := build(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL generate store fixture:", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		panic(err)
	}
	if err := os.WriteFile(*output, data, 0o600); err != nil {
		panic(err)
	}
	fmt.Println("WROTE", *output)
}
