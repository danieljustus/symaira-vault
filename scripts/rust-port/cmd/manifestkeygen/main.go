// Command manifestkeygen freezes public manifest map-key behavior. All expected
// records come from UpdateManifestEntry, RemoveManifestEntry and LoadManifest.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/age"

	vault "github.com/danieljustus/symaira-vault/internal/vault"
)

const revision = "88a9ca41e668f381c6319ed26fe922d8cc22e980"
const generator = "scripts/rust-port/cmd/manifestkeygen/main.go"
const payload = "synthetic-manifest-value"

type record struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type snapshot struct {
	Error            string            `json:"error"`
	Exists           bool              `json:"exists"`
	Version          int               `json:"version"`
	Generation       int               `json:"generation"`
	Entries          map[string]record `json:"entries"`
	Mode             uint32            `json:"mode"`
	TimesValid       bool              `json:"times_valid"`
	CreatedPreserved bool              `json:"created_preserved"`
	Files            []string          `json:"files"`
}
type vector struct {
	Name         string          `json:"name"`
	Input        json.RawMessage `json:"input"`
	Pseudonymize bool            `json:"pseudonymize"`
	Steps        []snapshot      `json:"steps"`
}
type fixture struct {
	Revision        string   `json:"revision"`
	GoVersion       string   `json:"go_version"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
	Payload         string   `json:"payload"`
	Vectors         []vector `json:"vectors"`
}

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
}

// Bind the entire tracked internal production tree and module dependencies to
// the actual pinned revision, rather than trusting a caller-supplied label.
func sourceDigest(root string) (string, error) {
	cmd := exec.Command("git", "ls-tree", "-r", "--name-only", revision, "--", "internal", "go.mod", "go.sum")
	cmd.Dir = root
	names, err := cmd.Output()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	for _, name := range strings.Fields(string(names)) {
		if strings.HasSuffix(name, "_test.go") || (!strings.HasSuffix(name, ".go") && name != "go.mod" && name != "go.sum") {
			continue
		}
		cmd = exec.Command("git", "show", revision+":"+name)
		cmd.Dir = root
		pinned, err := cmd.Output()
		if err != nil {
			return "", err
		}
		current, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return "", err
		}
		// Git's Windows checkout may normalize LF blobs to CRLF. Compare
		// normalized bytes, but bind the digest to the revision's blob bytes.
		if !bytes.Equal(bytes.ReplaceAll(pinned, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(current, []byte("\r\n"), []byte("\n"))) {
			return "", fmt.Errorf("production source differs from %s: %s", revision, name)
		}
		h.Write([]byte(name + "\x00"))
		h.Write(pinned)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func capture(root string, id *age.X25519Identity, opErr error, created *string) (snapshot, error) {
	s := snapshot{Entries: map[string]record{}, Files: []string{}}
	if opErr != nil {
		s.Error = opErr.Error()
	}
	m, err := vault.LoadManifest(root, id)
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	if err == nil {
		s.Exists = true
		s.Version = m.Version
		s.Generation = m.Generation
		info, statErr := os.Stat(filepath.Join(root, "manifest.age"))
		if statErr != nil {
			return s, statErr
		}
		s.Mode = uint32(info.Mode().Perm())
		s.TimesValid = !m.Created.IsZero() && !m.Updated.IsZero() && !m.Created.After(m.Updated)
		nowCreated := m.Created.String()
		s.CreatedPreserved = *created == "" || *created == nowCreated
		*created = nowCreated
		for key, e := range m.Entries {
			s.Entries[key] = record{e.SHA256, e.Size}
			s.TimesValid = s.TimesValid && !e.MTime.IsZero() && !e.MTime.Before(m.Created) && !e.MTime.After(m.Updated)
		}
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		s.Files = append(s.Files, filepath.ToSlash(rel))
		return nil
	})
	return s, err
}

func build(root string) (fixture, error) {
	f := fixture{Revision: revision, GoVersion: runtime.Version(), Payload: payload}
	if f.GoVersion != "go1.26.6" {
		return f, fmt.Errorf("requires go1.26.6, got %s", f.GoVersion)
	}
	var err error
	f.SourceDigest, err = sourceDigest(root)
	if err != nil {
		return f, err
	}
	src, err := os.ReadFile(filepath.Join(root, generator))
	if err != nil {
		return f, err
	}
	digest := sha256.Sum256(src)
	f.GeneratorDigest = hex.EncodeToString(digest[:])
	cases := []struct{ name, input string }{
		{"omitted", `{}`}, {"empty", `{"path":""}`}, {"ordinary", `{"path":"nested.name/key.v1"}`},
		{"traversal", `{"path":"../outside"}`}, {"dot", `{"path":"."}`}, {"absolute", `{"path":"/outside"}`},
		{"spelling", `{"path":" spaced//key\\leaf "}`}, {"nul", `{"path":"nul\u0000key"}`},
	}
	for _, pseudo := range []bool{false, true} {
		for _, c := range cases {
			v := vector{Name: c.name, Input: json.RawMessage(c.input), Pseudonymize: pseudo}
			err = func() error {
				dir, mkErr := os.MkdirTemp("", "manifest-key-fixture-")
				if mkErr != nil {
					return mkErr
				}
				defer func() {
					if removeErr := os.RemoveAll(dir); removeErr != nil {
						panic(removeErr)
					}
				}()
				id, idErr := age.GenerateX25519Identity()
				if idErr != nil {
					return idErr
				}
				// These are fixture inputs, not expected output. Manifest APIs only require
				// the root; the same inert identity marker lets Rust open the isolated tree.
				for name, data := range map[string]string{"config.yaml": fmt.Sprintf("vault:\n  pseudonymize_paths: %t\n", pseudo), "identity.age": "inert fixture marker"} {
					if writeErr := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); writeErr != nil {
						return writeErr
					}
				}
				var input struct {
					Path string `json:"path"`
				}
				if unmarshalErr := json.Unmarshal(v.Input, &input); unmarshalErr != nil {
					return unmarshalErr
				}
				created := ""
				operations := []func() error{
					func() error { return vault.RemoveManifestEntry(dir, input.Path, id) },
					func() error { return vault.UpdateManifestEntry(dir, input.Path, []byte(payload), id) },
					func() error { return vault.RemoveManifestEntry(dir, "absent-map-key", id) },
					func() error { return vault.RemoveManifestEntry(dir, input.Path, id) },
				}
				for _, op := range operations {
					s, captureErr := capture(dir, id, op(), &created)
					if captureErr != nil {
						return captureErr
					}
					v.Steps = append(v.Steps, s)
				}
				return nil
			}()
			if err != nil {
				return f, err
			}
			f.Vectors = append(f.Vectors, v)
		}
	}
	return f, nil
}

func encoded(f fixture) ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	return append(b, '\n'), err
}
func check(data, expected []byte) error {
	if !bytes.Equal(data, expected) {
		return fmt.Errorf("manifest-key fixture differs from production oracle")
	}
	return nil
}
func run() error {
	output := flag.String("output", "testdata/port/store/manifest-keys.json", "fixture path")
	verify := flag.Bool("check", false, "regenerate and compare without writing")
	flag.Parse()
	f, err := build(repoRoot())
	if err != nil {
		return err
	}
	data, err := encoded(f)
	if err != nil {
		return err
	}
	if *verify {
		got, err := os.ReadFile(*output)
		if err != nil {
			return err
		}
		return check(got, data)
	}
	return os.WriteFile(*output, data, 0644)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
