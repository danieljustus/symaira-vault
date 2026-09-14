// Command store004gen freezes the STORE-004 high-level manifest failure contract.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const identityText = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL"

const (
	oracleCommit      = "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
	oracleRelease     = "v0.22.1"
	requiredGoVersion = "go1.26.6"
	sourceTree        = "target/migration-run/store004gen/oracle-src"
)

var goExecutable = "go"
var oracleTimeout = 2 * time.Minute

var sourceFiles = []string{
	"internal/config/config.go",
	"internal/config/config_load.go",
	"internal/config/schema.go",
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
	"internal/vault/manifest.go",
}
var generatorFiles = []string{
	"scripts/rust-port/cmd/store004gen/main.go",
	"scripts/rust-port/cmd/store004gen/main_test.go",
	"scripts/rust-port/cmd/store004gen/process_group_unix.go",
	"scripts/rust-port/cmd/store004gen/process_group_windows.go",
	"scripts/rust-port/cmd/store004gen/process_group_windows_test.go",
}

const oracleProgram = `package main
import (
  "encoding/json"
  "fmt"
  "os"
  "path/filepath"
  "filippo.io/age"
  vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
  vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)
const identityText = "` + identityText + `"
type outcome struct { CaseID string ` + "`json:\"case_id\"`" + `; Pseudonymize bool ` + "`json:\"pseudonymize\"`" + `; HighLevel string ` + "`json:\"highlevel\"`" + `; EntryExists bool ` + "`json:\"entry_exists\"`" + `; ManifestKind string ` + "`json:\"manifest_kind\"`" + `; ManifestLoad string ` + "`json:\"manifest_load\"`" + ` }
func main() {
  legacy := false; _ = legacy
  pseudo := len(os.Args) > 1 && os.Args[1] == "--pseudonymize"
  root, err := os.MkdirTemp("", "symvault-store004-"); if err != nil { panic(err) }; defer os.RemoveAll(root)
  identity, err := age.ParseX25519Identity(identityText); if err != nil { panic(err) }
  cfg := vaultconfig.Default(); cfg.VaultDir = root; cfg.Vault = &vaultconfig.VaultConfig{FormatVersion: 2, LegacyMode: &legacy, SearchIndex: false, PseudonymizePaths: pseudo}; if err = vaultpkg.Init(root, identity, cfg); err != nil { panic(err) }
  if err = os.Mkdir(filepath.Join(root, "manifest.age"), 0700); err != nil { panic(err) }
  entry := &vaultpkg.Entry{Data: map[string]any{"value": "store004"}}
  err = vaultpkg.WriteEntry(root, "alpha", entry, identity)
  loadErr := "ok"; if _, e := vaultpkg.LoadManifest(root, identity); e != nil { loadErr = "error" }
  kind := "file"; if info, e := os.Stat(filepath.Join(root, "manifest.age")); e == nil && info.IsDir() { kind = "directory" }
  highlevel := "ok"; if err != nil { highlevel = "error" }; result := outcome{"WRITE-MANIFEST-FAILURE-001", pseudo, highlevel, err == nil && entryExists(root, "alpha", pseudo, identity), kind, loadErr}
  if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }; json.NewEncoder(os.Stdout).Encode([]outcome{result})
}
func entryExists(root, name string, pseudo bool, identity *age.X25519Identity) bool { if !pseudo { _, err := os.Stat(filepath.Join(root, "entries", name+".age")); return err == nil }; entries := filepath.Join(root, "entries"); matched := false; _ = filepath.Walk(entries, func(path string, info os.FileInfo, err error) error { if err == nil && info.Mode().IsRegular() && filepath.Ext(path) == ".age" { matched = true }; return nil }); _ = identity; return matched }
`

type outcome struct {
	CaseID       string `json:"case_id"`
	Pseudonymize bool   `json:"pseudonymize"`
	HighLevel    string `json:"highlevel"`
	EntryExists  bool   `json:"entry_exists"`
	ManifestKind string `json:"manifest_kind"`
	ManifestLoad string `json:"manifest_load"`
}
type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}
type fixture struct {
	SchemaVersion int       `json:"schema_version"`
	Oracle        oracle    `json:"oracle"`
	Cases         []outcome `json:"cases"`
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate store004gen")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}
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
	sourceDigest, err := digest(root, sourceFiles, true)
	if err != nil {
		return oracle{}, err
	}
	generatorDigest, err := digest(root, generatorFiles, false)
	if err != nil {
		return oracle{}, err
	}
	return oracle{oracleCommit, oracleRelease, append([]string(nil), sourceFiles...), sourceDigest, append([]string(nil), generatorFiles...), generatorDigest}, nil
}
func safeArchivePath(name string) (string, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 || filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return "", errors.New("archive path is empty or absolute")
	}
	if runtime.GOOS != "windows" && strings.ContainsRune(name, '\\') {
		return "", errors.New("archive path has unsupported separator")
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("unsafe archive path")
	}
	return clean, nil
}
func extract(root string) (string, error) {
	dir := filepath.Join(root, sourceTree)
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", err
	}
	archiveFile, err := os.CreateTemp("", "symvault-store004-archive-*.tar")
	if err != nil {
		return "", err
	}
	archivePath := archiveFile.Name()
	if err = archiveFile.Close(); err != nil {
		_ = os.Remove(archivePath) // best effort: the real error is returned
		return "", err
	}
	defer func(p string) { _ = os.Remove(p) }(archivePath)
	cmd := exec.Command("git", "-C", root, "archive", "--format=tar", "--output="+archivePath, oracleCommit)
	if err = cmd.Run(); err != nil {
		return "", fmt.Errorf("git archive: %w", err)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		return "", err
	}
	if info.Size() > 64<<20 {
		return "", errors.New("oracle archive exceeds 67108864 bytes")
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer func(c io.Closer) { _ = c.Close() }(f)
	tr := tar.NewReader(f)
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return "", e
		}
		name, e := safeArchivePath(h.Name)
		if e != nil {
			return "", e
		}
		out := filepath.Join(dir, name)
		rel, e := filepath.Rel(dir, out)
		if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", errors.New("archive path escapes extraction root")
		}
		switch h.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			// Metadata records are interpreted by archive/tar and have no tree path.
			continue
		case tar.TypeDir:
			if e = os.MkdirAll(out, 0750); e != nil {
				return "", e
			}
		case tar.TypeReg:
			if e = os.MkdirAll(filepath.Dir(out), 0750); e != nil {
				return "", e
			}
			file, e := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if e != nil {
				return "", e
			}
			n, copyErr := io.Copy(file, io.LimitReader(tr, (64<<20)+1))
			closeErr := file.Close()
			if copyErr != nil {
				return "", copyErr
			}
			if closeErr != nil {
				return "", closeErr
			}
			if n > 64<<20 {
				return "", errors.New("oracle archive member exceeds 67108864 bytes")
			}
		default:
			return "", fmt.Errorf("unsupported archive entry type %d for %q", h.Typeflag, h.Name)
		}
	}
	return dir, nil
}
func resolveGo() (string, error) {
	path, err := exec.LookPath(goExecutable)
	if err != nil {
		return "", fmt.Errorf("locate Go executable %q: %w", goExecutable, err)
	}
	cmd := exec.Command(path, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("check Go toolchain %q: %w", path, err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 3 || fields[0] != "go" || fields[1] != "version" || fields[2] != requiredGoVersion {
		return "", fmt.Errorf("go toolchain %q is %q; require %s", path, strings.TrimSpace(string(output)), requiredGoVersion)
	}
	return path, nil
}

func isolatedEnvironment(goPath, home, tmp string) []string {
	allowed := []string{"PATH", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOVCS", "GOMODCACHE"}
	env := make([]string, 0, len(allowed)+3)
	for _, key := range allowed {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	// Windows derives the default GOPATH from USERPROFILE, not HOME, and TMP
	// and TEMP rather than TMPDIR. Without them the isolated child has neither
	// a module cache nor a way to derive one: "go: module cache not found:
	// neither GOMODCACHE nor GOPATH is set". Point them at the same isolated
	// directories, so isolation is preserved rather than weakened.
	env = append(env, "GOTOOLCHAIN=local", "HOME="+home, "USERPROFILE="+home,
		"TMPDIR="+tmp, "TMP="+tmp, "TEMP="+tmp,
		"PATH="+filepath.Dir(goPath)+string(os.PathListSeparator)+os.Getenv("PATH"))
	return env
}

func runOracle(root string, pseudonymize bool) (outcomes []outcome, err error) {
	goPath, err := resolveGo()
	if err != nil {
		return nil, err
	}
	tree, err := extract(root)
	if err != nil {
		return nil, err
	}
	defer func(p string) { _ = os.RemoveAll(p) }(tree)
	mainPath := filepath.Join(tree, "cmd", "store004oracle", "main.go")
	if err = os.MkdirAll(filepath.Dir(mainPath), 0750); err != nil {
		return nil, err
	}
	if err = os.WriteFile(mainPath, []byte(oracleProgram), 0600); err != nil {
		return nil, err
	}
	runtimeDir, err := os.MkdirTemp("", "symvault-store004-runtime-")
	if err != nil {
		return nil, err
	}
	defer func(p string) { _ = os.RemoveAll(p) }(runtimeDir)
	home, tmp := filepath.Join(runtimeDir, "home"), filepath.Join(runtimeDir, "tmp")
	if err = os.MkdirAll(home, 0700); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(tmp, 0700); err != nil {
		return nil, err
	}
	args := []string{"run", "./cmd/store004oracle"}
	if pseudonymize {
		args = append(args, "--pseudonymize")
	}
	ctx, cancel := context.WithTimeout(context.Background(), oracleTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goPath, args...)
	cmd.Dir, cmd.Env = tree, isolatedEnvironment(goPath, home, tmp)
	configureProcessGroup(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	defer func() {
		if closeErr := closeProcessGroup(cmd); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close oracle process group: %w", closeErr))
		}
	}()
	if err = startProcessGroup(cmd); err != nil {
		return nil, fmt.Errorf("start oracle: %w", err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err = <-waitErr:
	case <-ctx.Done():
		if _, killErr := killProcessGroup(cmd); killErr != nil {
			return nil, fmt.Errorf("oracle timeout cleanup: %w", killErr)
		}
		select {
		case <-waitErr:
		case <-time.After(5 * time.Second):
			return nil, errors.New("oracle timeout cleanup exceeded 5s")
		}
		return nil, fmt.Errorf("oracle timed out after %s: %w", oracleTimeout, ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("oracle: %w: %s", err, stderr.Bytes())
	}
	var got []outcome
	if err = json.Unmarshal(stdout.Bytes(), &got); err != nil {
		return nil, fmt.Errorf("oracle output: %w", err)
	}
	return got, nil
}

func generated(root string) ([]byte, error) {
	meta, err := authoritative(root)
	if err != nil {
		return nil, err
	}
	fresh, err := runOracle(root, false)
	if err != nil {
		return nil, err
	}
	pseudo, err := runOracle(root, true)
	if err != nil {
		return nil, err
	}
	cases := make([]outcome, 0, len(fresh)+len(pseudo))
	cases = append(cases, fresh...)
	cases = append(cases, pseudo...)
	data, err := json.MarshalIndent(fixture{1, meta, cases}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
func fixturePath(root, requested string) (string, error) {
	if filepath.IsAbs(requested) {
		return filepath.Clean(requested), nil
	}
	clean := filepath.Clean(filepath.FromSlash(requested))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("fixture path escapes repository")
	}
	return filepath.Join(root, clean), nil
}
func checkFixture(root, path string) error {
	want, err := generated(root)
	if err != nil {
		return err
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("fixture differs from regenerated oracle")
	}
	return nil
}

func main() {
	output := flag.String("output", "testdata/port/store/store004_manifest_failure.json", "fixture path")
	check := flag.Bool("check", false, "compare regenerated oracle bytes with fixture")
	flag.Parse()
	root := rootDir()
	path, err := fixturePath(root, *output)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL STORE-004 fixture:", err)
		os.Exit(1)
	}
	if *check {
		if checkErr := checkFixture(root, path); checkErr != nil {
			fmt.Fprintln(os.Stderr, "FAIL STORE-004 fixture:", checkErr)
			os.Exit(1)
		}
		fmt.Println("PASS STORE-004 fixture (2 cases, regenerated oracle)")
		return
	}
	want, err := generated(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL STORE-004 oracle:", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		panic(err)
	}
	if err = os.WriteFile(path, want, 0600); err != nil {
		panic(err)
	}
	fmt.Println("WROTE", path)
}
