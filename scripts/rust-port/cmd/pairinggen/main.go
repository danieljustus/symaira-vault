// Command pairinggen freezes the PAIRING-001 device-pairing handshake from the
// pinned Go production tree. Like its sibling generators it never reads the
// working tree for oracle bytes: sources are read out of the pinned commit and
// the detached oracle runs inside an extracted copy of that same commit.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	_ "embed"
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
)

const (
	oracleCommit  = "caadd5e"
	oracleRelease = "v0.22.1"
)

// sourceRoots are the production directories the detached oracle imports and
// exercises. extraSourceFiles pins the rest of the seam: the CLI wiring that
// decides where handshake artifacts are written and under which alias they are
// read back, the device registry the oracle drives directly, and the
// symlink-hardened atomic write the registry persists through. A change to any
// of them invalidates this fixture.
var (
	sourceRoots      = []string{"internal/pairing"}
	extraSourceFiles = []string{
		"cmd/device.go",
		"internal/vault/devices.go",
		"internal/vault/symlink_harden.go",
		"internal/vault/symlink_harden_windows.go",
		"internal/fsutil/reexport.go",
	}
	generatorFiles = []string{
		"scripts/rust-port/cmd/pairinggen/main.go",
		"scripts/rust-port/cmd/pairinggen/oracle.go.txt",
	}
)

//go:embed oracle.go.txt
var oracleProgram string

type OracleMeta struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type Case struct {
	ID       string          `json:"id"`
	Seam     string          `json:"seam"`
	Input    json.RawMessage `json:"input"`
	Expected json.RawMessage `json:"expected"`
}

type Fixture struct {
	SchemaVersion int               `json:"schema_version"`
	Oracle        OracleMeta        `json:"oracle"`
	Cases         []Case            `json:"cases"`
	Scope         map[string]string `json:"scope"`
}

func scope() map[string]string {
	return map[string]string{
		"artifact_bytes":   "byte contract: json.MarshalIndent with two-space indent, Go HTML escaping, and RFC3339Nano times",
		"parse_errors":     "semantic contract: accept/reject plus parsed fields; Go error strings are recorded for reference only and are not a Rust parity target",
		"device_sessions":  "out of scope here: DeviceSessionStore belongs to APPROVAL-001 under RUST-011, against its own advanced oracle a518124f",
		"reencryption":     "out of scope here: new-recipient re-encryption on `device accept` is covered by CRYPTO-004 and is not re-frozen by this generator",
		"token_generation": "not a byte contract: GenerateToken draws from crypto/rand; only its shape (32 base32-hex characters) and ValidatePairingToken acceptance are frozen",
		"expiry_clock":     "wall-clock independent: expiry is expressed through the exported pairing.TokenTTL, never by sleeping, so --check is not timing dependent",
		"registry_modes":   "the registry-modes group records POSIX permission bits and is compared on Unix runners only; the case identity is still checked on Windows, so the group cannot be dropped unnoticed",
		"registry_paths":   "no absolute path is frozen: the registry cases record devices.json bytes and returned values, which are identical on every platform",
	}
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate pairinggen")
	}
	root, err := canonicalDir(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	if err != nil {
		panic(fmt.Errorf("locate repository root: %w", err))
	}
	return root
}

func canonicalDir(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(abs)
	info, err := os.Stat(clean)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", clean)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	return filepath.Abs(resolved)
}

func safeRelativePath(path string) (string, error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 || filepath.IsAbs(path) || filepath.VolumeName(path) != "" {
		return "", fmt.Errorf("path must be a non-empty relative path")
	}
	if runtime.GOOS != "windows" && strings.ContainsRune(path, '\\') {
		return "", fmt.Errorf("path contains an unsupported separator")
	}
	clean := filepath.Clean(filepath.FromSlash(path))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes its root")
	}
	return clean, nil
}

func fixturePath(root, requested string) (string, error) {
	base := filepath.Join(root, "testdata", "port")
	var candidate string
	if filepath.IsAbs(requested) {
		candidate = filepath.Clean(requested)
	} else {
		relative, err := safeRelativePath(requested)
		if err != nil {
			return "", err
		}
		candidate = filepath.Join(root, relative)
	}
	relative, err := filepath.Rel(base, candidate)
	if err != nil {
		return "", err
	}
	return safeRelativePath(relative)
}

func openFixtureRoot(root string) (*os.Root, error) {
	return os.OpenRoot(filepath.Join(root, "testdata", "port"))
}

func trustedGitExecutable() (string, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("locate git: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve git executable: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	base := strings.ToLower(filepath.Base(resolved))
	if base != "git" && base != "git.exe" {
		return "", fmt.Errorf("unexpected git executable %q", base)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("git executable is a directory")
	}
	return resolved, nil
}

func newGitCommand(root string) (*exec.Cmd, error) {
	root, err := canonicalDir(root)
	if err != nil {
		return nil, fmt.Errorf("validate repository root: %w", err)
	}
	git, err := trustedGitExecutable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("git")
	if cmd.Err != nil {
		return nil, cmd.Err
	}
	cmd.Path = git
	cmd.Dir = root
	cmd.Args = []string{git}
	return cmd, nil
}

func gitLsTree(root, dir string) ([]byte, error) {
	dir, err := safeRelativePath(dir)
	if err != nil {
		return nil, fmt.Errorf("unsafe source root %q: %w", dir, err)
	}
	cmd, err := newGitCommand(root)
	if err != nil {
		return nil, err
	}
	cmd.Args = append(cmd.Args, "ls-tree", "-r", "--name-only", oracleCommit, "--", filepath.ToSlash(dir))
	return cmd.Output()
}

func gitShow(root, name string) ([]byte, error) {
	name, err := safeRelativePath(name)
	if err != nil {
		return nil, fmt.Errorf("unsafe source path %q: %w", name, err)
	}
	cmd, err := newGitCommand(root)
	if err != nil {
		return nil, err
	}
	cmd.Args = append(cmd.Args, "show", oracleCommit+":"+filepath.ToSlash(name))
	return cmd.Output()
}

func gitArchive(root string, output io.Writer) error {
	cmd, err := newGitCommand(root)
	if err != nil {
		return err
	}
	cmd.Args = append(cmd.Args, "archive", "--format=tar", oracleCommit)
	cmd.Stdout = output
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git archive: %w: %s", err, stderr.String())
	}
	return nil
}

func sourceFiles(root string) ([]string, error) {
	var files []string
	for _, dir := range sourceRoots {
		out, err := gitLsTree(root, dir)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.HasSuffix(line, ".go") && !strings.HasSuffix(line, "_test.go") {
				files = append(files, line)
			}
		}
	}
	files = append(files, extraSourceFiles...)
	sort.Strings(files)
	return files, nil
}

func digest(root string, names []string, pinned bool) (string, error) {
	h := sha256.New()
	var repository *os.Root
	if !pinned {
		var err error
		repository, err = os.OpenRoot(root)
		if err != nil {
			return "", err
		}
		defer func() { _ = repository.Close() }()
	}
	for _, name := range names {
		var data []byte
		var err error
		if pinned {
			data, err = gitShow(root, name)
		} else {
			clean, clErr := safeRelativePath(name)
			if clErr != nil {
				return "", fmt.Errorf("digest %s: %w", name, clErr)
			}
			data, err = repository.ReadFile(clean)
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

func metadata(root string) (OracleMeta, error) {
	src, err := sourceFiles(root)
	if err != nil {
		return OracleMeta{}, err
	}
	sourceDigest, err := digest(root, src, true)
	if err != nil {
		return OracleMeta{}, err
	}
	generatorDigest, err := digest(root, generatorFiles, false)
	if err != nil {
		return OracleMeta{}, err
	}
	return OracleMeta{oracleCommit, oracleRelease, src, sourceDigest, generatorFiles, generatorDigest}, nil
}

func extract(root string) (string, error) {
	dir, err := os.MkdirTemp("", "pairing-oracle-")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	archive, err := os.CreateTemp("", "pairing-oracle-*.tar")
	if err != nil {
		return "", err
	}
	archivePath := archive.Name()
	defer func() {
		_ = archive.Close()
		_ = os.Remove(archivePath)
	}()
	if err = gitArchive(root, archive); err != nil {
		return "", err
	}
	if _, err = archive.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind oracle archive: %w", err)
	}
	reader := tar.NewReader(archive)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		name, err := safeRelativePath(header.Name)
		if err != nil {
			return "", fmt.Errorf("unsafe oracle path %q: %w", header.Name, err)
		}
		out := filepath.Join(dir, name)
		switch header.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(out, 0750)
		case tar.TypeReg:
			err = os.MkdirAll(filepath.Dir(out), 0750)
			if err == nil {
				data := make([]byte, header.Size)
				if _, err = io.ReadFull(reader, data); err == nil {
					err = os.WriteFile(out, data, 0600)
				}
			}
		}
		if err != nil {
			return "", err
		}
	}
	keep = true
	return dir, nil
}

func runOracle(root string) ([]Case, error) {
	tree, err := extract(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tree) }()
	program := filepath.Join(tree, "cmd", "pairingoracle", "main.go")
	if err = os.MkdirAll(filepath.Dir(program), 0750); err != nil {
		return nil, err
	}
	if err = os.WriteFile(program, []byte(oracleProgram), 0600); err != nil {
		return nil, err
	}
	cmd := exec.Command("go", "run", "./cmd/pairingoracle")
	cmd.Dir = tree
	// stdout carries the fixture JSON and nothing else. `go run` reports module
	// downloads and build diagnostics on stderr, so the two streams are kept
	// apart: merging them made the first run on a cold module cache parse
	// "go: downloading ..." as the fixture. stderr is still captured and
	// surfaced on failure, so a real error cannot be swallowed.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("detached oracle: %w: %s", err, stderr.String())
	}
	var raw struct {
		Cases []Case `json:"cases"`
	}
	if err = json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	if len(raw.Cases) == 0 {
		return nil, errors.New("detached oracle produced no cases")
	}
	return raw.Cases, nil
}

func load(fixtures *os.Root, path string) (Fixture, error) {
	path, err := safeRelativePath(path)
	if err != nil {
		return Fixture{}, err
	}
	data, err := fixtures.ReadFile(path)
	if err != nil {
		return Fixture{}, err
	}
	var fixture Fixture
	err = json.Unmarshal(data, &fixture)
	return fixture, err
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameJSON(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ax, err := json.Marshal(x)
	if err != nil {
		return false
	}
	by, err := json.Marshal(y)
	if err != nil {
		return false
	}
	return bytes.Equal(ax, by)
}

func validate(root string, fixtures *os.Root, path string) error {
	fixture, err := load(fixtures, path)
	if err != nil {
		return err
	}
	meta, err := metadata(root)
	if err != nil {
		return err
	}
	if fixture.SchemaVersion != 1 || fixture.Oracle.Commit != meta.Commit || fixture.Oracle.Release != meta.Release ||
		fixture.Oracle.SourceDigest != meta.SourceDigest || fixture.Oracle.GeneratorDigest != meta.GeneratorDigest ||
		!sameStrings(fixture.Oracle.SourceFiles, meta.SourceFiles) || !sameStrings(fixture.Oracle.GeneratorFiles, meta.GeneratorFiles) {
		return errors.New("pairing fixture provenance changed; regenerate from the pinned Go oracle")
	}
	got, err := runOracle(root)
	if err != nil {
		return err
	}
	if len(got) != len(fixture.Cases) {
		return fmt.Errorf("pairing case cardinality %d, want %d", len(fixture.Cases), len(got))
	}
	for i := range got {
		if got[i].ID != fixture.Cases[i].ID || got[i].Seam != fixture.Cases[i].Seam ||
			!sameJSON(got[i].Input, fixture.Cases[i].Input) {
			return fmt.Errorf("pairing case %d (%s) drifted; regenerate from the Go oracle", i, fixture.Cases[i].ID)
		}
		// The registry-modes group records POSIX permission bits. Windows has
		// none to compare, so its payload is verified on Unix runners only.
		// The case identity is still checked above, so a group that silently
		// disappeared would still fail here.
		if runtime.GOOS == "windows" && strings.HasPrefix(got[i].ID, "registry-modes/") {
			continue
		}
		if !sameJSON(got[i].Expected, fixture.Cases[i].Expected) {
			return fmt.Errorf("pairing case %d (%s) drifted; regenerate from the Go oracle", i, fixture.Cases[i].ID)
		}
	}
	return nil
}

func writeFixture(fixtures *os.Root, path string, data []byte, check bool) error {
	path, err := safeRelativePath(path)
	if err != nil {
		return err
	}
	if check {
		existing, err := fixtures.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("%s is stale; regenerate from the pinned Go oracle", path)
		}
		return nil
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := fixtures.MkdirAll(dir, 0750); err != nil {
			return err
		}
	}
	return fixtures.WriteFile(path, data, 0600)
}

// main keeps no cleanup of its own so that run's deferred close always happens:
// calling os.Exit from inside a function that holds a defer would skip it.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL pairing fixture:", err)
		os.Exit(1)
	}
}

func run() error {
	output := flag.String("output", "testdata/port/pairing/contract.json", "fixture path")
	check := flag.Bool("check", false, "verify provenance and execute the detached oracle")
	flag.Parse()
	root := rootDir()
	fixtures, openErr := openFixtureRoot(root)
	if openErr != nil {
		return fmt.Errorf("open fixture root: %w", openErr)
	}
	defer func() { _ = fixtures.Close() }()

	outputPath, pathErr := fixturePath(root, *output)
	if pathErr != nil {
		return fmt.Errorf("fixture path: %w", pathErr)
	}

	if *check {
		if validateErr := validate(root, fixtures, outputPath); validateErr != nil {
			return validateErr
		}
		fixture, loadErr := load(fixtures, outputPath)
		if loadErr != nil {
			return loadErr
		}
		fmt.Printf("PASS Go pairing oracle fixture (%d cases)\n", len(fixture.Cases))
		return nil
	}

	meta, metaErr := metadata(root)
	if metaErr != nil {
		return metaErr
	}
	cases, oracleErr := runOracle(root)
	if oracleErr != nil {
		return oracleErr
	}
	data, marshalErr := json.MarshalIndent(Fixture{1, meta, cases, scope()}, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	data = append(data, '\n')
	if writeErr := writeFixture(fixtures, outputPath, data, false); writeErr != nil {
		return writeErr
	}
	fmt.Println("WROTE", *output)
	return nil
}
