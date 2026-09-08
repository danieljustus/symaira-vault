// Command storemetagen generates the deterministic entry metadata port fixture
// from the production Go preparation helper.
package main

import (
	"archive/tar"
	"bytes"
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
	"strings"
	"time"

	vault "github.com/danieljustus/symaira-vault/internal/vault"
)

const fixedNow = "2026-09-08T10:11:12.123456789Z"

var sourceFiles = []string{
	"internal/vault/entry.go",
	"internal/vault/entry_readwrite.go",
	"internal/vault/recipients.go",
	"internal/vault/entry_metadata.go",
}
var generatorFiles = []string{"scripts/rust-port/cmd/storemetagen/main.go"}

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}
type vector struct {
	Name         string             `json:"name"`
	Input        json.RawMessage    `json:"input"`
	PendingWrite *vault.WriteRecord `json:"pending_write,omitempty"`
	Path         string             `json:"path"`
	Pseudonymize bool               `json:"pseudonymize"`
	Now          string             `json:"now"`
	Expected     json.RawMessage    `json:"expected"`
	ExpectedJSON string             `json:"expected_json"`
}
type fixture struct {
	SchemaVersion int      `json:"schema_version"`
	Oracle        oracle   `json:"oracle"`
	Vectors       []vector `json:"vectors"`
}

func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("locate generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../")), nil
}
func readConfined(root, name string) ([]byte, error) {
	base, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	file, err := base.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func digest(root string, files []string) (string, error) {
	h := sha256.New()
	for _, name := range files {
		data, err := readConfined(root, name)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func verifySourcesAtCommit(root, commit string) error {
	cmd := exec.Command("git", "archive", commit)
	cmd.Dir = root
	archive, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("archive sources at %s: %w", commit, err)
	}
	want := make(map[string][]byte, len(sourceFiles))
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read source archive: %w", err)
		}
		for _, name := range sourceFiles {
			if header.Name == name {
				data, err := io.ReadAll(reader)
				if err != nil {
					return err
				}
				want[name] = data
			}
		}
	}
	for _, name := range sourceFiles {
		committed, ok := want[name]
		if !ok {
			return fmt.Errorf("source %s missing from oracle commit %s", name, commit)
		}
		current, err := readConfined(root, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if !bytes.Equal(committed, current) {
			return fmt.Errorf("source file %s differs from oracle commit %s", name, commit)
		}
	}
	return nil
}

func makeFixture(root, commit, release string) (fixture, error) {
	if commit == "" || release == "" {
		return fixture{}, errors.New("oracle commit and release are required")
	}
	if err := verifySourcesAtCommit(root, commit); err != nil {
		return fixture{}, err
	}
	sourceDigest, err := digest(root, sourceFiles)
	if err != nil {
		return fixture{}, err
	}
	generatorDigest, err := digest(root, generatorFiles)
	if err != nil {
		return fixture{}, err
	}
	now, err := time.Parse(time.RFC3339Nano, fixedNow)
	if err != nil {
		return fixture{}, err
	}
	pending := &vault.WriteRecord{Field: "token", Action: "set"}
	input := vault.Entry{Data: map[string]any{"token": "fixture-token"}, PendingWrite: pending}
	zero := vault.Entry{Data: nil, Metadata: vault.EntryMetadata{Version: 7}}
	existing := vault.Entry{Path: "old", Data: map[string]any{"x": "y"}, Metadata: vault.EntryMetadata{Created: now.Add(-time.Hour), Version: 2}}
	offsetNow, err := time.Parse(time.RFC3339Nano, "2026-09-08T10:11:12.123456789+01:30")
	if err != nil {
		return fixture{}, err
	}
	zeroOffset, err := time.Parse(time.RFC3339Nano, "0001-01-01T00:00:00+00:00")
	if err != nil {
		return fixture{}, err
	}
	zeroWalltime, err := time.Parse(time.RFC3339Nano, "0001-01-01T01:00:00+01:00")
	if err != nil {
		return fixture{}, err
	}
	nearZero, err := time.Parse(time.RFC3339Nano, "0001-01-01T00:00:00.000000001Z")
	if err != nil {
		return fixture{}, err
	}
	zeroOffsetEntry := vault.Entry{Data: map[string]any{"x": "y"}, Metadata: vault.EntryMetadata{Created: zeroOffset, Version: 4}}
	zeroWalltimeEntry := vault.Entry{Data: map[string]any{"x": "y"}, Metadata: vault.EntryMetadata{Created: zeroWalltime, Version: 5}}
	nearZeroEntry := vault.Entry{Data: map[string]any{"x": "y"}, Metadata: vault.EntryMetadata{Created: nearZero, Version: 6}}
	offsetEntry := vault.Entry{Data: map[string]any{"x": "y"}, Metadata: vault.EntryMetadata{Version: 3}}
	overflow := vault.Entry{Metadata: vault.EntryMetadata{Version: int(^uint(0) >> 1)}}
	cases := []struct {
		name, path, nowText string
		now                 time.Time
		pseudo              bool
		input               vault.Entry
		inputCreated        string
		pending             *vault.WriteRecord
	}{
		{"created_zero_pending", "logical/secret", fixedNow, now, true, input, "", pending},
		{"nil_data_existing_version", "logical/empty", fixedNow, now, false, zero, "", nil},
		{"created_nonzero", "logical/existing", fixedNow, now, true, existing, "", nil},
		{"offset_clock", "logical/offset", "2026-09-08T10:11:12.123456789+01:30", offsetNow, false, offsetEntry, "", nil},
		{"created_zero_offset", "logical/zero-offset", fixedNow, now, false, zeroOffsetEntry, "0001-01-01T00:00:00+00:00", nil},
		{"created_zero_walltime_offset", "logical/zero-walltime", fixedNow, now, false, zeroWalltimeEntry, "", nil},
		{"created_near_zero_nonzero", "logical/near-zero", fixedNow, now, false, nearZeroEntry, "", nil},
		{"version_overflow", "", fixedNow, now, false, overflow, "", nil},
	}
	vectors := make([]vector, 0, len(cases))
	for _, item := range cases {
		prepared := vault.PrepareEntryForWrite(&item.input, item.now, item.path, item.pseudo)
		raw, err := json.Marshal(prepared)
		if err != nil {
			return fixture{}, err
		}
		inputRaw, err := json.Marshal(item.input)
		if err != nil {
			return fixture{}, err
		}
		if item.inputCreated != "" {
			old := []byte(`"created":"0001-01-01T00:00:00Z"`)
			new := []byte(`"created":"` + item.inputCreated + `"`)
			if bytes.Count(inputRaw, old) != 1 {
				return fixture{}, errors.New("zero-offset input timestamp was not canonical Go output")
			}
			inputRaw = bytes.Replace(inputRaw, old, new, 1)
		}
		vectors = append(vectors, vector{item.name, inputRaw, item.pending, item.path, item.pseudo, item.nowText, raw, string(raw)})
	}
	return fixture{1, oracle{commit, release, sourceFiles, sourceDigest, generatorFiles, generatorDigest}, vectors}, nil
}
func fixtureBytes(value fixture) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func checkFixture(root, output, commit, release string) error {
	value, err := makeFixture(root, commit, release)
	if err != nil {
		return err
	}
	want, err := fixtureBytes(value)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(root, output)
	}
	relative, err := filepath.Rel(root, output)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("fixture output escapes repository root")
	}
	actual, err := readConfined(root, relative)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, want) {
		return errors.New("metadata fixture is stale; regenerate it")
	}
	return nil
}

func write(path string, value fixture) error {
	data, err := fixtureBytes(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
func main() {
	output := flag.String("output", "testdata/port/store/metadata.json", "fixture path")
	commit := flag.String("oracle-commit", "", "Go oracle commit")
	release := flag.String("oracle-release", "", "Go oracle release")
	check := flag.Bool("check", false, "compare generated bytes with output")
	flag.Parse()
	root, err := repoRoot()
	if err != nil {
		fatal(err)
	}
	value, err := makeFixture(root, *commit, *release)
	if err != nil {
		fatal(err)
	}
	if *check {
		if err := checkFixture(root, *output, *commit, *release); err != nil {
			fatal(err)
		}
		fmt.Printf("PASS metadata fixture (%d vectors)\n", len(value.Vectors))
		return
	}
	if !filepath.IsAbs(*output) {
		*output = filepath.Join(root, *output)
	}
	if err := write(*output, value); err != nil {
		fatal(err)
	}
	fmt.Println("WROTE", *output)
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "FAIL store metadata fixture:", err); os.Exit(1) }
