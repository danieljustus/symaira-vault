// Command configprofilegen derives the Rust profile contract from a pinned Go
// source tree. The pinned tree is archived and executed; the checkout's Go
// package is never used as the oracle.
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
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/diff"
)

const (
	pinnedOracleCommit  = "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
	pinnedOracleRelease = "v0.22.1"
	requiredGoVersion   = "go1.26.6"

	// Upper bound for a single extracted oracle archive member. The archive is
	// produced by git archive over our own pinned commit, so this is a sanity
	// bound rather than a trust boundary.
	maxOracleFileBytes = 64 << 20
)

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
	GeneratorFiles  []string `json:"generator_files"`
}

type caseResult struct {
	Name   string          `json:"name"`
	Input  string          `json:"input"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	Panic  string          `json:"panic,omitempty"`
}

type fixture struct {
	SchemaVersion int          `json:"schema_version"`
	Oracle        oracle       `json:"oracle"`
	Cases         []caseResult `json:"cases"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %v\n", err)
		os.Exit(1)
	}
}

func run() (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if value, ok := recovered.(error); ok {
				err = value
			} else {
				err = fmt.Errorf("%v", recovered)
			}
		}
	}()
	output := flag.String("output", "testdata/port/config_profiles_contract.json", "fixture output")
	check := flag.Bool("check", false, "check instead of writing")
	commit := flag.String("oracle-commit", "", "pinned Go oracle commit")
	release := flag.String("oracle-release", "", "pinned Go oracle release")
	flag.Parse()
	if *check {
		*commit, *release = pinnedOracleCommit, pinnedOracleRelease
	} else if *commit != pinnedOracleCommit || *release != pinnedOracleRelease {
		fatal("generation requires --oracle-commit=%s and --oracle-release=%s", pinnedOracleCommit, pinnedOracleRelease)
	}
	root := repositoryRoot()
	generatorFiles := []string{"scripts/rust-port/cmd/configprofilegen/main.go", "scripts/rust-port/cmd/configprofilegen/main_test.go"}
	entries, listErr := os.ReadDir(filepath.Join(root, "scripts/rust-port/internal/diff"))
	if listErr != nil {
		return listErr
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".go") {
			generatorFiles = append(generatorFiles, "scripts/rust-port/internal/diff/"+entry.Name())
		}
	}
	sort.Strings(generatorFiles)
	oracleRoot := makeTempDir("config-profile-oracle-")
	defer func() { err = errors.Join(err, removeTempTree(oracleRoot)) }()
	archiveOracle(root, oracleRoot)
	writeOracleHelper(oracleRoot)
	files := oracleSourceFiles(oracleRoot)
	meta := oracle{Commit: pinnedOracleCommit, Release: pinnedOracleRelease, SourceFiles: files,
		SourceDigest: digestFiles(oracleRoot, files), GeneratorFiles: generatorFiles, GeneratorDigest: digestFiles(root, generatorFiles)}
	cases := runOracle(oracleRoot)
	content, err := json.MarshalIndent(fixture{SchemaVersion: 1, Oracle: meta, Cases: cases}, "", "  ")
	if err != nil {
		fatal("encode fixture: %v", err)
	}
	content = append(content, '\n')
	fixturePath := filepath.Join(root, filepath.Clean(*output))
	if !strings.HasPrefix(fixturePath, filepath.Join(root, "testdata", "port")+string(filepath.Separator)) {
		fatal("output must be under testdata/port")
	}
	if *check {
		existing, readErr := os.ReadFile(fixturePath) // #nosec G304 -- operator-selected fixture path
		if readErr != nil {
			fatal("read fixture: %v", readErr)
		}
		if err := validateFixture(existing, content); err != nil {
			fatal("%v", err)
		}
		fmt.Printf("PASS pinned profile fixture (%d cases)\n", len(cases))
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o750); err != nil {
		fatal("create output directory: %v", err)
	}
	if err := os.WriteFile(fixturePath, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases)\n", *output, len(cases))
	return nil
}

func validateFixture(existing, generated []byte) error {
	if !bytes.Equal(existing, generated) {
		for i := 0; i < min(len(existing), len(generated)); i++ {
			if existing[i] != generated[i] {
				return fmt.Errorf("fixture is stale at byte %d: expected %q, generated %q", i, existing[i:min(i+160, len(existing))], generated[i:min(i+160, len(generated))])
			}
		}
		return fmt.Errorf("fixture is stale: expected %d bytes, generated %d", len(existing), len(generated))
	}
	return nil
}

func repositoryRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		fatal("locate generator")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	if err != nil {
		fatal("locate repository: %v", err)
	}
	return root
}

func makeTempDir(pattern string) string {
	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		fatal("temporary root: %v", err)
	}
	return dir
}

func archiveOracle(repo, destination string) {
	git, err := exec.LookPath("git")
	if err != nil {
		fatal("archive oracle: %v", err)
	}
	archive := filepath.Join(destination, "oracle.tar")
	observation, err := diff.Run(git, diff.Case{ID: "config-profile-archive", Args: []string{"-C", repo, "-c", "core.autocrlf=false", "-c", "core.eol=lf", "archive", "--format=tar", "--output", archive, pinnedOracleCommit}, TimeoutMS: 60000})
	if err != nil || observation.ExitCode != 0 || observation.Signal != "" || observation.TimedOut {
		fatal("archive oracle: %v exit=%d signal=%q timeout=%t", err, observation.ExitCode, observation.Signal, observation.TimedOut)
	}
	file, err := os.Open(archive) // #nosec G304 -- archive path is constructed above under our own temp directory
	if err != nil {
		fatal("read archive: %v", err)
	}
	defer func() {
		if err := errors.Join(file.Close(), os.Remove(archive)); err != nil {
			fatal("close archive: %v", err)
		}
	}()
	tr := tar.NewReader(file)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fatal("read oracle archive: %v", err)
		}
		name, err := safeArchivePath(header.Name)
		if err != nil {
			fatal("oracle archive path: %v", err)
		}
		path := filepath.Join(destination, name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o750); err != nil {
				fatal("extract oracle: %v", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				fatal("extract oracle: %v", err)
			}
			// #nosec G304 -- path is validated by safeArchivePath and rooted in our temp directory
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				fatal("extract oracle: %v", err)
			}
			// The archive comes from git archive over this repository's own
			// pinned commit, but the extraction is bounded anyway: an
			// unbounded io.Copy from a tar reader is a decompression-bomb
			// sink. Reading one byte past the cap detects truncation instead
			// of silently writing a short file.
			written, copyErr := io.Copy(file, io.LimitReader(tr, maxOracleFileBytes+1))
			if copyErr == nil && written > maxOracleFileBytes {
				copyErr = fmt.Errorf("oracle archive member %q exceeds %d bytes", name, int64(maxOracleFileBytes))
			}
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				fatal("extract oracle: %v %v", copyErr, closeErr)
			}
		}
	}
}

func safeArchivePath(name string) (string, error) {
	// Tar paths are slash-separated and relative, independent of the host OS.
	// Windows IsAbs rejects a rooted path without a drive, so check it here.
	if strings.HasPrefix(name, "/") || strings.ContainsAny(name, `\:`) {
		return "", fmt.Errorf("unsafe path %q", name)
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe path %q", name)
	}
	return clean, nil
}

func writeOracleHelper(root string) {
	const helper = `package main
import (
  "encoding/json"
  "fmt"
  "os"
  "runtime"
  config "github.com/danieljustus/symaira-vault/internal/config"
)
type result struct { Name string ` + "`json:\"name\"`" + `; Input string ` + "`json:\"input\"`" + `; Result any ` + "`json:\"result,omitempty\"`" + `; Error string ` + "`json:\"error,omitempty\"`" + `; Panic string ` + "`json:\"panic,omitempty\"`" + ` }
type snapshot struct { DefaultProfile string ` + "`json:\"default_profile\"`" + `; Profiles map[string]*config.Profile ` + "`json:\"profiles\"`" + `; Saved string ` + "`json:\"saved\"`" + ` }
func run(name, input string) (out result) { out.Name, out.Input = name, input; defer func(){ if r:=recover(); r!=nil { out.Panic=fmt.Sprint(r) } }();
  in, err:=os.CreateTemp("", "config-profile-input-*.yaml"); if err!=nil { out.Error=err.Error(); return }; defer os.Remove(in.Name()); if _,err=in.WriteString(input); err!=nil { out.Error=err.Error(); return }; in.Close()
  cfg,err:=config.Load(in.Name()); if err!=nil { out.Error=err.Error(); return }
  saved,err:=os.CreateTemp("", "config-profile-saved-*.yaml"); if err!=nil { out.Error=err.Error(); return }; saved.Close(); defer os.Remove(saved.Name())
  if err=cfg.SaveTo(saved.Name()); err!=nil { out.Error=err.Error(); return }; data,err:=os.ReadFile(saved.Name()); if err!=nil { out.Error=err.Error(); return }
  out.Result=snapshot{cfg.DefaultProfile,cfg.Profiles,string(data)}; return }
func main(){ if runtime.Version()!=` + "`go1.26.6`" + ` { panic("toolchain="+runtime.Version()+", want go1.26.6") }; cases:=[]struct{name,input string}{
 {"profiles", "profiles:\n  work:\n    vault: ~/.symvault-work\n  family:\n    vault: ~/vaults/family\ndefaultProfile: work\n"}, {"empty_path", "profiles:\n  empty:\n    vault: \"\"\n"}, {"null_profiles", "profiles: null\ndefaultProfile: null\n"}, {"null_profile", "profiles:\n  empty: null\n"}, {"null_path", "profiles:\n  empty:\n    vault: null\n"}, {"numeric_name", "profiles:\n  1:\n    vault: /tmp/vault\n"}, {"numeric_path", "profiles:\n  bad:\n    vault: 1\n"}, {"map_profile", "profiles:\n  bad: {}\n"}, {"sequence_profile", "profiles:\n  bad: []\n"}, {"bool_profile", "profiles:\n  bad: true\n"}, {"map_default", "defaultProfile: {}\n"}, {"sequence_default", "defaultProfile: []\n"}, {"bool_default", "defaultProfile: true\n"}, {"numeric_default", "defaultProfile: 1\n"}, }
 cases=append(cases,
   struct{name,input string}{"unicode-digit-prefix", "profiles:\n  ١a: {}\n  ١_: {}\n"},
   struct{name,input string}{"unicode-letter-number", "profiles:\n  Ⅰ: {}\n  a: {}\n"},
   struct{name,input string}{"unicode-digit-run", "profiles:\n  ١0: {}\n  ٢: {}\n"},
   struct{name,input string}{"duplicate-default-profile", "defaultProfile: safe\ndefaultProfile: other\n"},
   struct{name,input string}{"duplicate-root", "defaultAgent: first\ndefaultAgent: second\n"},
   struct{name,input string}{"duplicate-profile", "profiles:\n  same: {vault: first}\n  same: {vault: second}\n"},
   struct{name,input string}{"lexically-distinct-keys", "profiles:\n  01: {vault: first}\n  1: {vault: second}\n"},
   struct{name,input string}{"profile-alias", "profiles:\n  first: &p {vault: /tmp/first}\n  second: *p\n"},
   struct{name,input string}{"profile-merge", "profiles:\n  first: &p {vault: /tmp/first}\n  second: {<<: *p}\n"},
 )
 for i,scalar:=range []string{"TRUE", "01", "0x10", "1_000", "1.0", "1e3", "18446744073709551616", "yes", "no", "on", "off", "1:20", "C:\\Temp\\vault"} {
   cases=append(cases,struct{name,input string}{fmt.Sprintf("scalar-default-%d",i),"defaultProfile: "+scalar+"\n"})
   cases=append(cases,struct{name,input string}{fmt.Sprintf("scalar-name-%d",i),"profiles:\n  "+scalar+":\n    vault: /tmp/test\n"})
   cases=append(cases,struct{name,input string}{fmt.Sprintf("scalar-vault-%d",i),"profiles:\n  test:\n    vault: "+scalar+"\n"})
 }
 out:=make([]result,0,len(cases)); for _,c:=range cases { out=append(out,run(c.name,c.input)) }; json.NewEncoder(os.Stdout).Encode(out) }
`
	path := filepath.Join(root, "internal/configprofileoracle/main.go")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatal("write helper: %v", err)
	}
	if err := os.WriteFile(path, []byte(helper), 0o600); err != nil {
		fatal("write helper: %v", err)
	}
}

func oracleSourceFiles(root string) []string {
	files := []string{"go.mod", "go.sum", "internal/fsutil/reexport.go"}
	entries, err := os.ReadDir(filepath.Join(root, "internal", "config"))
	if err != nil {
		fatal("list oracle sources: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			files = append(files, filepath.ToSlash(filepath.Join("internal/config", entry.Name())))
		}
	}
	sort.Strings(files)
	return files
}
func digestFiles(root string, names []string) string {
	h := sha256.New()
	for _, name := range names {
		// #nosec G304 -- name comes from the fixed production source list
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			fatal("hash %s: %v", name, err)
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
func runOracle(root string) []caseResult {
	goBinary := pinnedGoBinary()
	cache := makeTempDir("config-profile-cache-")
	defer func() {
		if err := removeTempTree(cache); err != nil {
			fatal("remove oracle cache: %v", err)
		}
	}()
	observation, err := diff.Run(goBinary, diff.Case{
		ID:        "config-profile-oracle",
		Args:      []string{"-C", root, "run", "./internal/configprofileoracle"},
		TimeoutMS: 300000,
		Env:       map[string]string{"GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=readonly", "CGO_ENABLED": "0", "GOCACHE": filepath.Join(cache, "build"), "GOMODCACHE": filepath.Join(cache, "modules")},
	})
	if err != nil || observation.ExitCode != 0 || observation.Signal != "" || observation.TimedOut {
		fatal("run pinned oracle: %v exit=%d signal=%q timeout=%t\n%s", err, observation.ExitCode, observation.Signal, observation.TimedOut, observation.Stderr)
	}
	var cases []caseResult
	if err := json.Unmarshal(observation.Stdout, &cases); err != nil {
		fatal("decode oracle: %v", err)
	}
	// Normalize only the saved YAML field, which is derived from our sandbox.
	// Inputs and arbitrary user values must remain byte-for-byte untouched.
	for i := range cases {
		if len(cases[i].Result) == 0 {
			continue
		}
		var snapshot struct {
			Saved string `json:"saved"`
		}
		if err := json.Unmarshal(cases[i].Result, &snapshot); err != nil {
			fatal("decode case %s: %v", cases[i].Name, err)
		}
		snapshot.Saved = normalizeSaved(snapshot.Saved, filepath.Join(observation.SandboxRoot, "home", ".local", "share", "symaira-vault"))
		updated, err := json.Marshal(snapshotWithSaved(cases[i].Result, snapshot.Saved))
		if err != nil {
			fatal("normalize case %s: %v", cases[i].Name, err)
		}
		cases[i].Result = updated
	}
	return cases
}

func snapshotWithSaved(raw json.RawMessage, saved string) map[string]any {
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		fatal("decode snapshot: %v", err)
	}
	value["saved"] = saved
	return value
}

// Only the generated top-level default vault path is non-semantic. Never
// replace user profile values or every occurrence of the temporary root.
func normalizeSaved(saved, vaultPath string) string {
	lines := strings.Split(saved, "\n")
	for i, line := range lines {
		if line == "vaultDir: "+vaultPath {
			lines[i] = "vaultDir: /fixture/root/data/symaira-vault"
		}
	}
	return strings.Join(lines, "\n")
}

func pinnedGoBinary() string {
	// The generator itself must be built with the pinned toolchain. This
	// works with setup-go as well as GOTOOLCHAIN, without a named shim.
	if runtime.Version() != requiredGoVersion {
		fatal("generator toolchain %s, want %s", runtime.Version(), requiredGoVersion)
	}
	name := "go"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	launcher := exec.Command("go", "env", "GOROOT")
	launcher.Env = append(os.Environ(), "GOTOOLCHAIN="+requiredGoVersion)
	goRoot, err := launcher.Output()
	if err != nil {
		fatal("resolve pinned Go root: %v", err)
	}
	binary := filepath.Join(strings.TrimSpace(string(goRoot)), "bin", name)
	version, err := exec.Command(binary, "version").Output() // #nosec G204 -- binary is the pinned Go toolchain resolved above
	fields := strings.Fields(string(version))
	if err != nil || len(fields) < 3 || fields[2] != requiredGoVersion {
		fatal("pinned Go binary version mismatch: %s", strings.TrimSpace(string(version)))
	}
	return binary
}

func removeTempTree(root string) error {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil {
			// Only directories need the traversal bit to be removable; files
			// must not be widened past owner read/write.
			mode := os.FileMode(0o600)
			if info.IsDir() {
				mode = 0o700
			}
			_ = os.Chmod(path, mode)
		}
		return nil
	})
	return os.RemoveAll(root)
}

func fatal(format string, args ...any) {
	panic(fmt.Errorf(format, args...))
}
