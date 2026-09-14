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
	pinnedOracleCommit  = "caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44"
	pinnedOracleRelease = "v0.22.1"
	requiredGoVersion   = "go1.26.6"
)

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type caseResult struct {
	Name   string          `json:"name"`
	Input  string          `json:"input"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
	Panic  string          `json:"panic,omitempty"`
}

type fixture struct {
	Oracle oracle       `json:"oracle"`
	Cases  []caseResult `json:"cases"`
}

func main() {
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
	generatorPath := filepath.Join(root, "scripts/rust-port/cmd/configprofilegen/main.go")
	oracleRoot := makeTempDir("config-profile-oracle-")
	defer os.RemoveAll(oracleRoot)
	archiveOracle(root, oracleRoot)
	writeOracleHelper(oracleRoot)
	files := oracleSourceFiles(oracleRoot)
	meta := oracle{Commit: pinnedOracleCommit, Release: pinnedOracleRelease, SourceFiles: files,
		SourceDigest: digestFiles(oracleRoot, files), GeneratorDigest: digestFile(generatorPath)}
	cases := runOracle(oracleRoot)
	content, err := json.MarshalIndent(fixture{Oracle: meta, Cases: cases}, "", "  ")
	if err != nil {
		fatal("encode fixture: %v", err)
	}
	content = append(content, '\n')
	fixturePath := filepath.Join(root, filepath.Clean(*output))
	if !strings.HasPrefix(fixturePath, filepath.Join(root, "testdata", "port")+string(filepath.Separator)) {
		fatal("output must be under testdata/port")
	}
	if *check {
		existing, err := os.ReadFile(fixturePath)
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; rerun generation")
		}
		fmt.Printf("PASS pinned profile fixture (%d cases)\n", len(cases))
		return
	}
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o750); err != nil {
		fatal("create output directory: %v", err)
	}
	if err := os.WriteFile(fixturePath, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases)\n", *output, len(cases))
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
	cmd := exec.Command("git", "-C", repo, "archive", "--format=tar", pinnedOracleCommit)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fatal("archive oracle: %v", err)
	}
	if err := cmd.Start(); err != nil {
		fatal("archive oracle: %v", err)
	}
	tr := tar.NewReader(stdout)
	for {
		header, err := tr.Next()
		if err == io.EOF {
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
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				fatal("extract oracle: %v", err)
			}
			_, copyErr := io.Copy(file, tr)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil {
				fatal("extract oracle: %v %v", copyErr, closeErr)
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		fatal("archive oracle: %v", err)
	}
}

func safeArchivePath(name string) (string, error) {
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
	var files []string
	entries, err := os.ReadDir(filepath.Join(root, "internal", "config"))
	if err != nil {
		fatal("list oracle sources: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".go") {
			files = append(files, filepath.ToSlash(filepath.Join("internal/config", entry.Name())))
		}
	}
	sort.Strings(files)
	return files
}
func digestFiles(root string, names []string) string {
	h := sha256.New()
	for _, name := range names {
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
func digestFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("hash generator: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func runOracle(root string) []caseResult {
	toolchain := exec.Command("go1.26.6", "env", "GOROOT")
	goRootBytes, err := toolchain.Output()
	if err != nil {
		fatal("locate pinned toolchain: %v", err)
	}
	goBinary := filepath.Join(strings.TrimSpace(string(goRootBytes)), "bin", "go")
	cmd := exec.Command(goBinary, "run", "./internal/configprofileoracle")
	cmd.Dir = root
	envRoot := makeTempDir("config-profile-env-")
	defer os.RemoveAll(envRoot)
	for _, dir := range []string{"home", "config", "data", "cache", "tmp", "gocache"} {
		if err := os.MkdirAll(filepath.Join(envRoot, dir), 0o700); err != nil {
			fatal("oracle environment: %v", err)
		}
	}
	cmd.Env = []string{"HOME=" + filepath.Join(envRoot, "home"), "USERPROFILE=" + filepath.Join(envRoot, "home"), "XDG_CONFIG_HOME=" + filepath.Join(envRoot, "config"), "XDG_DATA_HOME=" + filepath.Join(envRoot, "data"), "XDG_CACHE_HOME=" + filepath.Join(envRoot, "cache"), "TMPDIR=" + filepath.Join(envRoot, "tmp"), "GOCACHE=" + filepath.Join(envRoot, "gocache"), "PATH=" + os.Getenv("PATH"), "GOTOOLCHAIN=local"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		fatal("run pinned oracle: %v\n%s", err, stderr.String())
	}
	// Only canonicalize the generated sandbox; preserve all YAML values verbatim.
	normalized := bytes.ReplaceAll(stdout.Bytes(), []byte(envRoot), []byte("/fixture/root"))
	var cases []caseResult
	if err := json.Unmarshal(normalized, &cases); err != nil {
		fatal("decode oracle: %v\n%s", err, stderr.String())
	}
	return cases
}
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
