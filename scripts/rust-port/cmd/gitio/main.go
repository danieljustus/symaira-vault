// Command gitio freezes productive GIT-002 transport projections from Go.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/git"
)

type Oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	Generator       string   `json:"generator"`
	GeneratorDigest string   `json:"generator_digest"`
}
type Case struct {
	ID       string         `json:"id"`
	Seam     string         `json:"seam"`
	Input    map[string]any `json:"input"`
	Expected map[string]any `json:"expected"`
}
type Fixture struct {
	SchemaVersion int    `json:"schema_version"`
	Oracle        Oracle `json:"oracle"`
	Cases         []Case `json:"cases"`
}

func fail(err error) {
	if err != nil {
		panic(err)
	}
}

func hash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate gitio")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	fail(err)
	return root
}

func sourceFiles(root string) []string {
	var files []string
	fail(filepath.Walk(filepath.Join(root, "internal", "git"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	}))
	sort.Strings(files)
	return files
}

func digestFiles(root string, files []string) string {
	var all []byte
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		fail(err)
		all = append(all, []byte(name)...)
		all = append(all, 0)
		all = append(all, data...)
		all = append(all, 0)
	}
	return hash(all)
}

func gitCommit(root string) string {
	out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	fail(err)
	return strings.TrimSpace(string(out))
}

func setupRemote(remoteURL string) string {
	dir, err := os.MkdirTemp("", "gitio-go-")
	fail(err)
	fail(git.Init(dir))
	fail(os.WriteFile(filepath.Join(dir, "entry.age"), []byte("fixture"), 0o600))
	fail(git.AutoCommit(dir, "fixture"))
	fail(git.AddRemote(dir, "origin", remoteURL))
	return dir
}

func classify(result git.PullResult) string {
	if result.Error == nil {
		return "success"
	}
	if git.IsOfflineError(result.Error) {
		return "offline"
	}
	text := strings.ToLower(result.Error.Error())
	if strings.Contains(text, "authentication") || strings.Contains(text, "credentials") || strings.Contains(text, "401") || strings.Contains(text, "403") {
		return "authentication"
	}
	return "other"
}

func transportCases() []Case {
	offlineDir := setupRemote("http://127.0.0.1:1/unreachable.git")
	defer os.RemoveAll(offlineDir)
	offline := git.PullWithResult(offlineDir)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	authDir := setupRemote(server.URL + "/repo.git")
	defer os.RemoveAll(authDir)
	auth := git.PullWithResult(authDir)

	return []Case{
		{
			ID:       "GIT-002-go-offline",
			Seam:     "GIT-002",
			Input:    map[string]any{"remote": "http://127.0.0.1:1/unreachable.git"},
			Expected: map[string]any{"success": offline.Success, "skipped": offline.Skipped, "error_class": classify(offline)},
		},
		{
			ID:       "GIT-002-go-auth",
			Seam:     "GIT-002",
			Input:    map[string]any{"status": http.StatusUnauthorized},
			Expected: map[string]any{"success": auth.Success, "skipped": auth.Skipped, "error_class": classify(auth)},
		},
		{
			ID:       "GIT-002-rust-process-contract",
			Seam:     "GIT-002",
			Input:    map[string]any{"timeout_seconds": 20, "terminal_prompt": "0", "passphrase_env": "removed"},
			Expected: map[string]any{"askpass": "inherited", "descendant_cleanup": "process-group"},
		},
	}
}

func metadata(root, commit string) Oracle {
	files := sourceFiles(root)
	generator := "scripts/rust-port/cmd/gitio/main.go"
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(generator)))
	fail(err)
	return Oracle{
		Commit: commit, Release: "working-tree", SourceFiles: files,
		SourceDigest: digestFiles(root, files), Generator: generator,
		GeneratorDigest: hash(data),
	}
}

func main() {
	output := flag.String("output", "testdata/port/sync/git-io.json", "fixture path")
	check := flag.Bool("check", false, "verify fixture")
	flag.Parse()
	root := rootDir()
	path := filepath.Join(root, filepath.FromSlash(*output))
	commit := gitCommit(root)
	if *check {
		existing, err := os.ReadFile(path)
		fail(err)
		var previous Fixture
		fail(json.Unmarshal(existing, &previous))
		if previous.Oracle.Commit == "" {
			panic("fixture has no oracle commit")
		}
		// Keep the generation revision stable across the commit that records
		// the fixture. Source and generator digests still detect content drift.
		commit = previous.Oracle.Commit
	}
	meta := metadata(root, commit)
	fixture := Fixture{SchemaVersion: 1, Oracle: meta, Cases: transportCases()}
	data, err := json.MarshalIndent(fixture, "", "  ")
	fail(err)
	data = append(data, '\n')
	if *check {
		existing, err := os.ReadFile(path)
		fail(err)
		if string(existing) != string(data) {
			panic(fmt.Errorf("%s is stale; regenerate from the Go oracle", *output))
		}
		fmt.Printf("PASS Go git IO fixture (%d cases)\n", len(fixture.Cases))
		return
	}
	fail(os.MkdirAll(filepath.Dir(path), 0o750))
	fail(os.WriteFile(path, data, 0o600))
	fmt.Printf("WROTE %s\n", *output)
}
