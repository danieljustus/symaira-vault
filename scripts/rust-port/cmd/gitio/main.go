// Command gitio freezes productive GIT-002 transport projections from Go.
package main

import (
	"bytes"
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

// oracleCommit is the immutable Go production revision whose internal/git
// blobs are used to generate this fixture. The fixture is regenerated only
// after deliberately advancing this pin when the production source changes.
const oracleCommit = "32566f057e60e830b9af0599f4398487fefeaa0f"
const oracleRelease = "unreleased"

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

func setupRemote(remoteURL string) string {
	dir, err := os.MkdirTemp("", "gitio-go-")
	fail(err)
	fail(git.Init(dir))
	fail(os.WriteFile(filepath.Join(dir, "entry.age"), []byte("fixture"), 0o600))
	fail(git.AutoCommit(dir, "fixture"))
	fail(git.AddRemote(dir, "origin", remoteURL))
	return dir
}

func errorClass(err error) string {
	if err == nil {
		return "success"
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "known_hosts"), strings.Contains(text, "known hosts"):
		return "ssh_configuration"
	case strings.Contains(text, "authentication"), strings.Contains(text, "credentials"), strings.Contains(text, "401"), strings.Contains(text, "403"):
		return "authentication"
	case strings.Contains(text, "timed out"), strings.Contains(text, "timeout"):
		return "timeout"
	case git.IsOfflineError(err):
		return "offline"
	default:
		return "other"
	}
}

func pullProjection(result git.PullResult) map[string]any {
	return map[string]any{
		"success":     result.Success,
		"skipped":     result.Skipped,
		"has_remote":  result.HasRemote,
		"error_class": errorClass(result.Error),
	}
}

func pushProjection(result git.PushResult) map[string]any {
	return map[string]any{
		"success":     result.Success,
		"skipped":     result.Skipped,
		"has_remote":  result.HasRemote,
		"error_class": errorClass(result.Error),
	}
}

func setGitConfig(dir, key, value string) {
	cmd := exec.Command("git", "-C", dir, "config", key, value)
	fail(cmd.Run())
}

func unixSSHFailureCase(id string, setup func(dir, marker string)) Case {
	if runtime.GOOS == "windows" {
		panic("gitio SSH oracle requires a native Unix runner")
	}
	dir := setupRemote("ssh://git@example.invalid/repo.git")
	defer os.RemoveAll(dir)
	marker := filepath.Join(dir, id+".marker")
	setup(dir, marker)
	oldSSH, hadSSH := os.LookupEnv("GIT_SSH_COMMAND")
	fail(os.Setenv("GIT_SSH_COMMAND", marker+".sh"))
	defer func() {
		if hadSSH {
			_ = os.Setenv("GIT_SSH_COMMAND", oldSSH)
		} else {
			_ = os.Unsetenv("GIT_SSH_COMMAND")
		}
	}()
	if id == "GIT-002-go-askpass" {
		oldAskpass, hadAskpass := os.LookupEnv("GIT_ASKPASS")
		oldPrompt, hadPrompt := os.LookupEnv("GIT_TERMINAL_PROMPT")
		fail(os.Setenv("GIT_ASKPASS", "/bin/false"))
		fail(os.Setenv("GIT_TERMINAL_PROMPT", "0"))
		defer func() {
			if hadAskpass {
				_ = os.Setenv("GIT_ASKPASS", oldAskpass)
			} else {
				_ = os.Unsetenv("GIT_ASKPASS")
			}
			if hadPrompt {
				_ = os.Setenv("GIT_TERMINAL_PROMPT", oldPrompt)
			} else {
				_ = os.Unsetenv("GIT_TERMINAL_PROMPT")
			}
		}()
	}
	result := git.PushWithResult(dir)
	projection := pushProjection(result)
	if id == "GIT-002-go-askpass" {
		observed, err := os.ReadFile(marker)
		if err != nil {
			panic(fmt.Sprintf("askpass marker missing after Go push (%v)", result.Error))
		}
		projection["observed"] = strings.TrimSpace(string(observed))
	}
	if id == "GIT-002-go-timeout" {
		pid, err := os.ReadFile(marker)
		fail(err)
		pidText := strings.TrimSpace(string(pid))
		cleaned := !processAlive(pidText)
		projection["timed_out"] = errorClass(result.Error) == "timeout"
		projection["descendant_cleanup"] = cleaned
		if !cleaned {
			_ = exec.Command("kill", "-KILL", pidText).Run()
		}
	}
	input := map[string]any{"remote": "ssh://git@example.invalid/repo.git"}
	if id == "GIT-002-go-askpass" {
		input["askpass_env"] = "inherited"
		input["terminal_prompt"] = "0"
	}
	if id == "GIT-002-go-timeout" {
		input["timeout_seconds"] = 20
	}
	return Case{
		ID:       id,
		Seam:     "GIT-002",
		Input:    input,
		Expected: projection,
	}
}

func processAlive(pid string) bool {
	return exec.Command("kill", "-0", pid).Run() == nil
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

	cases := []Case{
		{
			ID:       "GIT-002-go-offline",
			Seam:     "GIT-002",
			Input:    map[string]any{"remote": "http://127.0.0.1:1/unreachable.git"},
			Expected: pullProjection(offline),
		},
		{
			ID:       "GIT-002-go-auth",
			Seam:     "GIT-002",
			Input:    map[string]any{"status": http.StatusUnauthorized},
			Expected: pullProjection(auth),
		},
	}
	cases = append(cases,
		unixSSHFailureCase("GIT-002-go-ssh-precedence", func(dir, marker string) {
			helper := marker + ".sh"
			fail(os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' 'known_hosts: authentication failed: connection refused' >&2\nexit 1\n"), 0o700))
			setGitConfig(dir, "core.sshCommand", helper)
		}),
		unixSSHFailureCase("GIT-002-go-askpass", func(dir, marker string) {
			helper := marker + ".sh"
			body := fmt.Sprintf("#!/bin/sh\nprintf 'askpass=%%s\\nterminal_prompt=%%s\\n' \"${GIT_ASKPASS:+inherited}\" \"$GIT_TERMINAL_PROMPT\" > %s\nexit 1\n", marker)
			fail(os.WriteFile(helper, []byte(body), 0o700))
			setGitConfig(dir, "core.sshCommand", helper)
		}),
		unixSSHFailureCase("GIT-002-go-timeout", func(dir, marker string) {
			helper := marker + ".sh"
			body := fmt.Sprintf("#!/bin/sh\n(sleep 60) &\nprintf '%%s\\n' \"$!\" > %s\nwait\n", marker)
			fail(os.WriteFile(helper, []byte(body), 0o700))
			setGitConfig(dir, "core.sshCommand", helper)
		}),
	)
	return cases
}

func sourceFilesAtCommit(root, commit string) []string {
	out, err := exec.Command("git", "-C", root, "ls-tree", "-r", "--name-only", commit, "--", "internal/git").Output()
	fail(err)
	var files []string
	for _, name := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			files = append(files, filepath.ToSlash(name))
		}
	}
	sort.Strings(files)
	return files
}

func pinnedFile(root, commit, name string) []byte {
	out, err := exec.Command("git", "-C", root, "show", commit+":"+name).Output()
	fail(err)
	return out
}

func pinnedSourceDigest(root, commit string, files []string) string {
	var all []byte
	for _, name := range files {
		current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		fail(err)
		pinned := pinnedFile(root, commit, name)
		if !bytes.Equal(current, pinned) {
			panic(fmt.Sprintf("working-tree source differs from pinned Go oracle: %s", name))
		}
		all = append(all, []byte(name)...)
		all = append(all, 0)
		all = append(all, pinned...)
		all = append(all, 0)
	}
	return hash(all)
}

func metadata(root string) Oracle {
	files := sourceFiles(root)
	pinned := sourceFilesAtCommit(root, oracleCommit)
	if strings.Join(files, "\n") != strings.Join(pinned, "\n") {
		panic("working-tree internal/git file set differs from pinned Go oracle")
	}
	generator := "scripts/rust-port/cmd/gitio/main.go"
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(generator)))
	fail(err)
	return Oracle{
		Commit:          oracleCommit,
		Release:         oracleRelease,
		SourceFiles:     files,
		SourceDigest:    pinnedSourceDigest(root, oracleCommit, files),
		Generator:       generator,
		GeneratorDigest: hash(data),
	}
}

func main() {
	output := flag.String("output", "testdata/port/sync/git-io.json", "fixture path")
	check := flag.Bool("check", false, "verify fixture")
	flag.Parse()
	root := rootDir()
	path := filepath.Join(root, filepath.FromSlash(*output))
	meta := metadata(root)
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
