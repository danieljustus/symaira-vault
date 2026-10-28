// Command configoverridesgen freezes the actual root flag/environment path
// selection seam. Config.Load does not overlay arbitrary SYMVAULT_* fields.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	rootcmd "github.com/danieljustus/symaira-vault/cmd"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
	"github.com/spf13/pflag"
)

const oracleCommit = "314a25a5cdd2e90517bb55a90495d7b97f68c6df"
const config = "defaultProfile: primary\nvaultDir: ignored-file-dir\nprofiles:\n  primary:\n    vault: ~/primary\n  alternate:\n    vault: ~/alternate\n  empty:\n    vault: ''\n"

type observation struct {
	Path       string `json:"path"`
	ErrorClass string `json:"error_class"`
}
type vector struct {
	Name   string            `json:"name"`
	Args   []string          `json:"args"`
	Env    map[string]string `json:"env"`
	Config *string           `json:"config"`
	Result observation       `json:"result"`
}
type fixture struct {
	SchemaVersion int            `json:"schema_version"`
	Oracle        map[string]any `json:"oracle"`
	RootFlags     []string       `json:"root_flags"`
	Cases         []vector       `json:"cases"`
}

func inputs() []vector {
	var cases []vector
	add := func(name string, args []string, env map[string]string, document *string) {
		if args == nil {
			args = []string{}
		}
		if env == nil {
			env = map[string]string{}
		}
		cases = append(cases, vector{Name: name, Args: args, Env: env, Config: document})
	}
	doc := config
	add("defaults_no_file", nil, nil, nil)
	add("file_default_profile", nil, nil, &doc)
	empty := ""
	add("empty_file", nil, nil, &empty)
	for _, key := range []string{"SYMVAULT_VAULT", "SYMVAULT_PROFILE"} {
		for _, value := range []string{"", "   ", "\t\n"} {
			add(fmt.Sprintf("%s_empty_%d", key, len(cases)), nil, map[string]string{key: value}, &doc)
		}
	}
	for _, value := range []string{"~/env", " relative//env/../vault ", "~other", "false", "0"} {
		add(fmt.Sprintf("vault_env_%d", len(cases)), nil, map[string]string{"SYMVAULT_VAULT": value}, &doc)
	}
	for _, value := range []string{"alternate", " alternate ", "absent", "empty", "false"} {
		add("profile_env_"+strings.TrimSpace(value)+fmt.Sprint(len(cases)), nil, map[string]string{"SYMVAULT_PROFILE": value}, &doc)
	}
	add("env_vault_beats_profile_flag", []string{"--profile", "absent"}, map[string]string{"SYMVAULT_VAULT": "~/env"}, &doc)
	add("flag_vault_beats_both_envs", []string{"--vault", "~/flag", "--profile", "absent"}, map[string]string{"SYMVAULT_VAULT": "~/env", "SYMVAULT_PROFILE": "absent"}, &doc)
	for _, value := range []string{"", " ", "~/flag", "relative//a/../b", "~"} {
		add(fmt.Sprintf("vault_flag_%d", len(cases)), []string{"--vault=" + value}, map[string]string{"SYMVAULT_VAULT": "~/env"}, &doc)
	}
	for _, value := range []string{"", "   ", "primary", " primary ", "absent", "empty"} {
		add(fmt.Sprintf("profile_flag_%d", len(cases)), []string{"--profile=" + value}, map[string]string{"SYMVAULT_PROFILE": "alternate"}, &doc)
	}
	add("profile_without_file", nil, map[string]string{"SYMVAULT_PROFILE": "alternate"}, nil)
	for _, document := range []string{"defaultProfile: absent\n", "defaultProfile: empty\nprofiles:\n  empty: {vault: ''}\n", "sessionTimeout: -1s\n"} {
		d := document
		add(fmt.Sprintf("invalid_default_%d", len(cases)), nil, nil, &d)
		add(fmt.Sprintf("invalid_requested_%d", len(cases)), []string{"--profile=primary"}, nil, &d)
	}
	// No typed environment binding exists: these deliberately invalid values
	// must not reject or override the file. Empty versus absent stays visible.
	for _, key := range []string{"SYMVAULT_CONFIG", "SYMVAULT_SESSION_TIMEOUT", "SYMVAULT_USE_TOUCH_ID", "SYMVAULT_DEFAULT_PROFILE", "SYMVAULT_VAULT_DIR", "SYMVAULT_QUIET", "SYMVAULT_OUTPUT", "SYMVAULT_THEME"} {
		add("unbound_"+key, nil, map[string]string{key: "invalid-value"}, &doc)
	}
	for _, args := range [][]string{
		{"--config=missing.yaml"}, {"--vault"}, {"--profile"}, {"--quiet=invalid"}, {"--json=invalid"}, {"--no-pipe-warning=invalid"},
		{"--quiet"}, {"--json", "--output=text"}, {"--output=yaml"}, {"--no-pipe-warning"}, {"--color=never"}, {"--theme=highcontrast"},
	} {
		add(fmt.Sprintf("root_flags_%d", len(cases)), args, nil, &doc)
	}
	return cases
}

func probe(item vector) observation {
	root := rootcmd.NewRootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	if err := root.ParseFlags(item.Args); err != nil {
		return observation{ErrorClass: "flags"}
	}
	path, err := cli.VaultPath()
	if err != nil {
		text := err.Error()
		class := "profile"
		if strings.Contains(text, "cannot load config") {
			class = "config"
		}
		return observation{ErrorClass: class}
	}
	home := os.Getenv("HOME")
	if runtime.GOOS == "windows" {
		home = os.Getenv("USERPROFILE")
	}
	path = strings.ReplaceAll(path, home, "HOME")
	return observation{Path: filepath.ToSlash(path)}
}

func capture(item vector) (observation, error) {
	dir, err := os.MkdirTemp("", "cfg-overrides-")
	if err != nil {
		return observation{}, err
	}
	defer os.RemoveAll(dir)
	home := filepath.Join(dir, "home")
	if err = os.MkdirAll(home, 0700); err != nil {
		return observation{}, err
	}
	if item.Config != nil {
		parent := filepath.Join(home, ".config", "symaira-vault")
		if err = os.MkdirAll(parent, 0700); err != nil {
			return observation{}, err
		}
		if err = os.WriteFile(filepath.Join(parent, "config.yaml"), []byte(*item.Config), 0600); err != nil {
			return observation{}, err
		}
	}
	payload, _ := json.Marshal(item)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return observation{}, err
	}
	child := exec.CommandContext(ctx, exe, "--probe")
	child.Stdin = bytes.NewReader(payload)
	child.Dir = home
	child.Env = []string{"HOME=" + home, "USERPROFILE=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "XDG_DATA_HOME=" + filepath.Join(home, ".local", "share"), "XDG_CACHE_HOME=" + filepath.Join(home, ".cache"), "TMPDIR=" + dir, "TMP=" + dir, "TEMP=" + dir, "LANG=C", "TZ=UTC"}
	if system := os.Getenv("SystemRoot"); system != "" {
		child.Env = append(child.Env, "SystemRoot="+system)
	}
	keys := make([]string, 0, len(item.Env))
	for key := range item.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !strings.HasPrefix(key, "SYMVAULT_") {
			return observation{}, fmt.Errorf("reserved env %s", key)
		}
		child.Env = append(child.Env, key+"="+item.Env[key])
	}
	output, err := child.Output()
	if err != nil {
		return observation{}, fmt.Errorf("%s: %w", item.Name, err)
	}
	var result observation
	err = json.Unmarshal(output, &result)
	return result, err
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--probe" {
		var item vector
		if err := json.NewDecoder(os.Stdin).Decode(&item); err != nil {
			panic(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(probe(item)); err != nil {
			panic(err)
		}
		return
	}
	output := flag.String("output", "testdata/port/config/overrides.json", "fixture path")
	check := flag.Bool("check", false, "compare without writing")
	flag.Parse()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("configoverridesgen: source location unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../.."))
	sources := []string{"cmd/root.go", "internal/cli/cli.go", "internal/cli/vaultpath.go"}
	entries, err := os.ReadDir(filepath.Join(root, "internal/config"))
	must(err)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			sources = append(sources, "internal/config/"+entry.Name())
		}
	}
	sort.Strings(sources)
	resolved, err := provenance.Verify(root, oracleCommit, sources)
	must(err)
	must(exec.Command("git", "-C", root, "merge-base", "--is-ancestor", resolved, "HEAD").Run())
	digest, err := provenance.Digest(root, sources)
	must(err)
	gen, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/configoverridesgen/main.go"})
	must(err)
	rootCommand := rootcmd.NewRootCmd()
	var flags []string
	rootCommand.PersistentFlags().VisitAll(func(f *pflag.Flag) { flags = append(flags, f.Name) })
	sort.Strings(flags)
	data := fixture{SchemaVersion: 1, Oracle: map[string]any{"commit": resolved, "source_files": sources, "source_digest": digest, "generator_digest": gen}, RootFlags: flags, Cases: inputs()}
	for i := range data.Cases {
		data.Cases[i].Result, err = capture(data.Cases[i])
		must(err)
	}
	content, err := json.MarshalIndent(data, "", "  ")
	must(err)
	content = append(content, '\n')
	if *check {
		recorded, err := os.ReadFile(*output)
		must(err)
		if !bytes.Equal(content, recorded) {
			must(fmt.Errorf("override fixture drift: %s", *output))
		}
	} else {
		must(os.WriteFile(*output, content, 0600))
	}
	fmt.Printf("PASS CFG-002 overrides (%d cases)\n", len(data.Cases))
}
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
