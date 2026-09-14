package main

import (
	"encoding/json"
	"fmt"
	"os"

	config "github.com/danieljustus/symaira-vault/internal/config"
)

type caseResult struct {
	Name   string `json:"name"`
	Input  string `json:"input"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
	Panic  string `json:"panic,omitempty"`
}

type snapshot struct {
	DefaultProfile string                     `json:"default_profile"`
	Profiles       map[string]*config.Profile `json:"profiles"`
	Saved          string                     `json:"saved"`
}

func run(name, input string) (out caseResult) {
	out.Name, out.Input = name, input
	defer func() {
		if r := recover(); r != nil {
			out.Panic = fmt.Sprint(r)
		}
	}()
	path, err := os.CreateTemp("", "config-profile-*.yaml")
	if err != nil {
		out.Error = err.Error()
		return
	}
	defer os.Remove(path.Name())
	if _, err = path.WriteString(input); err != nil {
		out.Error = err.Error()
		return
	}
	path.Close()
	cfg, err := config.Load(path.Name())
	if err != nil {
		out.Error = err.Error()
		return
	}
	savedPath, err := os.CreateTemp("", "config-profile-saved-*.yaml")
	if err != nil {
		out.Error = err.Error()
		return
	}
	savedPath.Close()
	defer os.Remove(savedPath.Name())
	if err = cfg.SaveTo(savedPath.Name()); err != nil {
		out.Error = err.Error()
		return
	}
	saved, err := os.ReadFile(savedPath.Name())
	if err != nil {
		out.Error = err.Error()
		return
	}
	out.Result = snapshot{DefaultProfile: cfg.DefaultProfile, Profiles: cfg.Profiles, Saved: string(saved)}
	return
}

func main() {
	// Keep the oracle hermetic and deterministic; no real user paths are read.
	for key, value := range map[string]string {
		"HOME":            "/fixture/root/home",
		"USERPROFILE":     "/fixture/root/home",
		"XDG_CONFIG_HOME": "/fixture/root/config",
		"XDG_DATA_HOME":   "/tmp/config-profile-oracle/data",
		"XDG_CACHE_HOME":  "/fixture/root/cache",
	} {
		if err := os.Setenv(key, value); err != nil {
			panic(err)
		}
	}
	if err := os.MkdirAll("/tmp/config-profile-oracle/data/symaira-vault", 0o700); err != nil {
		panic(err)
	}
	cases := []struct{ name, input string }{
		{"profiles", "profiles:\n  work:\n    vault: ~/.symvault-work\n  family:\n    vault: ~/vaults/family\ndefaultProfile: work\n"},
		{"empty_path", "profiles:\n  empty:\n    vault: \"\"\n"},
		{"null_profiles", "profiles: null\ndefaultProfile: null\n"},
		{"null_profile", "profiles:\n  empty: null\n"},
		{"null_path", "profiles:\n  empty:\n    vault: null\n"},
		{"numeric_name", "profiles:\n  1:\n    vault: /tmp/vault\n"},
		{"numeric_path", "profiles:\n  bad:\n    vault: 1\n"},
	}
	results := make([]caseResult, 0, len(cases))
	for _, c := range cases {
		results = append(results, run(c.name, c.input))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		panic(err)
	}
}
