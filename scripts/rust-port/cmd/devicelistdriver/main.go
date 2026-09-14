// devicelistdriver places the complete Python build-and-test driver inside the
// existing native process tree, including its bootstrap toolchain subprocesses.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/diff"
)

func run() error {
	report := flag.String("report", "", "fresh absolute evidence destination")
	flag.Parse()
	if *report == "" {
		return errors.New("report is required")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		return err
	}
	python, err = filepath.Abs(python)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cacheJSON, err := exec.Command("go", "env", "-json", "GOCACHE", "GOMODCACHE").Output()
	if err != nil {
		return fmt.Errorf("resolve Go build caches: %w", err)
	}
	var environment map[string]string
	if err := json.Unmarshal(cacheJSON, &environment); err != nil {
		return err
	}
	for key, fallback := range map[string]string{
		"CARGO_HOME":       filepath.Join(home, ".cargo"),
		"RUSTUP_HOME":      filepath.Join(home, ".rustup"),
		"CARGO_TARGET_DIR": filepath.Join(root, "target"),
	} {
		value := os.Getenv(key)
		if value == "" {
			value = fallback
		}
		environment[key] = value
	}
	environment["GOTOOLCHAIN"] = "go1.26.6"
	environment["RUSTUP_TOOLCHAIN"] = "1.98.0"
	environment["PYTHONDONTWRITEBYTECODE"] = "1"
	// Build discovery only; the inner CLI case runner does not inherit these.
	for _, key := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "VSINSTALLDIR", "VCINSTALLDIR", "VCToolsInstallDir", "WindowsSdkDir", "WindowsSDKVersion", "LIB", "LIBPATH", "INCLUDE"} {
		if value := os.Getenv(key); value != "" {
			environment[key] = value
		}
	}
	head, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	absoluteReport, err := filepath.Abs(*report)
	if err != nil {
		return err
	}
	result, err := diff.Run(python, diff.Case{
		ID:   "device-list-driver",
		Args: []string{filepath.Join(root, "scripts", "rust-port", "device_list_differential.py"), "--supervised", "--report", absoluteReport},
		Env:  environment, TimeoutMS: 1800000,
	})
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(result.Stdout); err != nil {
		return err
	}
	if _, err := os.Stderr.Write(result.Stderr); err != nil {
		return err
	}
	if result.TimedOut || result.Signal != "" || result.ExitCode != 0 {
		return fmt.Errorf("device-list driver failed: exit=%d signal=%q timeout=%t", result.ExitCode, result.Signal, result.TimedOut)
	}
	return validateReport(absoluteReport, strings.TrimSpace(string(head)))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
