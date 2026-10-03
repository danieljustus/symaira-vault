package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCheckFixtureRejectsDriftWithoutRewriting(t *testing.T) {
	root := rootDir()
	want, err := generated(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "store004_manifest_failure.json")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	mutated := append([]byte(nil), original...)
	mutated[len(mutated)-2] ^= 1
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := checkFixture(root, path); err == nil {
		t.Fatal("check accepted modified fixture")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, before) {
		t.Fatal("check rewrote modified fixture")
	}
}

func TestCheckFixtureRejectsProcessGroupSourceDrift(t *testing.T) {
	if os.Getenv("SYMVAULT_TEST_STORE004_PAUSE_AFTER_DRIFT") == "1" {
		previous := oracleContext
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		oracleContext = ctx
		t.Cleanup(func() { stop(); oracleContext = previous })
	}
	root := filepath.Join(t.TempDir(), "repo")
	if output, err := exec.Command("git", "clone", "--shared", "--no-checkout", rootDir(), root).CombinedOutput(); err != nil {
		t.Fatalf("clone oracle repository: %v: %s", err, output)
	}
	for _, name := range generatorFiles {
		data, err := os.ReadFile(filepath.Join(rootDir(), name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixture := filepath.Join(root, "fixture.json")
	want, err := os.ReadFile(filepath.Join(rootDir(), "testdata/port/store/store004_manifest_failure.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkFixture(root, fixture); err != nil {
		t.Fatalf("check rejected unchanged isolated fixture: %v", err)
	}
	source := filepath.Join(root, "scripts/rust-port/cmd/store004gen/process_group_unix.go")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, append(original, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	tracked, err := os.ReadFile(filepath.Join(rootDir(), "scripts/rust-port/cmd/store004gen/process_group_unix.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tracked, original) {
		t.Fatal("drift check modified tracked repository source")
	}
	// Let the external cancellation probe stop here without relying on timing.
	if os.Getenv("SYMVAULT_TEST_STORE004_PAUSE_AFTER_DRIFT") == "1" {
		t.Log("STORE004_ISOLATED_DRIFT_READY")
		select {}
	}
	if err := checkFixture(root, fixture); err == nil {
		t.Fatal("check accepted process-group source drift")
	}
}

func TestExtractAcceptsGitArchivePAXMetadataOnly(t *testing.T) {
	tree, err := extract(rootDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tree) })
	if _, err := os.Stat(filepath.Join(tree, "pax_global_header")); !os.IsNotExist(err) {
		t.Fatalf("git archive metadata was materialized: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tree, "internal", "vault", "manifest.go")); err != nil {
		t.Fatalf("real git archive source missing: %v", err)
	}
}

func TestIsolatedEnvironmentExcludesCredentialsAndXDG(t *testing.T) {
	t.Setenv("PATH", "/safe/path")
	t.Setenv("AWS_ACCESS_KEY_ID", "must-not-forward")
	t.Setenv("XDG_CONFIG_HOME", "/real/config")
	t.Setenv("GOPROXY", "https://proxy.golang.org")
	env := isolatedEnvironment("/safe/go", "/fresh/home", "/fresh/tmp")
	got := make(map[string]string, len(env))
	for _, item := range env {
		for i := 0; i < len(item); i++ {
			if item[i] == '=' {
				got[item[:i]] = item[i+1:]
				break
			}
		}
	}
	if _, ok := got["AWS_ACCESS_KEY_ID"]; ok {
		t.Fatal("credential environment variable was forwarded")
	}
	if _, ok := got["XDG_CONFIG_HOME"]; ok {
		t.Fatal("XDG environment variable was forwarded")
	}
	if got["HOME"] != "/fresh/home" || got["TMPDIR"] != "/fresh/tmp" || got["GOTOOLCHAIN"] != "local" {
		t.Fatalf("isolated runtime overrides missing: %#v", got)
	}
	// Windows resolves the default GOPATH from USERPROFILE and temporary
	// directories from TMP/TEMP. They must point at the isolated directories,
	// never at the real profile.
	if got["USERPROFILE"] != "/fresh/home" {
		t.Fatalf("USERPROFILE is not the isolated home: %#v", got)
	}
	if got["TMP"] != "/fresh/tmp" || got["TEMP"] != "/fresh/tmp" {
		t.Fatalf("TMP/TEMP are not the isolated temporary directory: %#v", got)
	}
}

func TestRunOracleTimeoutCleansProcessGroup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("descendant cleanup proof is Unix-specific")
	}
	for _, parentCancel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent-cancel=%t", parentCancel), func(t *testing.T) {
			stubDir := t.TempDir()
			goStub := filepath.Join(stubDir, "go-stub")
			readyPath := filepath.Join(stubDir, "descendant-ready")
			if err := os.WriteFile(goStub, []byte(fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'go version go1.26.6 darwin/arm64'; exit 0; fi\n(trap '' TERM INT; while :; do sleep 60; done) &\nchild=$!\nprintf '%%s\\n' \"$child\" > %q\nwait \"$child\"\n", readyPath)), 0o700); err != nil {
				t.Fatal(err)
			}
			oldGo, oldTimeout := goExecutable, oracleTimeout
			oldContext := oracleContext
			ctx, cancel := context.WithCancel(context.Background())
			oracleContext = ctx
			goExecutable, oracleTimeout = goStub, 100*time.Millisecond
			if parentCancel {
				oracleTimeout = 2 * time.Minute
			}
			t.Cleanup(func() { cancel(); oracleContext = oldContext; goExecutable, oracleTimeout = oldGo, oldTimeout })

			started := time.Now()
			result := make(chan error, 1)
			go func() {
				_, err := runOracle(rootDir(), false)
				result <- err
			}()

			var descendantPID int
			readyDeadline := time.NewTimer(5 * time.Second)
			readyTicker := time.NewTicker(10 * time.Millisecond)
			for descendantPID == 0 {
				select {
				case <-readyTicker.C:
					data, err := os.ReadFile(readyPath)
					if err != nil {
						continue
					}
					pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
					if err != nil || pid <= 0 {
						t.Fatalf("invalid descendant readiness PID %q: %v", data, err)
					}
					descendantPID = pid
				case <-readyDeadline.C:
					t.Fatal("timeout stub did not signal descendant readiness")
				}
			}
			readyTicker.Stop()
			if parentCancel {
				cancel()
			}
			if !readyDeadline.Stop() {
				<-readyDeadline.C
			}

			select {
			case err := <-result:
				if err == nil {
					t.Fatal("timeout stub unexpectedly succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runOracle did not return within cleanup bound")
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("timeout cleanup exceeded bound: %v", elapsed)
			}

			goneDeadline := time.NewTimer(2 * time.Second)
			goneTicker := time.NewTicker(10 * time.Millisecond)
			defer goneDeadline.Stop()
			defer goneTicker.Stop()
			for {
				if err := exec.Command("kill", "-0", strconv.Itoa(descendantPID)).Run(); err != nil {
					return
				}
				select {
				case <-goneTicker.C:
				case <-goneDeadline.C:
					t.Fatalf("descendant PID %d survived process-group cleanup", descendantPID)
				}
			}
		})
	}
}
