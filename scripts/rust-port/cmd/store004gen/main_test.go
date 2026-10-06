package main

import (
	"bytes"
	"context"
	"errors"
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
	if err := checkFixture(root, path); err != nil {
		t.Fatalf("check rejected unchanged fixture: %v", err)
	}
	original, _ := os.ReadFile(path)
	mutated := bytes.Replace(original, []byte(`"entry_exists": true`), []byte(`"entry_exists": false`), 1)
	if bytes.Equal(mutated, original) {
		t.Fatal("fixture mutation did not change the frozen outcome")
	}
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := checkFixture(root, path); err == nil || err.Error() != "fixture differs from regenerated oracle" {
		t.Fatalf("fixture mutation rejection = %v", err)
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
	mutated := bytes.Replace(original, []byte("syscall.SIGKILL"), []byte("syscall.SIGTERM"), 1)
	if bytes.Equal(mutated, original) {
		t.Fatal("source mutation did not change process termination")
	}
	if err := os.WriteFile(source, mutated, 0o600); err != nil {
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
	if err := checkFixture(root, fixture); err == nil || err.Error() != "fixture differs from regenerated oracle" {
		t.Fatalf("source mutation rejection = %v", err)
	}
	after, err := os.ReadFile(fixture)
	if err != nil || !bytes.Equal(after, want) {
		t.Fatalf("source drift check rewrote fixture: %v", err)
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
			// Publish the deepest descendant only after it exists, via an atomic
			// rename. Reading a partially written PID used to fail this test and
			// restore globals while the oracle goroutine was still running.
			if err := os.WriteFile(goStub, []byte(fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'go version go1.26.6'; exit 0; fi\n(trap '' TERM INT; sleep 60 &\nleaf=$!\nprintf '%%s\\n' \"$leaf\" > %q\nmv %q %q\nwait \"$leaf\") &\nwait \"$!\"\n", readyPath+".tmp", readyPath+".tmp", readyPath)), 0o700); err != nil {
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
			joined := false
			go func() {
				_, err := runOracle(rootDir(), false)
				result <- err
			}()
			t.Cleanup(func() {
				cancel()
				if !joined {
					select {
					case <-result:
					case <-time.After(5 * time.Second):
						t.Error("oracle did not join before restoring test globals")
					}
				}
			})

			var descendantPID int
			readyDeadline := time.NewTimer(5 * time.Second)
			readyTicker := time.NewTicker(10 * time.Millisecond)
			defer readyDeadline.Stop()
			defer readyTicker.Stop()
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
			readyDeadline.Stop()

			select {
			case err := <-result:
				joined = true
				want := context.DeadlineExceeded
				if parentCancel {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					t.Fatalf("oracle error = %v, want %v", err, want)
				}
			case <-time.After(5 * time.Second):
				stacks := make([]byte, 1<<20)
				stacks = stacks[:runtime.Stack(stacks, true)]
				state, stateErr := exec.Command("ps", "-o", "pid,ppid,pgid,state", "-p", strconv.Itoa(descendantPID)).CombinedOutput()
				t.Fatalf("runOracle did not return within cleanup bound; descendant state: %s (%v)\n%s", state, stateErr, stacks)
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

// Reap the leader before cancellation while a separately owned process retains
// its output handles. This makes the observed blocked pipe join deterministic;
// it does not assert which process retained the hosted failure's pipes.
func TestRunOracleCancellationJoinsInheritedPipes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("separate Unix process-group pipe holder; Windows job ownership is tested separately")
	}
	root := t.TempDir()
	ready, stub := filepath.Join(root, "holder.pid"), filepath.Join(root, "go-stub")
	script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'go version go1.26.6'; exit 0; fi\nexec %q -test.run='^TestStore004InheritedPipeHelper$' -- leader %q\n", os.Args[0], ready)
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	oldGo, oldTimeout, oldContext := goExecutable, oracleTimeout, oracleContext
	ctx, cancel := context.WithCancel(context.Background())
	goExecutable, oracleTimeout, oracleContext = stub, 2*time.Minute, ctx
	result := make(chan error, 1)
	go func() { _, err := runOracle(rootDir(), false); result <- err }()
	var holderPID, leaderPID int
	joined := false
	t.Cleanup(func() {
		cancel()
		if holderPID > 0 {
			if output, err := exec.Command("kill", "-KILL", strconv.Itoa(holderPID)).CombinedOutput(); err != nil {
				t.Errorf("kill test-owned pipe holder: %v: %s", err, output)
			}
		}
		if !joined {
			select {
			case <-result:
			case <-time.After(5 * time.Second):
				t.Error("oracle did not join after releasing test-owned pipes")
			}
		}
		goExecutable, oracleTimeout, oracleContext = oldGo, oldTimeout, oldContext
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if holderPID == 0 {
			if data, err := os.ReadFile(ready); err == nil {
				if _, err = fmt.Sscanf(string(data), "%d %d", &holderPID, &leaderPID); err != nil || holderPID <= 0 || leaderPID <= 0 {
					t.Fatalf("invalid holder readiness: %q: %v", data, err)
				}
			}
		}
		// A missing leader proves Process.Wait has reaped it before cancel.
		if leaderPID > 0 && exec.Command("kill", "-0", strconv.Itoa(leaderPID)).Run() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if leaderPID == 0 || exec.Command("kill", "-0", strconv.Itoa(leaderPID)).Run() == nil {
		t.Fatal("holder and reaped leader did not reach readiness")
	}
	cancel()
	select {
	case err := <-result:
		joined = true
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("oracle cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("oracle did not join inherited pipes within cleanup bound")
	}
	stacks := make([]byte, 1<<20)
	stacks = stacks[:runtime.Stack(stacks, true)]
	if bytes.Contains(stacks, []byte("os/exec.(*Cmd).awaitGoroutines")) || bytes.Contains(stacks, []byte("os/exec.(*Cmd).writerDescriptor.func")) {
		t.Fatalf("oracle returned with unjoined process I/O goroutines:\n%s", stacks)
	}
}

func TestStore004InheritedPipeHelper(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "--" {
		return
	}
	mode, ready := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	if mode == "holder" {
		data := []byte(fmt.Sprintf("%d %d", os.Getpid(), os.Getppid()))
		if err := os.WriteFile(ready+".tmp", data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(ready+".tmp", ready); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Minute)
		}
	}
	if mode != "leader" {
		t.Fatalf("unknown helper mode: %s", mode)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestStore004InheritedPipeHelper$", "--", "holder", ready)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	configureProcessGroup(child)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	// The test owns the separate group. Keep the leader until the original PPID
	// is published, then exit without closing the holder's inherited handles.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	t.Fatal("holder failed to publish readiness")
}
