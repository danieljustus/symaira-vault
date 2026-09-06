//go:build !windows

package diff

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestBuildManifestNormalizesInternalAbsoluteSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	entries, err := buildManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Path == "link" && entry.LinkTarget == "<SANDBOX>/target" {
			return
		}
	}
	t.Fatalf("normalized symlink missing: %#v", entries)
}

func TestRunTimeoutKillsDescendantProcessGroup(t *testing.T) {
	caseSpec := Case{
		ID:        "timeout-child",
		Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_HELPER_MODE": "child"},
		TimeoutMS: 100,
	}
	result, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut {
		t.Fatal("expected process timeout")
	}
	if result.Signal == "" {
		t.Fatal("expected terminating signal to be captured")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(result.Stdout)))
	if err != nil {
		t.Fatalf("parse helper child PID: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		err = syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant process %d survived group termination: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUnixProcessTreeLifecycle(t *testing.T) {
	cmd := exec.Command("true")
	tree, err := newProcessTree(cmd)
	if err != nil {
		t.Fatalf("newProcessTree: %v", err)
	}
	if err := tree.Assign(); err != nil {
		t.Fatalf("tree.Assign: %v", err)
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("tree.Close: %v", err)
	}
}

func TestUnixProcessTreeKillReportsEffectiveAndAlreadyGone(t *testing.T) {
	activeCmd := exec.Command("sleep", "30")
	activeTree, err := newProcessTree(activeCmd)
	if err != nil {
		t.Fatalf("newProcessTree active: %v", err)
	}
	if err := activeCmd.Start(); err != nil {
		t.Fatalf("activeCmd.Start: %v", err)
	}
	if err := activeTree.Assign(); err != nil {
		t.Fatalf("activeTree.Assign: %v", err)
	}
	effective, err := activeTree.Kill()
	if err != nil {
		t.Fatalf("activeTree.Kill: %v", err)
	}
	if !effective {
		t.Fatal("activeTree.Kill reported no effective termination")
	}
	_ = activeCmd.Wait()
	if err := activeTree.Close(); err != nil {
		t.Fatalf("activeTree.Close: %v", err)
	}

	goneCmd := exec.Command("true")
	goneTree, err := newProcessTree(goneCmd)
	if err != nil {
		t.Fatalf("newProcessTree gone: %v", err)
	}
	if err := goneCmd.Start(); err != nil {
		t.Fatalf("goneCmd.Start: %v", err)
	}
	if err := goneTree.Assign(); err != nil {
		t.Fatalf("goneTree.Assign: %v", err)
	}
	if err := goneCmd.Wait(); err != nil {
		t.Fatalf("goneCmd.Wait: %v", err)
	}
	effective, err = goneTree.Kill()
	if err != nil {
		t.Fatalf("goneTree.Kill: %v", err)
	}
	if effective {
		t.Fatal("goneTree.Kill reported effective termination after natural exit")
	}
}
