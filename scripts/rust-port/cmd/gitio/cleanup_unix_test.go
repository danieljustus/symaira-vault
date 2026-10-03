//go:build !windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestCleanupObservationRejectsLiveProcessAndAcceptsReapedProcess(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCleanupObservationChild$")
	cmd.Env = append(os.Environ(), "GITIO_CLEANUP_CHILD=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	pid := strconv.Itoa(cmd.Process.Pid)
	started := time.Now()
	if waitForProcessExit(pid, 80*time.Millisecond) {
		t.Fatal("live descendant was reported as cleaned up")
	}
	if time.Since(started) > time.Second {
		t.Fatal("cleanup observation exceeded its bound")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("terminated helper unexpectedly succeeded")
	}
	if !waitForProcessExit(pid, 80*time.Millisecond) {
		t.Fatal("reaped descendant was reported as live")
	}
}

func TestCleanupObservationChild(t *testing.T) {
	if os.Getenv("GITIO_CLEANUP_CHILD") == "1" {
		time.Sleep(10 * time.Second)
	}
}
