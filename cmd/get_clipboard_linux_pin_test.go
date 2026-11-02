package cmd

// PLATFORM-WIRE-001 provenance for testdata/port/platform/get_clipboard_linux.json.
//
// The Linux generator (get_clipboard_linux_fixture_generator_test.go) only
// builds on GOOS=linux, and on a non-Linux host it runs in a container whose
// git cannot read a worktree checkout and whose Go is not the pinned toolchain.
// The oracle pin is therefore resolved here, without a build tag: on the host
// TestGetClipboardLinuxOraclePin verifies the pinned commit and writes the
// result to a file that the container generator reads; on a Linux host the
// generator resolves it directly.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	getClipboardLinuxOracleShort = "5229f949"
	getClipboardLinuxOracleSHA   = "5229f9490cd25c22adb641677546a57802417304"
	getClipboardLinuxGoVersion   = "go1.26.6"
	// getClipboardLinuxPinFileEnv names the JSON file the host pin test writes
	// and the container generator reads.
	getClipboardLinuxPinFileEnv = "SYMVAULT_GET_CLIPBOARD_LINUX_PIN_FILE"
)

// getClipboardLinuxSourceFiles are the production Go files the Linux capture
// executes; go.mod and go.sum are part of the pinned comparison because the
// capture is not separable from the atotto module.
var getClipboardLinuxSourceFiles = []string{
	"go.mod",
	"go.sum",
	"cmd/crud/get.go",
	"internal/clipboard/clipboard.go",
	"internal/clipboard/clipboard_signal_unix.go",
	"internal/clipboard/interface.go",
	"internal/clipboard/provider.go",
	"internal/clipboard/system_clipboard.go",
	"internal/ui/cliout/cliout.go",
}

type getClipboardLinuxPin struct {
	Commit     string `json:"commit"`
	CommitSHA  string `json:"commit_sha"`
	SourceHash string `json:"source_hash"`
}

func getClipboardLinuxWorkingDigest(t *testing.T, root string, files []string) string {
	t.Helper()
	h := sha256.New()
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- fixed compiled-in source list
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func getClipboardLinuxGitDigest(t *testing.T, root, commit string, files []string) string {
	t.Helper()
	h := sha256.New()
	for _, name := range files {
		show := exec.Command("git", "show", commit+":"+name) // #nosec G204 -- fixed git operation over compiled-in source paths and an immutable pin
		show.Dir = root
		data, err := show.Output()
		if err != nil {
			t.Fatalf("read pinned source blob %s:%s: %v", commit, name, err)
		}
		fmt.Fprintf(h, "%s\x00", name)
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// computeGetClipboardLinuxPin proves the working-tree oracle sources equal the
// blobs of the pinned, reachable commit and returns the digest both share.
func computeGetClipboardLinuxPin(t *testing.T, root string) getClipboardLinuxPin {
	t.Helper()
	if os.Getenv("GOWORK") != "off" {
		t.Fatal("Linux clipboard oracle requires GOWORK=off")
	}
	if runtime.Version() != getClipboardLinuxGoVersion {
		t.Fatalf("Linux clipboard oracle requires %s, got %s", getClipboardLinuxGoVersion, runtime.Version())
	}
	cmd := exec.Command("git", "merge-base", "--is-ancestor", getClipboardLinuxOracleSHA, "HEAD") // #nosec G204 -- fixed git operation over an immutable pin
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("oracle pin %s is not reachable from HEAD: %v\n%s", getClipboardLinuxOracleSHA, err, strings.TrimSpace(string(out)))
	}
	pinned := getClipboardLinuxGitDigest(t, root, getClipboardLinuxOracleSHA, getClipboardLinuxSourceFiles)
	working := getClipboardLinuxWorkingDigest(t, root, getClipboardLinuxSourceFiles)
	if pinned != working {
		t.Fatalf("Go production sources differ from pinned oracle %s: working %s, pinned %s", getClipboardLinuxOracleShort, working, pinned)
	}
	return getClipboardLinuxPin{Commit: getClipboardLinuxOracleShort, CommitSHA: getClipboardLinuxOracleSHA, SourceHash: pinned}
}

// resolveGetClipboardLinuxPin is what the generator calls: it trusts the file
// written by the host pin test inside a container, and computes the pin itself
// everywhere else.
func resolveGetClipboardLinuxPin(t *testing.T, root string) getClipboardLinuxPin {
	t.Helper()
	path := os.Getenv(getClipboardLinuxPinFileEnv)
	if path == "" {
		return computeGetClipboardLinuxPin(t, root)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path chosen by the Makefile for this run
	if err != nil {
		t.Fatalf("read host-verified oracle pin: %v", err)
	}
	var pin getClipboardLinuxPin
	if err := json.Unmarshal(raw, &pin); err != nil {
		t.Fatalf("decode host-verified oracle pin: %v", err)
	}
	if pin.CommitSHA != getClipboardLinuxOracleSHA || pin.Commit != getClipboardLinuxOracleShort {
		t.Fatalf("host-verified pin names %s, want %s", pin.CommitSHA, getClipboardLinuxOracleSHA)
	}
	if working := getClipboardLinuxWorkingDigest(t, root, getClipboardLinuxSourceFiles); working != pin.SourceHash {
		t.Fatalf("working-tree sources (%s) differ from the host-verified pin digest (%s)", working, pin.SourceHash)
	}
	return pin
}

// TestGetClipboardLinuxOraclePin is the host half for non-Linux machines. It
// verifies the pin and writes it to the file named by
// SYMVAULT_GET_CLIPBOARD_LINUX_PIN_FILE; without that variable it skips.
func TestGetClipboardLinuxOraclePin(t *testing.T) {
	path := os.Getenv(getClipboardLinuxPinFileEnv)
	if path == "" {
		t.Skip("set " + getClipboardLinuxPinFileEnv + " to verify the Linux clipboard oracle pin on the host")
	}
	data, err := json.Marshal(computeGetClipboardLinuxPin(t, ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
