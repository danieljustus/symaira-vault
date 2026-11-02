package server

// PLATFORM-WIRE-001 provenance for testdata/port/mcp/copy-clipboard-linux.json.
//
// The Linux generator (mcp_copy_clipboard_linux_fixture_generator_test.go) only
// builds on GOOS=linux, and on a non-Linux host it runs in a container whose
// git cannot read a worktree checkout and whose Go is not the pinned toolchain.
// The oracle pin is therefore resolved here, without a build tag: on the host
// TestMCPCopyClipboardLinuxOraclePin verifies the pinned commit and writes the
// result to a file that the container generator reads; on a Linux host the
// generator resolves it directly.

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

const (
	copyClipboardLinuxOracleShort = "5229f949"
	copyClipboardLinuxOracleSHA   = "5229f9490cd25c22adb641677546a57802417304"
	// copyClipboardLinuxPinFileEnv names the JSON file the host pin test writes
	// and the container generator reads.
	copyClipboardLinuxPinFileEnv = "SYMAIRA_MCP_COPY_CLIPBOARD_LINUX_PIN_FILE"
)

// copyClipboardLinuxSourceFiles are the production Go files the Linux capture
// executes. Unlike copy-clipboard.json, go.mod and go.sum are part of the
// pinned comparison too: the capture is not separable from the atotto module.
var copyClipboardLinuxSourceFiles = []string{
	"go.mod",
	"go.sum",
	"internal/clipboard/clipboard.go",
	"internal/clipboard/clipboard_signal_unix.go",
	"internal/clipboard/interface.go",
	"internal/clipboard/provider.go",
	"internal/clipboard/system_clipboard.go",
	"internal/crypto/totp.go",
	"internal/mcp/server/server.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/tools_clipboard.go",
	"internal/mcp/server/tools_totp.go",
}

type copyClipboardLinuxPin struct {
	Commit     string `json:"commit"`
	CommitSHA  string `json:"commit_sha"`
	SourceHash string `json:"source_hash"`
}

// computeCopyClipboardLinuxPin proves the working-tree oracle sources equal the
// blobs of the pinned, reachable commit and returns the digest both share.
func computeCopyClipboardLinuxPin(t *testing.T, root string) copyClipboardLinuxPin {
	t.Helper()
	if os.Getenv("GOWORK") != "off" {
		t.Fatal("Linux clipboard oracle requires GOWORK=off")
	}
	if runtime.Version() != localMCPOracleGoVersion {
		t.Fatalf("Linux clipboard oracle requires %s, got %s", localMCPOracleGoVersion, runtime.Version())
	}
	cmd := exec.Command("git", "merge-base", "--is-ancestor", copyClipboardLinuxOracleSHA, "HEAD") // #nosec G204 -- fixed git operation over an immutable pin
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("oracle pin %s is not reachable from HEAD: %v\n%s", copyClipboardLinuxOracleSHA, err, strings.TrimSpace(string(out)))
	}
	pinned := executeAPIRequestGitDigest(t, root, copyClipboardLinuxOracleSHA, copyClipboardLinuxSourceFiles)
	working := executeAPIRequestWorkingDigest(t, root, copyClipboardLinuxSourceFiles)
	if pinned != working {
		t.Fatalf("Go production sources differ from pinned oracle %s: working %s, pinned %s", copyClipboardLinuxOracleShort, working, pinned)
	}
	return copyClipboardLinuxPin{Commit: copyClipboardLinuxOracleShort, CommitSHA: copyClipboardLinuxOracleSHA, SourceHash: pinned}
}

// resolveCopyClipboardLinuxPin is what the generator calls: it trusts the file
// written by the host pin test inside a container, and computes the pin itself
// everywhere else.
func resolveCopyClipboardLinuxPin(t *testing.T, root string) copyClipboardLinuxPin {
	t.Helper()
	path := os.Getenv(copyClipboardLinuxPinFileEnv)
	if path == "" {
		return computeCopyClipboardLinuxPin(t, root)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path chosen by the Makefile for this run
	if err != nil {
		t.Fatalf("read host-verified oracle pin: %v", err)
	}
	var pin copyClipboardLinuxPin
	if err := json.Unmarshal(raw, &pin); err != nil {
		t.Fatalf("decode host-verified oracle pin: %v", err)
	}
	if pin.CommitSHA != copyClipboardLinuxOracleSHA || pin.Commit != copyClipboardLinuxOracleShort {
		t.Fatalf("host-verified pin names %s, want %s", pin.CommitSHA, copyClipboardLinuxOracleSHA)
	}
	if working := executeAPIRequestWorkingDigest(t, root, copyClipboardLinuxSourceFiles); working != pin.SourceHash {
		t.Fatalf("working-tree sources (%s) differ from the host-verified pin digest (%s)", working, pin.SourceHash)
	}
	return pin
}

// TestMCPCopyClipboardLinuxOraclePin is the host half for non-Linux machines.
// It verifies the pin and writes it to the file named by
// SYMAIRA_MCP_COPY_CLIPBOARD_LINUX_PIN_FILE; without that variable it skips.
func TestMCPCopyClipboardLinuxOraclePin(t *testing.T) {
	path := os.Getenv(copyClipboardLinuxPinFileEnv)
	if path == "" {
		t.Skip("set " + copyClipboardLinuxPinFileEnv + " to verify the Linux clipboard oracle pin on the host")
	}
	pin := computeCopyClipboardLinuxPin(t, executeAPIRequestRepoRoot(t))
	data, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
