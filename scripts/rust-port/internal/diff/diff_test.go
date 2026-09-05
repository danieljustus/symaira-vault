package diff

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRunAndCompareIdenticalHelper(t *testing.T) {
	if os.Getenv("SYMVAULT_PORT_HELPER") == "1" {
		helperProcess()
		return
	}
	caseSpec := Case{
		ID:           "helper",
		Args:         []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:          map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_OUTPUT": "${WORKSPACE}/out.txt"},
		CompareFiles: true,
	}
	left, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	if err := Compare(caseSpec, left, right); err != nil {
		t.Fatal(err)
	}
}

func TestCompareDetectsStreamMismatchWithoutLeakingContent(t *testing.T) {
	testCase := Case{ID: "mismatch"}
	err := Compare(testCase, Result{Stdout: []byte("secret-left")}, Result{Stdout: []byte("secret-right")})
	if err == nil {
		t.Fatal("expected mismatch")
	}
	if got := err.Error(); contains(got, "secret-left") || contains(got, "secret-right") {
		t.Fatalf("mismatch exposed stream content: %s", got)
	}
}

func TestRunTimesOutAndTerminatesProcess(t *testing.T) {
	caseSpec := Case{
		ID:        "timeout",
		Args:      []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:       map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_HELPER_MODE": "hang"},
		TimeoutMS: 50,
	}
	result, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut {
		t.Fatal("expected process timeout")
	}
}

func TestRunCapturesSideEffectsOutsideWorkspace(t *testing.T) {
	caseSpec := Case{
		ID:   "home-side-effect",
		Args: []string{"-test.run=TestRunAndCompareIdenticalHelper"},
		Env:  map[string]string{"SYMVAULT_PORT_HELPER": "1", "PORT_OUTPUT": "${HOME}/out.txt"},
	}
	result, err := Run(os.Args[0], caseSpec)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Files {
		if entry.Path == "home/out.txt" && entry.Type == "file" {
			return
		}
	}
	t.Fatalf("HOME side effect missing from sandbox manifest: %#v", result.Files)
}

func TestConsoleComparisonNormalizesRootsAndCRLF(t *testing.T) {
	testCase := Case{StdoutMode: "console_text"}
	left := Result{Stdout: []byte("path=/tmp/left/file\r\n"), SandboxRoot: "/tmp/left"}
	right := Result{Stdout: []byte("path=/tmp/right/file\n"), SandboxRoot: "/tmp/right"}
	if err := Compare(testCase, left, right); err != nil {
		t.Fatal(err)
	}
}

func TestBuildManifestIsDeterministicAndDetectsContent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "entry"), []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := buildManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("manifest is not deterministic: %#v != %#v", first, second)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "entry"), []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := buildManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(first, changed) {
		t.Fatal("manifest did not detect content change")
	}
}

func TestSafeWorkspacePathRejectsEscape(t *testing.T) {
	if _, err := safeWorkspacePath(t.TempDir(), "../escape"); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestIsolatedEnvRejectsSandboxAndKeyringOverrides(t *testing.T) {
	replacements := map[string]string{"${HOME}": "/isolated/home"}
	for _, key := range []string{"HOME", "xdg_data_home", "TMPDIR", "SYMVAULT_TEST_KEYRING", "SYMVAULT_SECUREUI"} {
		_, err := isolatedEnv("/isolated/home", "/isolated/tmp", "/isolated/runtime", "/isolated/state", map[string]string{key: "host-value"}, replacements)
		if err == nil {
			t.Fatalf("expected override %q to be rejected", key)
		}
	}
}

func helperProcess() {
	switch os.Getenv("PORT_HELPER_MODE") {
	case "hang":
		time.Sleep(30 * time.Second)
		return
	case "child":
		child := exec.Command("sleep", "30")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintf(os.Stdout, "%d\n", child.Process.Pid)
		_ = child.Wait()
		return
	}
	path := os.Getenv("PORT_OUTPUT")
	_ = os.WriteFile(path, []byte("deterministic\n"), 0o600)
	_, _ = os.Stdout.WriteString("ok\n")
}

func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
