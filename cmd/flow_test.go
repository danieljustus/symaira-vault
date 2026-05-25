package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/cli"
	"github.com/danieljustus/symaira-vault/internal/config"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func testTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "symaira-flow-test")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	return dir
}

func captureStdout(fn func()) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()
	return buf.String()
}

func captureStderr(fn func()) string {
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()
	return buf.String()
}

func execWithStdout(args ...string) string {
	rootCmd.SetArgs(args)
	defer rootCmd.SetArgs(nil)
	return captureStdout(func() {
		_ = rootCmd.Execute()
	})
}

func TestCmdSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}
	vaultDir := testTempDir(t)
	passphrase := []byte("correct horse battery staple")

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	output := execWithStdout("--vault", vaultDir, "set", "demo.password", "--value", "StrongP@ssw0rd123")
	if !strings.Contains(output, "Entry saved") {
		t.Errorf("set output missing success: %s", output)
	}
}

func TestCmdGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}
	vaultDir, err := os.MkdirTemp("", "symaira-flow-test")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(vaultDir)
	passphrase := []byte("correct horse battery staple")
	identity, _ := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "secret123"}}
	_ = vaultpkg.WriteEntry(vaultDir, "demo", entry, identity)
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	output := execWithStdout("--vault", vaultDir, "get", "demo.password")
	if strings.TrimSpace(output) != "secret123" {
		t.Errorf("get output: %q", output)
	}
}

func TestCmdList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}
	vaultDir := testTempDir(t)
	passphrase := []byte("correct horse battery staple")
	identity, _ := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "secret123"}}
	_ = vaultpkg.WriteEntry(vaultDir, "demo", entry, identity)
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	output := execWithStdout("--vault", vaultDir, "list")
	if !strings.Contains(output, "demo") {
		t.Errorf("list output missing entry: %s", output)
	}
}

func TestCmdFind(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}
	vaultDir := testTempDir(t)
	passphrase := []byte("correct horse battery staple")
	identity, _ := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "secret123"}}
	_ = vaultpkg.WriteEntry(vaultDir, "demo", entry, identity)
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	output := execWithStdout("--vault", vaultDir, "find", "secret123")
	if !strings.Contains(output, "demo") {
		t.Errorf("find output missing match: %s", output)
	}
}

func TestCmdGenerate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}
	vaultDir := testTempDir(t)
	passphrase := []byte("test-passphrase")

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	output := execWithStdout("--vault", vaultDir, "generate", "--length", "16", "--store", "gen.pass")
	if !strings.Contains(output, "Password stored at") {
		t.Errorf("generate output missing success: %s", output)
	}
}

func TestCmdDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}
	vaultDir := testTempDir(t)
	passphrase := []byte("test-passphrase")
	identity, _ := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "secret"}}
	_ = vaultpkg.WriteEntry(vaultDir, "delme", entry, identity)
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.WriteString("y\n")
	_ = w.Close()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "delete", "delme"})
	defer rootCmd.SetArgs(nil)
	output := captureStdout(func() {
		_ = rootCmd.Execute()
	})
	os.Stdin = oldStdin
	_ = r.Close()

	if !strings.Contains(output, "Deleted") {
		t.Errorf("delete output missing success: %s", output)
	}
}

func TestCmdAdd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}
	vaultDir := testTempDir(t)
	passphrase := []byte("correct horse battery staple")

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	output := execWithStdout("--vault", vaultDir, "add", "newentry", "--value", "mysecretpassword")
	if !strings.Contains(output, "Entry created") {
		t.Errorf("add output missing success: %s", output)
	}
}

func TestCmdUnlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}

	restoreSession := stubSessionFuncs(t)
	t.Cleanup(restoreSession)
	cli.SessionLoadPassphrase = func(string) ([]byte, error) { return nil, nil }
	cli.SessionSavePassphrase = func(string, []byte, time.Duration) error { return nil }
	cli.SessionSaveIdentity = func(string, string, time.Duration) error { return nil }

	vaultDir := testTempDir(t)
	passphrase := []byte("correct horse battery staple")

	if _, err := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default()); err != nil {
		t.Fatalf("init vault: %v", err)
	}
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "unlock"})
	defer rootCmd.SetArgs(nil)
	output := captureStderr(func() {
		_ = rootCmd.Execute()
	})
	if !strings.Contains(output, "unlocked") && !strings.Contains(output, "Unlock") {
		t.Errorf("unlock output unexpected: %s", output)
	}
}

func TestCmdRecipientsAddAndRemove(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow CLI flow test in short mode")
	}
	vaultDir := testTempDir(t)
	passphrase := []byte("correct horse battery staple")
	identity, _ := vaultpkg.InitWithPassphrase(vaultDir, passphrase, config.Default())
	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	defer func() { _ = os.Unsetenv("OPENPASS_PASSPHRASE") }()

	origVault := vault
	origChanged := vaultFlag.Changed
	defer func() {
		vault = origVault
		if vaultFlag != nil {
			_ = vaultFlag.Value.Set(origVault)
			vaultFlag.Changed = origChanged
		}
	}()

	recipient := identity.Recipient().String()

	output := execWithStdout("--vault", vaultDir, "recipients", "add", recipient)
	if !strings.Contains(output, "added") {
		t.Errorf("recipients add output unexpected: %s", output)
	}

	_ = os.Setenv("OPENPASS_PASSPHRASE", string(passphrase))
	output = execWithStdout("--vault", vaultDir, "recipients", "remove", recipient, "-y")
	if !strings.Contains(output, "removed") {
		t.Errorf("recipients remove output unexpected: %s", output)
	}
}
