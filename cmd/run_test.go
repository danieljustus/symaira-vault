package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestCmdRun_Basic(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run", "--", "echo", "hello")
	if !strings.Contains(out, "hello") {
		t.Errorf("expected 'hello' in stdout, got: %q", out)
	}
}

func TestCmdRun_SecretInjection(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"api_key": "secret123"}}
	_ = vaultpkg.WriteEntry(vaultDir, "github", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run", "--env", "API_KEY=github.api_key", "--", "sh", "-c", "echo $API_KEY")
	if !strings.Contains(out, "secret123") {
		t.Errorf("expected 'secret123' in stdout, got: %q", out)
	}
}

func TestCmdRun_MissingSecretRef(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--env", "FOO=missing.value", "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for missing secret ref, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "secret ref not found") && !strings.Contains(errStr, "not found") {
			t.Errorf("expected 'not found' in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_Timeout(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--timeout", "100ms", "--", "sleep", "10"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected timeout error, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "timed out") && !strings.Contains(errStr, "timeout") && !strings.Contains(errStr, "deadline") {
			t.Errorf("expected timeout-related error, got: %q", errStr)
		}
	}
}

func TestCmdRun_WorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: path format differs")
	}
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	tmpDir := t.TempDir()
	resolvedDir, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	out := execWithStdout("--vault", vaultDir, "run", "--working-dir", tmpDir, "--", "pwd")
	out = strings.TrimSpace(out)
	outResolved, err := filepath.EvalSymlinks(out)
	if err != nil {
		t.Fatalf("eval symlinks on pwd output: %v", err)
	}
	if outResolved != resolvedDir {
		t.Errorf("expected pwd output %q, got: %q (resolved: %q)", tmpDir, out, outResolved)
	}
}

func TestCmdRun_MultipleEnvFlags(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry1 := &vaultpkg.Entry{Data: map[string]any{"token": "tok1"}}
	entry2 := &vaultpkg.Entry{Data: map[string]any{"secret": "sec1"}}
	_ = vaultpkg.WriteEntry(vaultDir, "svc1", entry1, identity.Identity)
	_ = vaultpkg.WriteEntry(vaultDir, "svc2", entry2, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run",
		"--env", "TOKEN=svc1.token",
		"--env", "SECRET=svc2.secret",
		"--", "sh", "-c", "echo TOKEN=$TOKEN SECRET=$SECRET")
	if !strings.Contains(out, "TOKEN=tok1") {
		t.Errorf("expected TOKEN=tok1 in stdout, got: %q", out)
	}
	if !strings.Contains(out, "SECRET=sec1") {
		t.Errorf("expected SECRET=sec1 in stdout, got: %q", out)
	}
}

func TestCmdRun_NonZeroExit(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--", "sh", "-c", "exit 42"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected non-zero exit error, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "exited with code") && !strings.Contains(errStr, "42") {
			t.Errorf("expected exit code 42 in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_UninitializedVault(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for uninitialized vault, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "not initialized") {
			t.Errorf("expected 'not initialized' in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_TooManyEnvironmentVariables(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)

	for _, svc := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		entry := &vaultpkg.Entry{Data: map[string]any{"key": svc}}
		_ = vaultpkg.WriteEntry(vaultDir, svc, entry, identity.Identity)
	}

	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run",
		"--env", "A=a.key", "--env", "B=b.key", "--env", "C=c.key",
		"--env", "D=d.key", "--env", "E=e.key", "--env", "F=f.key",
		"--env", "G=g.key", "--env", "H=h.key", "--env", "I=i.key",
		"--env", "J=j.key",
		"--", "sh", "-c", "echo ALL_SET"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCmdRun_EnvWithBareRef(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "thepass"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "run", "--env", "DB_PASSWORD=db.password", "--", "sh", "-c", "echo $DB_PASSWORD")
	if !strings.Contains(out, "thepass") {
		t.Errorf("expected 'thepass' in stdout, got: %q", out)
	}
}

func TestCmdRun_StdoutStderrPassthrough(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	var stdout, stderr string

	stdout = captureStdout(func() {
		stderr = captureStderr(func() {
			rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--", "sh", "-c", "echo stdout; echo stderr >&2"})
			_ = rootCmd.Execute()
			rootCmd.SetArgs(nil)
		})
	})

	if !strings.Contains(stdout, "stdout") {
		t.Errorf("expected 'stdout' in stdout, got: %q", stdout)
	}
	if !strings.Contains(stderr, "stderr") {
		t.Errorf("expected 'stderr' in stderr, got: %q", stderr)
	}
}

func TestCmdRun_NoArgsError(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error when no command provided, got nil")
	}
}

func TestCmdRun_InvalidEnvFormat(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--env", "NOEQUALSIGN", "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid --env format, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "invalid --env format") {
			t.Errorf("expected 'invalid --env format' in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_EnvFile(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "filesecret"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	if err := os.WriteFile(envFile, []byte("DB_PASS=db.password\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	out := execWithStdout("--vault", vaultDir, "run", "--env-file", envFile, "--", "sh", "-c", "echo $DB_PASS")
	if !strings.Contains(out, "filesecret") {
		t.Errorf("expected 'filesecret' in stdout, got: %q", out)
	}
}

func TestCmdRun_EnvFileMultiple(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry1 := &vaultpkg.Entry{Data: map[string]any{"token": "tok_from_file"}}
	entry2 := &vaultpkg.Entry{Data: map[string]any{"secret": "sec_from_file"}}
	_ = vaultpkg.WriteEntry(vaultDir, "svc1", entry1, identity.Identity)
	_ = vaultpkg.WriteEntry(vaultDir, "svc2", entry2, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	content := "TOKEN=svc1.token\nSECRET=svc2.secret\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	out := execWithStdout("--vault", vaultDir, "run", "--env-file", envFile, "--",
		"sh", "-c", "echo TOKEN=$TOKEN SECRET=$SECRET")
	if !strings.Contains(out, "TOKEN=tok_from_file") {
		t.Errorf("expected TOKEN=tok_from_file in stdout, got: %q", out)
	}
	if !strings.Contains(out, "SECRET=sec_from_file") {
		t.Errorf("expected SECRET=sec_from_file in stdout, got: %q", out)
	}
}

func TestCmdRun_EnvFileWithComments(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "comment_test"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	content := "# This is a comment\nDB_PASS=db.password\n# Another comment\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	out := execWithStdout("--vault", vaultDir, "run", "--env-file", envFile, "--", "sh", "-c", "echo $DB_PASS")
	if !strings.Contains(out, "comment_test") {
		t.Errorf("expected 'comment_test' in stdout, got: %q", out)
	}
}

func TestCmdRun_EnvFileNotFound(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--env-file", "/nonexistent/.env.symvault", "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for missing env file, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "open env file") && !strings.Contains(errStr, "no such file") {
			t.Errorf("expected env file error, got: %q", errStr)
		}
	}
}

func TestCmdRun_EnvFileInvalidFormat(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	if err := os.WriteFile(envFile, []byte("NOEQUALSIGN\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--env-file", envFile, "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid env file format, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "invalid format") {
			t.Errorf("expected 'invalid format' in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_EnvFileDuplicateVar(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "dup_test"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	if err := os.WriteFile(envFile, []byte("DB_PASS=db.password\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run",
		"--env", "DB_PASS=db.password",
		"--env-file", envFile,
		"--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for duplicate env var, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "duplicate env var") {
			t.Errorf("expected 'duplicate env var' in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_EnvFileEmptyLines(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "empty_lines_test"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	content := "\n\nDB_PASS=db.password\n\n\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	out := execWithStdout("--vault", vaultDir, "run", "--env-file", envFile, "--", "sh", "-c", "echo $DB_PASS")
	if !strings.Contains(out, "empty_lines_test") {
		t.Errorf("expected 'empty_lines_test' in stdout, got: %q", out)
	}
}

func TestParseEnvFile(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	content := "# Comment\nDB_PASS=db.password\nAPI_KEY=stripe.token\n\n# Another comment\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	result, err := parseEnvFile(envFile)
	if err != nil {
		t.Fatalf("parseEnvFile() unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result))
	}
	if result["DB_PASS"] != "db.password" {
		t.Errorf("DB_PASS = %q, want %q", result["DB_PASS"], "db.password")
	}
	if result["API_KEY"] != "stripe.token" {
		t.Errorf("API_KEY = %q, want %q", result["API_KEY"], "stripe.token")
	}
}

func TestParseEnvFile_EmptyName(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	if err := os.WriteFile(envFile, []byte("=db.password\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	_, err := parseEnvFile(envFile)
	if err == nil {
		t.Fatal("expected error for empty name in env file, got nil")
	}
	if !strings.Contains(err.Error(), "empty name or ref") {
		t.Errorf("expected 'empty name or ref' in error, got: %q", err.Error())
	}
}

func TestParseEnvFile_EmptyRef(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	if err := os.WriteFile(envFile, []byte("DB_PASS=\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	_, err := parseEnvFile(envFile)
	if err == nil {
		t.Fatal("expected error for empty ref in env file, got nil")
	}
	if !strings.Contains(err.Error(), "empty name or ref") {
		t.Errorf("expected 'empty name or ref' in error, got: %q", err.Error())
	}
}

func TestParseEnvFile_VeryLongLine(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	// bufio.Scanner default buffer is 64KB; a line exceeding this triggers scanner.Err
	longLine := strings.Repeat("A", 65*1024)
	if err := os.WriteFile(envFile, []byte(longLine+"=value\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	_, err := parseEnvFile(envFile)
	if err == nil {
		t.Fatal("expected error for very long line in env file, got nil")
	}
	if !strings.Contains(err.Error(), "read env file") {
		t.Errorf("expected 'read env file' in error, got: %q", err.Error())
	}
}

func TestCmdRun_EnvFileMissingSecret(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	envFile := filepath.Join(t.TempDir(), ".env.symvault")
	if err := os.WriteFile(envFile, []byte("MISSING=nonexistent.entry\n"), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "run", "--env-file", envFile, "--", "echo", "hello"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for missing secret in env file, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "not found") && !strings.Contains(errStr, "secret ref") {
			t.Errorf("expected 'not found' or 'secret ref' in error, got: %q", errStr)
		}
	}
}

func TestCmdRun_Passthrough(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	t.Setenv("SYMVAULT_TEST_PASSTHROUGH", "parent_val")

	out := execWithStdout("--vault", vaultDir, "run",
		"--passthrough", "SYMVAULT_TEST_PASSTHROUGH",
		"--", "sh", "-c", "echo $SYMVAULT_TEST_PASSTHROUGH")
	if !strings.Contains(out, "parent_val") {
		t.Errorf("expected 'parent_val' in stdout, got: %q", out)
	}
}

func TestCmdRun_PassthroughNotUsed(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	t.Setenv("SYMVAULT_TEST_NO_PASS", "should_be_stripped")

	out := execWithStdout("--vault", vaultDir, "run",
		"--", "sh", "-c", "echo $SYMVAULT_TEST_NO_PASS")
	if strings.Contains(out, "should_be_stripped") {
		t.Errorf("env var should be stripped without --passthrough, got: %q", out)
	}
}

func TestCmdRun_PassthroughMultiple(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	t.Setenv("SYMVAULT_TEST_P1", "val1")
	t.Setenv("SYMVAULT_TEST_P2", "val2")

	out := execWithStdout("--vault", vaultDir, "run",
		"--passthrough", "SYMVAULT_TEST_P1",
		"--passthrough", "SYMVAULT_TEST_P2",
		"--", "sh", "-c", "echo P1=$SYMVAULT_TEST_P1 P2=$SYMVAULT_TEST_P2")
	if !strings.Contains(out, "P1=val1") {
		t.Errorf("expected 'P1=val1' in stdout, got: %q", out)
	}
	if !strings.Contains(out, "P2=val2") {
		t.Errorf("expected 'P2=val2' in stdout, got: %q", out)
	}
}

func TestCmdRun_StdinForwarding(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdin = r
	_, _ = w.WriteString("stdin_test_data")
	_ = w.Close()

	out := execWithStdout("--vault", vaultDir, "run", "--", "cat")
	if !strings.Contains(out, "stdin_test_data") {
		t.Errorf("expected 'stdin_test_data' in stdout from stdin forwarding, got: %q", out)
	}
}
