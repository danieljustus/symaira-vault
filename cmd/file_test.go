package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestAttachment(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cert.pfx")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write test attachment: %v", err)
	}
	return path
}

func TestCmdFile_AddGetRoundTrip(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	content := []byte("fake-pkcs12-certificate-bytes-1234567890")
	src := writeTestAttachment(t, content)

	out := execWithStdout("--vault", vaultDir, "file", "add", "elster/cert", "--field", "cert_p12", "--from", src)
	if !strings.Contains(out, "Attached") {
		t.Fatalf("expected 'Attached' in output, got: %q", out)
	}
	sum := sha256.Sum256(content)
	wantSHA := hex.EncodeToString(sum[:])
	if !strings.Contains(out, wantSHA) {
		t.Errorf("expected sha256 %s in add output, got: %q", wantSHA, out)
	}

	outPath := filepath.Join(t.TempDir(), "roundtrip.pfx")
	getOut := execWithStdout("--vault", vaultDir, "file", "get", "elster/cert#cert_p12", "--out", outPath)
	if !strings.Contains(getOut, "Exported") {
		t.Fatalf("expected 'Exported' in output, got: %q", getOut)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("round-trip content mismatch: got %q, want %q", got, content)
	}
}

func TestCmdFile_GetAutoDetectsSoleAttachment(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	content := []byte("sole-attachment-content")
	src := writeTestAttachment(t, content)

	execWithStdout("--vault", vaultDir, "file", "add", "svc/cert", "--field", "cert_p12", "--from", src)

	outPath := filepath.Join(t.TempDir(), "out.pfx")
	// No "#field" and no --field: must auto-detect the entry's only attachment.
	getOut := execWithStdout("--vault", vaultDir, "file", "get", "svc/cert", "--out", outPath)
	if !strings.Contains(getOut, "Exported") {
		t.Fatalf("expected 'Exported' in output, got: %q", getOut)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", got, content)
	}
}

func TestCmdFile_AddSizeLimitRejected(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	src := writeTestAttachment(t, make([]byte, 200))

	rootCmd.SetArgs([]string{"--vault", vaultDir, "file", "add", "toobig/cert",
		"--field", "cert_p12", "--from", src, "--max-size", "100"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected size-limit error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds the 100 byte limit") {
		t.Errorf("expected size-limit message, got: %q", err.Error())
	}

	// Nothing should have been written to the vault.
	rootCmd.SetArgs([]string{"--vault", vaultDir, "file", "get", "toobig/cert", "--out", filepath.Join(t.TempDir(), "x")})
	getErr := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	if getErr == nil {
		t.Error("expected entry to not exist after rejected add, but get succeeded")
	}
}

func TestCmdFile_AddMissingRequiredFlags(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "file", "add", "svc/cert", "--from", "/nonexistent"})
	defer rootCmd.SetArgs(nil)
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "--field is required") {
		t.Errorf("expected '--field is required' error, got: %v", err)
	}
}

func TestCmdFile_UseInvokesCommandWithMaterializedPath(t *testing.T) {
	if os.Getenv("SYMVAULT_SKIP_SUBPROCESS_TESTS") != "" {
		t.Skip("subprocess execution disabled in this environment")
	}
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	content := []byte("materialize-me-please")
	src := writeTestAttachment(t, content)
	execWithStdout("--vault", vaultDir, "file", "add", "elster/cert", "--field", "cert_p12", "--from", src)

	out := execWithStdout("--vault", vaultDir, "file", "use", "elster/cert", "--",
		"sh", "-c", "cat \"$SYMVAULT_FILE_CERT_P12\"")
	if !strings.Contains(out, string(content)) {
		t.Errorf("expected materialized file content %q in stdout, got: %q", content, out)
	}
}

func TestCmdFile_UseCustomAsName(t *testing.T) {
	if os.Getenv("SYMVAULT_SKIP_SUBPROCESS_TESTS") != "" {
		t.Skip("subprocess execution disabled in this environment")
	}
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	content := []byte("custom-name-content")
	src := writeTestAttachment(t, content)
	execWithStdout("--vault", vaultDir, "file", "add", "elster/cert", "--field", "cert_p12", "--from", src)

	out := execWithStdout("--vault", vaultDir, "file", "use", "elster/cert", "--as", "MYCERT", "--",
		"sh", "-c", "cat \"$SYMVAULT_FILE_MYCERT\"")
	if !strings.Contains(out, string(content)) {
		t.Errorf("expected materialized file content %q in stdout, got: %q", content, out)
	}
}

func TestCmdFile_UseMissingCommandArg(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "file", "use", "elster/cert"})
	defer rootCmd.SetArgs(nil)
	if err := rootCmd.Execute(); err == nil {
		t.Error("expected error when no command is given after path, got nil")
	}
}

func TestCmdFile_GetAmbiguousAttachmentsRequiresField(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	src1 := writeTestAttachment(t, []byte("first"))
	src2 := writeTestAttachment(t, []byte("second"))
	execWithStdout("--vault", vaultDir, "file", "add", "multi/certs", "--field", "cert_a", "--from", src1)
	execWithStdout("--vault", vaultDir, "file", "add", "multi/certs", "--field", "cert_b", "--from", src2)

	rootCmd.SetArgs([]string{"--vault", vaultDir, "file", "get", "multi/certs", "--out", filepath.Join(t.TempDir(), "x")})
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "multiple attachment fields") {
		t.Errorf("expected 'multiple attachment fields' error, got: %v", err)
	}
}
