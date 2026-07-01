package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestCmdTemplateGenerate_PositionalArgs(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "s3cret"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db/prod", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "template", "generate", "--type", "env",
		"DB_PASS=db/prod.password")
	if !strings.Contains(out, "s3cret") {
		t.Errorf("expected 's3cret' in output, got: %q", out)
	}
	if !strings.Contains(out, "DB_PASS=") {
		t.Errorf("expected 'DB_PASS=' in output, got: %q", out)
	}
}

func TestCmdTemplateGenerate_MultiplePositionalArgs(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry1 := &vaultpkg.Entry{Data: map[string]any{"token": "tok123"}}
	entry2 := &vaultpkg.Entry{Data: map[string]any{"secret": "sec456"}}
	_ = vaultpkg.WriteEntry(vaultDir, "stripe", entry1, identity.Identity)
	_ = vaultpkg.WriteEntry(vaultDir, "aws", entry2, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "template", "generate", "--type", "env",
		"API_KEY=stripe.token", "AWS_SECRET=aws.secret")
	if !strings.Contains(out, "tok123") {
		t.Errorf("expected 'tok123' in output, got: %q", out)
	}
	if !strings.Contains(out, "sec456") {
		t.Errorf("expected 'sec456' in output, got: %q", out)
	}
}

func TestCmdTemplateGenerate_PrefixFlag(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry1 := &vaultpkg.Entry{Data: map[string]any{"token": "tok1"}}
	entry2 := &vaultpkg.Entry{Data: map[string]any{"secret": "sec2"}}
	_ = vaultpkg.WriteEntry(vaultDir, "work/api", entry1, identity.Identity)
	_ = vaultpkg.WriteEntry(vaultDir, "work/db", entry2, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "template", "generate", "--type", "env",
		"--prefix", "work/")
	if !strings.Contains(out, "tok1") {
		t.Errorf("expected 'tok1' in output, got: %q", out)
	}
	if !strings.Contains(out, "sec2") {
		t.Errorf("expected 'sec2' in output, got: %q", out)
	}
}

func TestCmdTemplateGenerate_PrefixWithPositionalOverride(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry1 := &vaultpkg.Entry{Data: map[string]any{"token": "prefix_tok"}}
	entry2 := &vaultpkg.Entry{Data: map[string]any{"password": "explicit_pass"}}
	_ = vaultpkg.WriteEntry(vaultDir, "work/api", entry1, identity.Identity)
	_ = vaultpkg.WriteEntry(vaultDir, "db/prod", entry2, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "template", "generate", "--type", "env",
		"--prefix", "work/", "EXPLICIT_DB=db/prod.password")
	if !strings.Contains(out, "prefix_tok") {
		t.Errorf("expected 'prefix_tok' in output, got: %q", out)
	}
	if !strings.Contains(out, "explicit_pass") {
		t.Errorf("expected 'explicit_pass' in output, got: %q", out)
	}
}

func TestCmdTemplateGenerate_NoRefsError(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "env"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for no refs, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "no secret references") {
			t.Errorf("expected 'no secret references' in error, got: %q", errStr)
		}
	}
}

func TestCmdTemplateGenerate_InvalidRefFormat(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "env",
		"NOEQUALSIGN"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid ref format, got nil")
	} else {
		errStr := err.Error()
		if !strings.Contains(errStr, "invalid ref format") {
			t.Errorf("expected 'invalid ref format' in error, got: %q", errStr)
		}
	}
}

func TestCmdTemplateGenerate_DryRun(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "s3cret"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	out := execWithStdout("--vault", vaultDir, "template", "generate", "--type", "env",
		"--dry-run", "DB_PASS=db.password")
	if !strings.Contains(out, "***") {
		t.Errorf("expected '***' in dry-run output, got: %q", out)
	}
	if strings.Contains(out, "s3cret") {
		t.Errorf("dry-run should not contain actual secret, got: %q", out)
	}
}

func TestCmdTemplateGenerate_OutputFile(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "filetest"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	outFile := filepath.Join(t.TempDir(), "output.env")
	rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "env",
		"--output", outFile, "DB_PASS=db.password"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, readErr := os.ReadFile(outFile)
	if readErr != nil {
		t.Fatalf("read output file: %v", readErr)
	}
	if !strings.Contains(string(content), "filetest") {
		t.Errorf("expected 'filetest' in output file, got: %q", string(content))
	}
}

func TestCmdTemplateGenerate_EmptyKeyInRef(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "env",
		"=db.password"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for empty key in ref, got nil")
	} else {
		if !strings.Contains(err.Error(), "empty key or ref") {
			t.Errorf("expected 'empty key or ref' in error, got: %q", err.Error())
		}
	}
}

func TestCmdTemplateGenerate_EmptyRefInRef(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "env",
		"DB_PASS="})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for empty ref in positional arg, got nil")
	} else {
		if !strings.Contains(err.Error(), "empty key or ref") {
			t.Errorf("expected 'empty key or ref' in error, got: %q", err.Error())
		}
	}
}

func TestCmdTemplateGenerate_InvalidTemplateType(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "s3cret"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "nonexistent",
		"DB_PASS=db.password"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid template type, got nil")
	} else {
		if !strings.Contains(err.Error(), "render template") && !strings.Contains(err.Error(), "unknown template") {
			t.Errorf("expected template render error, got: %q", err.Error())
		}
	}
}

func TestCmdTemplateGenerate_OutputFilePermissionError(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "permtest"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "env",
		"--output", "/nonexistent/dir/output.env", "DB_PASS=db.password"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for unwritable output path, got nil")
	} else {
		if !strings.Contains(err.Error(), "write output file") {
			t.Errorf("expected 'write output file' in error, got: %q", err.Error())
		}
	}
}

func TestCmdTemplateGenerate_JSONOutputWithFile(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "json_out_test"}}
	_ = vaultpkg.WriteEntry(vaultDir, "db", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	cli.OutputFormat = "json"
	t.Cleanup(func() { cli.OutputFormat = "text" })

	outFile := filepath.Join(t.TempDir(), "output.env")
	stdout := captureStdout(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "env",
			"--output", outFile, "DB_PASS=db.password"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})

	fileContent, readErr := os.ReadFile(outFile)
	if readErr != nil {
		t.Fatalf("read output file: %v", readErr)
	}
	if !strings.Contains(string(fileContent), "json_out_test") {
		t.Errorf("expected 'json_out_test' in output file, got: %q", string(fileContent))
	}
	if !strings.Contains(stdout, "output_path") {
		t.Errorf("expected 'output_path' in JSON stdout, got: %q", stdout)
	}
}

func TestCmdTemplateGenerate_PrefixReadError(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"token": "good_token"}}
	_ = vaultpkg.WriteEntry(vaultDir, "work/api", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	entryDir := filepath.Join(vaultDir, "entries", "work")
	badFile := filepath.Join(entryDir, "bad_entry.age")
	if err := os.WriteFile(badFile, []byte("not-valid-age-data"), 0600); err != nil {
		t.Fatalf("write bad entry file: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "template", "generate", "--type", "env",
		"--prefix", "work/"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for unreadable entry in prefix, got nil")
	} else {
		if !strings.Contains(err.Error(), "read entry") {
			t.Errorf("expected 'read entry' in error, got: %q", err.Error())
		}
	}
}
