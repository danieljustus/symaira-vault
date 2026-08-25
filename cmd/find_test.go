package cmd

import (
	"os"
	"strings"
	"testing"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestCmdFind_NoMatches(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "find", "nomatch_xyz_abc"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "No matches") {
		t.Errorf("expected No matches, got: %s", stderr)
	}
}

func TestCmdFind_WithFieldMatches(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "uniquevalue123"}}
	_ = vaultpkg.WriteEntry(vaultDir, "find-me", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "find", "find-me")
	if !strings.Contains(out, "find-me") {
		t.Errorf("expected find-me in output, got: %s", out)
	}
}

func TestCmdFind_SearchAlias(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry := &vaultpkg.Entry{Data: map[string]any{"password": "searchval"}}
	_ = vaultpkg.WriteEntry(vaultDir, "search-me", entry, identity.Identity)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()
	out := execWithStdout("--vault", vaultDir, "search", "search-me")
	if !strings.Contains(out, "search-me") {
		t.Errorf("expected search-me in output, got: %s", out)
	}
}

func TestCmdFind_Uninitialized(t *testing.T) {
	resetCmdFlags()
	t.Cleanup(resetCmdFlags)
	vaultDir := t.TempDir()
	defer setupVaultFlag(t, vaultDir)()
	stderr := captureStderr(func() {
		rootCmd.SetArgs([]string{"--vault", vaultDir, "find", "x"})
		_ = rootCmd.Execute()
		rootCmd.SetArgs(nil)
	})
	if !strings.Contains(stderr, "vault not initialized") && !strings.Contains(stderr, "Error") {
		t.Errorf("expected vault not initialized, got: %s", stderr)
	}
}

func TestFind_ErrorPaths(t *testing.T) {
	resetVaultState(t)
	t.Run("uninitialized vault", func(t *testing.T) {
		tmpDir := t.TempDir()
		_ = os.Setenv("SYMVAULT_VAULT", tmpDir)
		defer func() { _ = os.Unsetenv("SYMVAULT_VAULT") }()

		rootCmd.SetArgs([]string{"--vault", tmpDir, "find", "test"})
		defer rootCmd.SetArgs(nil)

		err := rootCmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "not initialized") {
			t.Errorf("expected 'not initialized' error, got: %v", err)
		}
	})
}

func TestCmdFind_URLFilter(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	identity, _ := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
	entry1 := &vaultpkg.Entry{Data: map[string]any{"url": "https://github.com/login", "username": "octocat"}}
	_ = vaultpkg.WriteEntry(vaultDir, "work/github", entry1, identity.Identity)
	entry2 := &vaultpkg.Entry{Data: map[string]any{"url": "http://gitlab.internal:8080/auth", "username": "gituser"}}
	_ = vaultpkg.WriteEntry(vaultDir, "personal/gitlab", entry2, identity.Identity)

	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	t.Run("find by bare domain", func(t *testing.T) {
		out := execWithStdout("--vault", vaultDir, "find", "--url", "github.com")
		if !strings.Contains(out, "work/github") {
			t.Errorf("expected work/github in output, got: %s", out)
		}
		if strings.Contains(out, "personal/gitlab") {
			t.Errorf("unexpected personal/gitlab in output: %s", out)
		}
	})

	t.Run("find by full URL with default port and path", func(t *testing.T) {
		out := execWithStdout("--vault", vaultDir, "find", "--url", "https://github.com:443/settings/profile")
		if !strings.Contains(out, "work/github") {
			t.Errorf("expected work/github in output, got: %s", out)
		}
	})

	t.Run("find by custom port URL", func(t *testing.T) {
		out := execWithStdout("--vault", vaultDir, "find", "--url", "http://gitlab.internal:8080")
		if !strings.Contains(out, "personal/gitlab") {
			t.Errorf("expected personal/gitlab in output, got: %s", out)
		}
	})

	t.Run("custom port mismatch returns no matches", func(t *testing.T) {
		stderr := captureStderr(func() {
			root := NewRootCmd()
			root.SetArgs([]string{"--vault", vaultDir, "find", "--url", "gitlab.internal"})
			_ = root.Execute()
		})
		if !strings.Contains(stderr, "No matches") {
			t.Errorf("expected No matches on port mismatch, got: %s", stderr)
		}
	})

	t.Run("json output format", func(t *testing.T) {
		out := execWithStdout("--vault", vaultDir, "find", "--url", "github.com", "--output", "json")
		if !strings.Contains(out, `"path": "work/github"`) && !strings.Contains(out, `"path":"work/github"`) {
			t.Errorf("expected JSON with work/github, got: %s", out)
		}
	})

	t.Run("combined query and url", func(t *testing.T) {
		out := execWithStdout("--vault", vaultDir, "find", "octocat", "--url", "github.com")
		if !strings.Contains(out, "work/github") {
			t.Errorf("expected work/github in output, got: %s", out)
		}
	})

	t.Run("combined query mismatch returns no matches", func(t *testing.T) {
		stderr := captureStderr(func() {
			root := NewRootCmd()
			root.SetArgs([]string{"--vault", vaultDir, "find", "nonexistent_term", "--url", "github.com"})
			_ = root.Execute()
		})
		if !strings.Contains(stderr, "No matches") {
			t.Errorf("expected No matches on query mismatch, got: %s", stderr)
		}
	})
}

func TestCmdFind_URLFilterErrors(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	defer setupVaultFlag(t, vaultDir)()

	t.Run("invalid url format", func(t *testing.T) {
		root := NewRootCmd()
		root.SetArgs([]string{"--vault", vaultDir, "find", "--url", "invalid::url"})
		err := root.Execute()
		if err == nil || !strings.Contains(err.Error(), "invalid url") {
			t.Errorf("expected invalid url error, got: %v", err)
		}
	})

	t.Run("no args and no url flag", func(t *testing.T) {
		root := NewRootCmd()
		root.SetArgs([]string{"--vault", vaultDir, "find"})
		err := root.Execute()
		if err == nil {
			t.Errorf("expected error when no args and no --url, got nil")
		}
	})
}
