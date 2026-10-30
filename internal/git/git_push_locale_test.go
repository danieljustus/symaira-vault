package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// germanLocale puts the process in a German session, the way a localized
// macOS or Linux login would (#1555).
func germanLocale(t *testing.T) {
	t.Helper()
	t.Setenv("LANG", "de_DE.UTF-8")
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	t.Setenv("LANGUAGE", "de")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
}

// TestPushWithSystemGitRunsInTheCLocale proves the environment handed to the
// git child with a fake git on PATH, so it does not depend on the host having
// a German message catalog.
func TestPushWithSystemGitRunsInTheCLocale(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake git is a POSIX shell script")
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf 'LC_ALL=%s LANGUAGE=%s' \"$LC_ALL\" \"${LANGUAGE-unset}\" >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	germanLocale(t)

	err := pushWithSystemGit(context.Background(), t.TempDir())
	if err == nil {
		t.Fatal("fake git exits 1, want an error")
	}
	if !strings.Contains(err.Error(), "LC_ALL=C LANGUAGE=unset") {
		t.Fatalf("git child must run with LC_ALL=C and no LANGUAGE, got %q", err)
	}
}

// TestPushWithSystemGitReportsEnglishErrorsUnderAGermanLocale runs the real
// git against an unreachable remote. With a localized git the text would be
// `Schwerwiegend: konnte nicht auf ... zugreifen`.
func TestPushWithSystemGitReportsEnglishErrorsUnderAGermanLocale(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX locale environment")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	germanLocale(t)
	const unreachable = "http://127.0.0.1:1/unreachable.git"

	probe, _ := exec.Command("git", "ls-remote", unreachable).CombinedOutput()
	if !strings.Contains(string(probe), "Schwerwiegend") {
		t.Skip("no German git catalog/locale on this host; the env contract is asserted by TestPushWithSystemGitRunsInTheCLocale")
	}

	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "base")
	run("remote", "add", "origin", unreachable)

	err := pushWithSystemGit(context.Background(), dir)
	if err == nil {
		t.Fatal("push to an unreachable remote must fail")
	}
	if strings.Contains(err.Error(), "Schwerwiegend") || !strings.Contains(err.Error(), "unable to access") {
		t.Fatalf("git error must be the English C-locale text, got %q", err)
	}
}
