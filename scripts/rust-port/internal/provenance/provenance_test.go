package provenance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRejectsChangedSourcesAndFalseCommitClaims(t *testing.T) {
	root := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		args = append([]string{"-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + filepath.Join(root, "no-hooks")}, args...)
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git: %v: %s", err, output)
		}
		return strings.TrimSpace(string(output))
	}
	git("init", "--template=")
	source := filepath.Join(root, "oracle.go")
	if err := os.WriteFile(source, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git("add", "oracle.go")
	git("commit", "-m", "synthetic oracle")
	commit := git("rev-parse", "HEAD")
	resolved, err := Verify(root, commit, []string{"oracle.go"})
	if err != nil || resolved != commit {
		t.Fatalf("valid oracle: %q %v", resolved, err)
	}
	if err := os.WriteFile(source, []byte("changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, commit, []string{"oracle.go"}); err == nil || !strings.Contains(err.Error(), "provenance mismatch") {
		t.Fatalf("changed oracle accepted: %v", err)
	}
	for _, claim := range []string{"", "does-not-exist"} {
		if _, err := Verify(root, claim, []string{"oracle.go"}); err == nil {
			t.Fatalf("false claim accepted: %q", claim)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "untracked.go"), []byte("new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, commit, []string{"untracked.go"}); err == nil {
		t.Fatal("untracked source accepted as committed")
	}
	if _, err := Verify(root, commit, []string{"missing.go"}); err == nil {
		t.Fatal("missing source accepted")
	}
	if _, err := Digest("", []string{source}); err != nil {
		t.Fatal(err)
	}
}
