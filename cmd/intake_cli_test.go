package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runIntakeCLI invokes the intake command through the real root tree.
func runIntakeCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRootCmd()
	root.SetArgs(args)
	out := &strings.Builder{}
	root.SetOut(out)
	root.SetErr(out)
	err := root.Execute()
	return out.String(), err
}

func TestIntakeCommandRegistered(t *testing.T) {
	root := NewRootCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "intake" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("intake command not registered on root")
	}
}

func TestIntakeDryRunJSONNoSecrets(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "creds.env")
	if err := os.WriteFile(src, []byte("USERNAME=alice\nPASSWORD=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runIntakeCLI(t, "intake", src, "--dry-run", "--json")
	if err != nil {
		t.Fatalf("intake: %v\n%s", err, out)
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "alice") {
		t.Fatalf("JSON output leaks secret values:\n%s", out)
	}
	var parsed struct {
		ImportID string `json:"import_id"`
		Results  []struct {
			Status     string `json:"status"`
			Provenance struct {
				SourceType string `json:"source_type"`
				SHA256     string `json:"sha256"`
			} `json:"provenance"`
			Suggestions []struct {
				Field string `json:"field"`
			} `json:"suggestions"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if parsed.ImportID != "" {
		t.Fatalf("dry-run must not emit import_id, got %q", parsed.ImportID)
	}
	if len(parsed.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(parsed.Results))
	}
	r := parsed.Results[0]
	if r.Status != "ok" {
		t.Fatalf("status = %q", r.Status)
	}
	if r.Provenance.SourceType != "env" {
		t.Fatalf("source_type = %q, want env", r.Provenance.SourceType)
	}
	fields := map[string]bool{}
	for _, s := range r.Suggestions {
		fields[s.Field] = true
	}
	if !fields["username"] || !fields["password"] {
		t.Fatalf("suggestions = %v, want username+password", fields)
	}
}

func TestIntakeRejectsMissingArgs(t *testing.T) {
	_, err := runIntakeCLI(t, "intake")
	if err == nil {
		t.Fatal("expected error for missing args")
	}
}
