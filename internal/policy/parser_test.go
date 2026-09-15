package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// A malformed glob used to load fine and then match nothing, so a deny rule
// written that way silently stopped denying. Loading must fail instead.
func TestLoadPolicyRejectsMalformedGlob(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.yaml")
	content := "version: \"1.0\"\nrules:\n  - name: deny broken\n    action: deny\n    conditions:\n      path: \"secrets/[\"\n"
	if err := os.WriteFile(broken, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(broken); err == nil {
		t.Fatal("LoadPolicy accepted a policy whose deny rule can never match")
	}

	good := filepath.Join(dir, "good.yaml")
	content = "version: \"1.0\"\nrules:\n  - name: deny class\n    action: deny\n    conditions:\n      path: \"secrets/[ab]\"\n"
	if err := os.WriteFile(good, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(good); err != nil {
		t.Fatalf("LoadPolicy rejected a well-formed glob: %v", err)
	}
}
