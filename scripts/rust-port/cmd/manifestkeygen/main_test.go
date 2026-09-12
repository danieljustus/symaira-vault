package main

import (
	"bytes"
	"encoding/json"
	"filippo.io/age"
	vault "github.com/danieljustus/symaira-vault/internal/vault"
	"os"
	"path/filepath"
	"testing"
)

func TestManifestKeyProductionFixture(t *testing.T) {
	f, err := build(repoRoot())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) != 16 {
		t.Fatalf("executed %d vectors, want 16", len(f.Vectors))
	}
	for _, v := range f.Vectors {
		t.Run(v.Name+map[bool]string{false: "/plain", true: "/pseudonymized"}[v.Pseudonymize], func(t *testing.T) {
			var input struct {
				Path string `json:"path"`
			}
			if err := json.Unmarshal(v.Input, &input); err != nil {
				t.Fatal(err)
			}
			if len(v.Steps) != 4 {
				t.Fatal("missing operation")
			}
			for i, s := range v.Steps {
				if s.Error != "" {
					t.Fatalf("step %d: %s", i, s.Error)
				}
				if s.Generation != i {
					t.Fatalf("step %d generation=%d", i, s.Generation)
				}
				if i == 0 {
					if s.Exists {
						t.Fatal("missing remove published a manifest")
					}
					continue
				}
				if !s.TimesValid || !s.CreatedPreserved || s.Mode != 0600 {
					t.Fatalf("step %d: %+v", i, s)
				}
				if i < 3 {
					if _, ok := s.Entries[input.Path]; !ok {
						t.Fatalf("map key spelling lost: %q", input.Path)
					}
				} else if len(s.Entries) != 0 {
					t.Fatal("remove retained key")
				}
			}
		})
	}
	expected, err := encoded(f)
	if err != nil {
		t.Fatal(err)
	}
	f.Vectors[0].Steps[1].Generation++
	mutated, err := encoded(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := check(mutated, expected); err == nil {
		t.Fatal("fixture checker accepted mutated generation")
	}
}

// Invalid-looking keys must reach the production loader unchanged. Compare
// exact diagnostics within the oracle; cryptographic library wording is not
// normalized into a cross-language byte-parity claim.
func TestManifestKeyMalformedErrorOrder(t *testing.T) {
	root := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	malformed := []byte("synthetic malformed manifest")
	file := filepath.Join(root, "manifest.age")
	if err := os.WriteFile(file, malformed, 0600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"update", "remove"} {
		run := func(key string) error {
			if action == "update" {
				return vault.UpdateManifestEntry(root, key, []byte(payload), id)
			}
			return vault.RemoveManifestEntry(root, key, id)
		}
		baseline := run("valid")
		if baseline == nil {
			t.Fatal("malformed manifest accepted")
		}
		t.Logf("%s exact loader error: %s", action, baseline)
		for _, key := range []string{"", "../outside", ".", "/outside", "nul\x00key"} {
			got := run(key)
			if got == nil || got.Error() != baseline.Error() {
				t.Fatalf("%s key=%q: %v, want %v", action, key, got, baseline)
			}
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, malformed) {
				t.Fatal("failure changed manifest bytes")
			}
		}
	}
}
