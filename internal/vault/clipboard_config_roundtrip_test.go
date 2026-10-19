package vault

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/symaira-vault/internal/config"
)

func TestClipboardDurationPublicRoundTrip(t *testing.T) {
	for _, input := range []string{"marshal", "literal"} {
		for _, tc := range []struct {
			name    string
			seconds int
			omitted bool
		}{
			{name: "omitted", seconds: 30, omitted: true},
			{name: "zero", seconds: 0},
			{name: "nonzero", seconds: 2},
		} {
			t.Run(input+"/"+tc.name, func(t *testing.T) {
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
				t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
				t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
				root := filepath.Join(home, "vault")
				path := filepath.Join(root, "config.yaml")
				cfg, err := config.LoadFromBytes([]byte("vault: {}\nclipboard: {}\n"))
				if err != nil {
					t.Fatal(err)
				}
				cfg.VaultDir = root
				cfg.Vault.LegacyMode = nil
				if !tc.omitted {
					cfg.Clipboard.AutoClearDuration = tc.seconds
				}
				passphrase := []byte("public-config-roundtrip-passphrase")
				if _, err := InitWithPassphrase(root, passphrase, cfg); err != nil {
					t.Fatal(err)
				}
				check := func(stage string) *config.Config {
					t.Helper()
					loaded, err := config.Load(path)
					if err != nil {
						t.Fatal(err)
					}
					if got := loaded.Clipboard.AutoClearDuration; got != tc.seconds {
						t.Errorf("%s: clipboard duration = %d, want %d", stage, got, tc.seconds)
					}
					return loaded
				}
				if input == "marshal" {
					check("InitWithPassphrase -> Load")
					if err := cfg.SaveTo(path); err != nil {
						t.Fatal(err)
					}
				} else {
					// A literal user configuration exercises first-open persistence
					// independently of the initialization/save serialization above.
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var document map[string]any
					if err := yaml.Unmarshal(raw, &document); err != nil {
						t.Fatal(err)
					}
					clipboard := map[string]any{}
					if !tc.omitted {
						clipboard["auto_clear_duration"] = tc.seconds
					}
					document["clipboard"] = clipboard
					raw, err = yaml.Marshal(document)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				before := check("before first open")
				if before.Vault.LegacyMode != nil {
					t.Fatal("fixture must exercise first-open legacy detection")
				}
				for attempt := range 2 {
					opened, err := OpenWithPassphrase(root, passphrase)
					if err != nil {
						t.Fatal(err)
					}
					if got := opened.Config.Clipboard.AutoClearDuration; got != tc.seconds {
						t.Errorf("open %d: clipboard duration = %d, want %d", attempt, got, tc.seconds)
					}
					persisted := check("OpenWithPassphrase -> Load")
					if persisted.Vault.LegacyMode == nil || *persisted.Vault.LegacyMode {
						t.Fatal("first open did not persist nonlegacy detection")
					}
				}
			})
		}
	}
}
