package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeLayoutSource copies the production Touch ID source into a scratch root,
// applying one mutation, so buildLayout's rejection path is exercised on a real
// file rather than a hand-written stand-in.
func writeLayoutSource(t *testing.T, mutate func(string) string) string {
	t.Helper()
	root := repositoryRoot()
	raw, err := os.ReadFile(filepath.Join(root, layoutSource)) // #nosec G304 -- fixed production input
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	path := filepath.Join(scratch, layoutSource)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(mutate(string(raw))), 0o600); err != nil {
		t.Fatal(err)
	}
	return scratch
}

func TestBuildLayoutAcceptsTheProductionSource(t *testing.T) {
	scratch := writeLayoutSource(t, func(s string) string { return s })
	got, err := buildLayout(scratch)
	if err != nil {
		t.Fatalf("production source rejected: %v", err)
	}
	if got.Account != "passphrase" || got.ServicePrefix != "symvault-biometric:" {
		t.Fatalf("layout = %q %q", got.Account, got.ServicePrefix)
	}
	for _, a := range got.Assertions {
		if !a.Matched {
			t.Fatalf("assertion %s not matched", a.Name)
		}
	}
}

func TestBuildLayoutRejectsDriftedSources(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(string) string
		want   string
	}{
		{"accessibility attribute dropped", func(s string) string {
			return strings.ReplaceAll(s, "kSecAttrAccessibleWhenUnlockedThisDeviceOnly", "kSecAttrAccessibleAlways")
		}, "store_accessible_when_unlocked_this_device_only"},
		{"value wrapped like go-keyring", func(s string) string {
			return strings.ReplaceAll(s, "CFDataCreate(NULL, (const UInt8 *)passphrase_c, (CFIndex)strlen(passphrase_c))", "CFDataCreate(NULL, (const UInt8 *)go_keyring_base64(passphrase_c), 0)")
		}, "value_is_raw_passphrase_bytes"},
		{"prompt before existence probe", func(s string) string {
			return strings.ReplaceAll(s, "kSecReturnData, kCFBooleanFalse", "kSecReturnData, kCFBooleanTrue")
		}, "load_checks_item_before_prompt"},
		{"account renamed", func(s string) string {
			return strings.ReplaceAll(s, `const biometricAccount = "passphrase"`, `const biometricAccount = "secret"`)
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scratch := writeLayoutSource(t, tc.mutate)
			got, err := buildLayout(scratch)
			if tc.want == "" {
				// A renamed constant is not a drift buildLayout rejects: it is
				// recorded, which is what makes the Rust constant comparison fail.
				if err != nil || got.Account != "secret" {
					t.Fatalf("renamed account: %v %q", err, got.Account)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("drift accepted or wrong error: %v", err)
			}
		})
	}
}
