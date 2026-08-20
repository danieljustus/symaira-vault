package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeDeviceName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Foo-Bar.local", "foo-bar"},
		{"foo-bar.home", "foo-bar"},
		{"MacBook-Pro-von-Daniel-2.local", "macbook-pro-von-daniel-2"},
		{"macbook-pro-von-daniel-2.home", "macbook-pro-von-daniel-2"},
		{"My-Mac.lan", "my-mac"},
		{"My-Mac.internal", "my-mac"},
		{"My-Mac.", "my-mac"},
		{"Already-Normal", "already-normal"},
		{"ALREADY-UPPER.LOCAL", "already-upper"},
		{"  padded  ", "padded"},
	}
	for _, tc := range cases {
		if got := NormalizeDeviceName(tc.in); got != tc.want {
			t.Errorf("NormalizeDeviceName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDeviceIdentityPersistsAcrossHostnameChanges(t *testing.T) {
	dir := t.TempDir()

	// First call on one network: identity derived from the hostname and
	// persisted in the vault directory.
	first := deviceIdentity(dir, "Foo-Bar.local")
	if first != "foo-bar" {
		t.Fatalf("deviceIdentity() = %q, want %q", first, "foo-bar")
	}

	// Network change: a different hostname representation must not change the
	// device identity.
	if got := deviceIdentity(dir, "macbook-pro-von-daniel-2.home"); got != first {
		t.Errorf("identity changed after hostname change: %q != %q", got, first)
	}

	// Restart with a completely different hostname: the persisted ID wins.
	if got := deviceIdentity(dir, "totally-different-host.example"); got != first {
		t.Errorf("identity changed after restart: %q != %q", got, first)
	}

	if _, err := os.Stat(filepath.Join(dir, deviceIDFile)); err != nil {
		t.Errorf("expected persisted device ID file: %v", err)
	}
}

func TestDeviceIdentityReadsExistingID(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, deviceIDFile, []byte("my-stable-device"))

	if got := DeviceIdentity(dir); got != "my-stable-device" {
		t.Errorf("DeviceIdentity() = %q, want %q", got, "my-stable-device")
	}
}

func TestDeviceIdentityNoVaultFallsBackToNormalisedHostname(t *testing.T) {
	// No vault dir available: fall back to a normalised hostname without
	// persisting anything.
	got := deviceIdentity("", "Foo-Bar.local")
	if got != "foo-bar" {
		t.Errorf("deviceIdentity() = %q, want %q", got, "foo-bar")
	}
}

func TestDeviceIdentityEmptyHostname(t *testing.T) {
	if got := deviceIdentity(t.TempDir(), ""); got != UnknownDeviceName {
		t.Errorf("deviceIdentity() = %q, want %q", got, UnknownDeviceName)
	}
}

// TestConflictFileNameStableAcrossNetworks is the core acceptance test for
// issue #800: the same machine observed under two different hostname
// representations must produce the identical conflict file name.
func TestConflictFileNameStableAcrossNetworks(t *testing.T) {
	var conflictNames []string
	for _, host := range []string{"Foo-Bar.local", "foo-bar.home"} {
		dir := t.TempDir()
		if err := Init(dir); err != nil {
			t.Fatalf("Init(%s): %v", host, err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
			t.Fatalf("mkdir entries: %v", err)
		}
		writeFile(t, dir, "entries/a.age", []byte("v1"))
		if err := AutoCommit(dir, "initial"); err != nil {
			t.Fatalf("AutoCommit(%s): %v", host, err)
		}
		writeFile(t, dir, "entries/a.age", []byte("v2"))

		if err := ResolveConflicts(dir, deviceIdentity(dir, host)); err != nil {
			t.Fatalf("ResolveConflicts(%s): %v", host, err)
		}
		entries, err := os.ReadDir(filepath.Join(dir, "entries"))
		if err != nil {
			t.Fatalf("read entries: %v", err)
		}
		var conflict string
		for _, e := range entries {
			if strings.Contains(e.Name(), ".conflict-") {
				conflict = e.Name()
			}
		}
		if conflict == "" {
			t.Fatalf("no conflict file created for host %s", host)
		}
		conflictNames = append(conflictNames, conflict)
	}

	if conflictNames[0] != conflictNames[1] {
		t.Errorf("conflict file names differ across networks: %q vs %q", conflictNames[0], conflictNames[1])
	}
}

func TestConflictFilesMigratedToCanonicalDeviceName(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	oldName := "old.conflict-MacBook-Pro-von-Daniel-2.local.age"
	newName := "old.conflict-macbook-pro-von-daniel-2.age"
	writeFile(t, dir, filepath.Join("entries", oldName), []byte("x"))

	// The current device identity normalises to the same device; the old
	// hostname-based conflict file must be renamed to the canonical name.
	if err := ResolveConflicts(dir, "macbook-pro-von-daniel-2"); err != nil {
		t.Fatalf("ResolveConflicts: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "entries", newName)); err != nil {
		t.Errorf("expected migrated conflict file %s: %v", newName, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "entries", oldName)); err == nil {
		t.Error("old hostname-based conflict file still present after migration")
	}
}

func TestConflictMigrationLeavesOtherDevicesAlone(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "entries"), 0o700); err != nil {
		t.Fatalf("mkdir entries: %v", err)
	}
	other := "old.conflict-another-device.age"
	writeFile(t, dir, filepath.Join("entries", other), []byte("x"))

	if err := ResolveConflicts(dir, "macbook-pro-von-daniel-2"); err != nil {
		t.Fatalf("ResolveConflicts: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "entries", other)); err != nil {
		t.Errorf("conflict file of another device should be untouched: %v", err)
	}
}

func TestParseConflictName(t *testing.T) {
	cases := []struct {
		in       string
		shadowed string
		device   string
		ok       bool
	}{
		{"config.conflict-macbook-2.yaml", "config.yaml", "macbook-2", true},
		{"config.conflict-MacBook-2.local.yaml", "config.yaml", "MacBook-2.local", true},
		{"a.b.conflict-mac.age", "a.b.age", "mac", true},
		{"config.yaml", "", "", false},
		{"manifest.age", "", "", false},
		{".conflict-mac.age", "", "", false},       // nothing is being shadowed
		{"config.conflict-macbook", "", "", false}, // no extension
	}
	for _, tc := range cases {
		shadowed, device, ok := ParseConflictName(tc.in)
		if ok != tc.ok || shadowed != tc.shadowed || device != tc.device {
			t.Errorf("ParseConflictName(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, shadowed, device, ok, tc.shadowed, tc.device, tc.ok)
		}
	}
}
