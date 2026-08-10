package git

import (
	"os"
	"path/filepath"
	"strings"
)

// deviceIDFile is the name of the file, stored inside the vault directory,
// that persists this device's stable identity across restarts and network
// changes. It is intentionally gitignored and excluded from commits: the
// identity is per-device and must never be replicated to other devices via
// the shared remote.
const deviceIDFile = ".device-id"

// UnknownDeviceName is returned by DeviceIdentity when neither a persisted
// device ID nor a usable hostname is available.
const UnknownDeviceName = "unknown"

// DeviceIdentity returns the stable identity of the current device. The value
// is derived once and persisted in the vault directory; later calls return the
// persisted value so the identity (and the conflict file names derived from
// it) does not change when the hostname changes — e.g. macOS reports
// 'MacBook-Pro-von-Daniel-2.local' on one network and
// 'macbook-pro-von-daniel-2.home' on another. When no vault directory is
// available (or the ID cannot be stored), a normalised hostname is used
// instead.
func DeviceIdentity(vaultDir string) string {
	hostname, _ := os.Hostname()
	return deviceIdentity(vaultDir, hostname)
}

// deviceIdentity is the testable core of DeviceIdentity: the hostname is an
// explicit parameter so tests can simulate network changes.
func deviceIdentity(vaultDir, hostname string) string {
	if vaultDir != "" {
		if id, err := os.ReadFile(filepath.Join(vaultDir, deviceIDFile)); err == nil {
			if name := NormalizeDeviceName(strings.TrimSpace(string(id))); name != "" {
				return name
			}
		}
	}
	if strings.TrimSpace(hostname) == "" {
		return UnknownDeviceName
	}
	name := NormalizeDeviceName(hostname)
	if vaultDir != "" {
		// Persist the identity once so a later hostname change cannot change
		// the device identity.
		if err := os.WriteFile(filepath.Join(vaultDir, deviceIDFile), []byte(name), 0o600); err == nil {
			return name
		}
	}
	return name
}

// NormalizeDeviceName normalises a hostname into a stable, filesystem-safe
// device identity: lowercased, with trailing dots and common DNS suffixes
// (.local, .home, .lan, ...) stripped. Both 'Foo-Bar.local' and
// 'foo-bar.home' normalise to 'foo-bar'.
func NormalizeDeviceName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	for _, suffix := range []string{".local", ".home", ".lan", ".internal", ".home.arpa"} {
		name = strings.TrimSuffix(name, suffix)
	}
	return name
}

// renameConflictsForDevice renames pre-existing conflict files whose embedded
// device name normalises to the current device identity but differs from it
// (e.g. old hostname-based names), so a single device does not leave duplicate
// conflict files behind after a hostname change. Best-effort: failures are
// ignored.
func renameConflictsForDevice(vaultDir, deviceName string) {
	canonical := NormalizeDeviceName(deviceName)
	if canonical == "" || vaultDir == "" {
		return
	}
	_ = filepath.WalkDir(vaultDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		base := d.Name()
		idx := strings.Index(base, ".conflict-")
		if idx < 0 {
			return nil
		}
		rest := base[idx+len(".conflict-"):]
		dot := strings.LastIndex(rest, ".")
		if dot <= 0 {
			return nil
		}
		embedded := rest[:dot]
		if NormalizeDeviceName(embedded) != canonical || embedded == deviceName {
			return nil
		}
		newBase := base[:idx] + ".conflict-" + deviceName + rest[dot:]
		_ = os.Rename(path, filepath.Join(filepath.Dir(path), newBase))
		return nil
	})
}
