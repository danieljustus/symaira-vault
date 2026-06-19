package mcp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
)

// TestServeLongDescription_AdvertisesResolvedConfigPath guards against the
// serve help text drifting away from the actual path resolver. New installs
// resolve to the XDG config directory, so the advertised default must be the
// resolver-derived path, with the legacy location clearly marked as a fallback.
func TestServeLongDescription_AdvertisesResolvedConfigPath(t *testing.T) {
	long := serveLongDescription()

	wantDefault := filepath.Join(config.DefaultConfigDir(), "config.yaml")
	if !strings.Contains(long, wantDefault) {
		t.Errorf("serve help does not advertise the resolved default config path %q; got:\n%s", wantDefault, long)
	}

	if !strings.Contains(long, config.LegacyVaultSubdir) {
		t.Errorf("serve help does not mention the legacy %q fallback; got:\n%s", config.LegacyVaultSubdir, long)
	}

	// The legacy path may appear, but only when marked as legacy — it must not
	// be presented as the default.
	if strings.Contains(long, "~/"+config.LegacyVaultSubdir) && !strings.Contains(long, "legacy") {
		t.Errorf("serve help advertises the legacy path without marking it legacy:\n%s", long)
	}
}
