package vault_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestVaultDecoupling guards against regressions where internal/vault
// re-introduces forbidden dependencies (internal/git, internal/metrics, internal/ui, or os/exec).
// This ensures that internal/vault remains buildable for headless / non-desktop targets like iOS (ADR 0006 D2).
func TestVaultDecoupling(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "github.com/danieljustus/symaira-vault/internal/vault")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\nOutput: %s", err, string(out))
	}

	forbidden := []string{
		"internal/git",
		"internal/metrics",
		"internal/ui",
		"os/exec",
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		for _, f := range forbidden {
			if strings.Contains(trimmed, f) || trimmed == f {
				t.Errorf("forbidden dependency %q detected in internal/vault: %s", f, trimmed)
			}
		}
	}
}

// TestConfigDecoupling guards against regressions where internal/config
// re-introduces terminal UI dependencies (internal/ui).
func TestConfigDecoupling(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "github.com/danieljustus/symaira-vault/internal/config")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\nOutput: %s", err, string(out))
	}

	forbidden := []string{
		"internal/ui",
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		for _, f := range forbidden {
			if strings.Contains(trimmed, f) || trimmed == f {
				t.Errorf("forbidden dependency %q detected in internal/config: %s", f, trimmed)
			}
		}
	}
}
