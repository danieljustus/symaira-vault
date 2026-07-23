package health

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestScryptBenchmarkResult_SlowFastAndBoundaryMachines exercises the pure
// comparison behind checkScryptBenchmark for #683 without depending on real
// scrypt timing: a "slow machine" (benchmark recommends the same or a lower
// work factor than configured), a "fast machine" (benchmark recommends
// higher), and the exact-match boundary.
func TestScryptBenchmarkResult_SlowFastAndBoundaryMachines(t *testing.T) {
	tests := []struct {
		name       string
		current    int
		wf         int
		explicit   bool
		wantStatus Status
		wantSubstr string
	}{
		{
			name:       "slow machine, wf below current",
			current:    18,
			wf:         12,
			explicit:   false,
			wantStatus: StatusOK,
			wantSubstr: "exceeds recommendation",
		},
		{
			name:       "boundary: wf equals current",
			current:    18,
			wf:         18,
			explicit:   false,
			wantStatus: StatusOK,
			wantSubstr: "matches recommendation",
		},
		{
			name:       "fast machine, implicit default below wf",
			current:    18,
			wf:         20,
			explicit:   false,
			wantStatus: StatusWarn,
			wantSubstr: "default work factor",
		},
		{
			name:       "fast machine, explicit config below wf",
			current:    18,
			wf:         20,
			explicit:   true,
			wantStatus: StatusWarn,
			wantSubstr: "explicitly configured work factor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := scryptBenchmarkResult(tt.current, tt.wf, 42*time.Millisecond, tt.explicit)
			if r.Status != tt.wantStatus {
				t.Errorf("Status = %v, want %v (message: %q)", r.Status, tt.wantStatus, r.Message)
			}
			if !strings.Contains(r.Message, tt.wantSubstr) {
				t.Errorf("Message = %q, want substring %q", r.Message, tt.wantSubstr)
			}
		})
	}
}

// TestScryptBenchmarkResult_WarnHintExplainsConfigAloneDoesNotReencrypt
// covers the #683 acceptance criterion that the warning must explain that
// changing the config value alone does not re-encrypt the existing
// identity.age.
func TestScryptBenchmarkResult_WarnHintExplainsConfigAloneDoesNotReencrypt(t *testing.T) {
	r := scryptBenchmarkResult(18, 20, 42*time.Millisecond, false)
	if r.Status != StatusWarn {
		t.Fatalf("Status = %v, want Warn", r.Status)
	}
	if !strings.Contains(r.Hint, "does not re-encrypt") {
		t.Errorf("Hint = %q, want it to mention that the config change alone does not re-encrypt identity.age", r.Hint)
	}
	if !strings.Contains(r.Hint, "migrate kdf") {
		t.Errorf("Hint = %q, want it to point at `migrate kdf`", r.Hint)
	}
}

func TestScryptWorkFactorIsExplicit(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/config.yaml"

	if scryptWorkFactorIsExplicit(configPath) {
		t.Error("missing config.yaml: expected not explicit")
	}

	writeFile(t, configPath, "vault:\n  format_version: 1\n")
	if scryptWorkFactorIsExplicit(configPath) {
		t.Error("config.yaml without scrypt_work_factor key: expected not explicit")
	}

	writeFile(t, configPath, "vault:\n  format_version: 1\n  scrypt_work_factor: 18\n")
	if !scryptWorkFactorIsExplicit(configPath) {
		t.Error("config.yaml with scrypt_work_factor key: expected explicit")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
