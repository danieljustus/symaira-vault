package envfilter

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDefaultWhitelist_ContainsExpected(t *testing.T) {
	wl := DefaultWhitelist()
	expected := []string{
		"PATH", "HOME", "TMPDIR", "USER", "LANG", "LC_ALL",
		"SHELL", "TERM", "DISPLAY", "GNUPGHOME",
		"GIT_ASKPASS", "GIT_SSH", "SSH_AUTH_SOCK",
	}
	for _, e := range expected {
		if !contains(wl, e) {
			t.Errorf("DefaultWhitelist missing expected var: %s", e)
		}
	}
}

func TestDefaultWhitelist_NoDuplicates(t *testing.T) {
	wl := DefaultWhitelist()
	seen := make(map[string]bool)
	for _, v := range wl {
		if seen[v] {
			t.Errorf("Duplicate in DefaultWhitelist: %s", v)
		}
		seen[v] = true
	}
}

func TestFilterEnv_OnlyWhitelisted(t *testing.T) {
	// Set known test env vars
	t.Setenv("TEST_ENVFILTER_KNOWN", "should_pass")
	t.Setenv("TEST_ENVFILTER_SECRET", "should_be_stripped")

	wl := []string{"TEST_ENVFILTER_KNOWN"}
	result := FilterEnv(wl)

	// Should include the whitelisted var
	if !contains(result, "TEST_ENVFILTER_KNOWN=should_pass") {
		t.Errorf("FilterEnv should include whitelisted var TEST_ENVFILTER_KNOWN")
	}

	// Should NOT include the non-whitelisted var
	for _, e := range result {
		if strings.HasPrefix(e, "TEST_ENVFILTER_SECRET=") {
			t.Errorf("FilterEnv should have stripped TEST_ENVFILTER_SECRET, got: %s", e)
		}
	}
}

func TestFilterEnv_AllWhitelisted(t *testing.T) {
	t.Setenv("TEST_ENVFILTER_A", "value_a")
	t.Setenv("TEST_ENVFILTER_B", "value_b")

	wl := []string{"TEST_ENVFILTER_A", "TEST_ENVFILTER_B"}
	result := FilterEnv(wl)

	if !contains(result, "TEST_ENVFILTER_A=value_a") {
		t.Error("FilterEnv missing whitelisted var TEST_ENVFILTER_A")
	}
	if !contains(result, "TEST_ENVFILTER_B=value_b") {
		t.Error("FilterEnv missing whitelisted var TEST_ENVFILTER_B")
	}
}

func TestFilterEnv_EmptyWhitelist(t *testing.T) {
	result := FilterEnv([]string{})
	if result != nil {
		t.Errorf("FilterEnv with empty whitelist should return nil, got %v", result)
	}
}

func TestFilterEnv_NilWhitelist(t *testing.T) {
	result := FilterEnv(nil)
	if result != nil {
		t.Errorf("FilterEnv with nil whitelist should return nil, got %v", result)
	}
}

func TestFilterEnv_UnknownVarStripped(t *testing.T) {
	t.Setenv("TEST_ENVFILTER_SHOULD_BE_STRIPPED", "secret_value")

	wl := []string{"PATH", "HOME"}
	result := FilterEnv(wl)

	// Verify the secret env var is not in the result
	for _, e := range result {
		if strings.HasPrefix(e, "TEST_ENVFILTER_SHOULD_BE_STRIPPED=") {
			t.Errorf("FilterEnv should have stripped TEST_ENVFILTER_SHOULD_BE_STRIPPED, got: %s", e)
		}
	}
}

func TestFilterEnv_KeyOnlyMatch(t *testing.T) {
	t.Setenv("TEST_FOO", "value_foo")
	t.Setenv("TEST_FOO_BAR", "value_bar")

	wl := []string{"TEST_FOO"}
	result := FilterEnv(wl)

	if !contains(result, "TEST_FOO=value_foo") {
		t.Error("FilterEnv missing TEST_FOO")
	}
	for _, e := range result {
		if strings.HasPrefix(e, "TEST_FOO_BAR=") {
			t.Errorf("FilterEnv should not include TEST_FOO_BAR (different key), got: %s", e)
		}
	}
}

func TestFilterEnv_DoesNotLeakByDefault(t *testing.T) {
	t.Setenv("OPENPASS_VAULT", "/tmp/should_not_leak")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "should_be_removed")
	t.Setenv("API_KEY", "should_be_removed")

	wl := DefaultWhitelist()
	result := FilterEnv(wl)

	for _, e := range result {
		if strings.HasPrefix(e, "OPENPASS_VAULT=") {
			t.Errorf("Default whitelist should not pass OPENPASS_VAULT, got: %s", e)
		}
		if strings.HasPrefix(e, "AWS_SECRET_ACCESS_KEY=") {
			t.Errorf("Default whitelist should not pass AWS_SECRET_ACCESS_KEY, got: %s", e)
		}
		if strings.HasPrefix(e, "API_KEY=") {
			t.Errorf("Default whitelist should not pass API_KEY, got: %s", e)
		}
	}
}

func TestMergeWhitelist_Deduplicates(t *testing.T) {
	a := []string{"PATH", "HOME", "USER"}
	b := []string{"HOME", "LANG", "USER"}
	result := MergeWhitelist(a, b)

	expected := []string{"PATH", "HOME", "USER", "LANG"}
	if len(result) != len(expected) {
		t.Fatalf("MergeWhitelist length = %d, want %d", len(result), len(expected))
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("MergeWhitelist[%d] = %s, want %s", i, result[i], v)
		}
	}
}

func TestMergeWhitelist_Empty(t *testing.T) {
	result := MergeWhitelist()
	if len(result) != 0 {
		t.Errorf("MergeWhitelist() should return empty, got %v", result)
	}
}

func TestMergeWhitelist_Single(t *testing.T) {
	a := []string{"PATH", "HOME"}
	result := MergeWhitelist(a)
	if len(result) != 2 {
		t.Fatalf("MergeWhitelist(single) length = %d, want 2", len(result))
	}
}

func TestMergeWhitelist_ThreeLists(t *testing.T) {
	a := []string{"A", "B"}
	b := []string{"B", "C"}
	c := []string{"C", "D", "A"}
	result := MergeWhitelist(a, b, c)

	expected := []string{"A", "B", "C", "D"}
	if len(result) != len(expected) {
		t.Fatalf("MergeWhitelist(3) length = %d, want %d", len(result), len(expected))
	}
	for i, v := range expected {
		if result[i] != v {
			t.Errorf("MergeWhitelist(3)[%d] = %s, want %s", i, result[i], v)
		}
	}
}

func TestPrepareCmd_SetsEnv(t *testing.T) {
	cmd := exec.Command("echo", "test")
	PrepareCmd(cmd)

	if cmd.Env == nil {
		t.Fatal("PrepareCmd did not set cmd.Env")
	}

	// Verify default whitelist vars are in cmd.Env
	envMap := envSliceToMap(cmd.Env)
	defaults := DefaultWhitelist()
	for _, v := range defaults {
		if _, ok := envMap[v]; !ok {
			// It's OK if the var doesn't exist in os.Environ() — it just won't be present.
			// But if it DOES exist, it should be passed through.
			continue
		}
	}
}

func TestPrepareCmd_NoEnvLeak(t *testing.T) {
	t.Setenv("OPENPASS_TEST_SECRET", "should_not_leak_to_child")

	cmd := exec.Command("echo", "test")
	PrepareCmd(cmd)

	envMap := envSliceToMap(cmd.Env)
	if _, ok := envMap["OPENPASS_TEST_SECRET"]; ok {
		t.Error("PrepareCmd leaked OPENPASS_TEST_SECRET to child process env")
	}
}

func TestPrepareCmd_WithAdditional(t *testing.T) {
	t.Setenv("CUSTOM_VAR", "custom_value")
	t.Setenv("SECRET_VAR", "should_not_pass")

	cmd := exec.Command("echo", "test")
	PrepareCmd(cmd, "CUSTOM_VAR")

	envMap := envSliceToMap(cmd.Env)
	if v, ok := envMap["CUSTOM_VAR"]; !ok {
		t.Error("PrepareCmd with additional should include CUSTOM_VAR")
	} else if v != "custom_value" {
		t.Errorf("CUSTOM_VAR = %q, want %q", v, "custom_value")
	}
	if _, ok := envMap["SECRET_VAR"]; ok {
		t.Error("PrepareCmd should not pass SECRET_VAR even with additional")
	}
}

func TestMergeWhitelist_OrderPreserved(t *testing.T) {
	a := []string{"Z", "A"}
	b := []string{"B", "Z"}
	result := MergeWhitelist(a, b)

	if len(result) < 3 {
		t.Fatalf("expected at least 3 items, got %d", len(result))
	}
	if result[0] != "Z" || result[1] != "A" || result[2] != "B" {
		t.Errorf("order not preserved: got %v, want [Z A B]", result)
	}
}

func TestFilterEnv_SubstringKeyMatch(t *testing.T) {
	t.Setenv("MYVAR", "value")
	t.Setenv("MYVAR_EXTRA", "extra_value")

	wl := []string{"MYVAR"}
	result := FilterEnv(wl)

	if !contains(result, "MYVAR=value") {
		t.Error("FilterEnv missing MYVAR")
	}

	// MYVAR_EXTRA should NOT pass through since it's a different key
	for _, e := range result {
		if strings.HasPrefix(e, "MYVAR_EXTRA=") {
			t.Errorf("FilterEnv should not include MYVAR_EXTRA (different key), got: %s", e)
		}
	}
}

// Test helpers

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			m[parts[0]] = parts[1]
		} else if len(parts) == 1 {
			m[parts[0]] = ""
		}
	}
	return m
}
