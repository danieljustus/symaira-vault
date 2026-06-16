package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestVersionResult_String(t *testing.T) {
	v := VersionResult{
		Version: "1.2.3",
		Commit:  "abc1234",
		Built:   "2026-01-15",
	}

	got := v.String()
	want := "symvault 1.2.3 (commit: abc1234, built: 2026-01-15)"
	if got != want {
		t.Errorf("VersionResult.String() = %q, want %q", got, want)
	}
}

func TestVersionResult_String_DevVersion(t *testing.T) {
	v := VersionResult{
		Version: "dev",
		Commit:  "none",
		Built:   "unknown",
	}

	got := v.String()
	want := "symvault dev (commit: none, built: unknown)"
	if got != want {
		t.Errorf("VersionResult.String() = %q, want %q", got, want)
	}
}

func TestVersionResult_JSONTags(t *testing.T) {
	v := VersionResult{
		Version: "1.0.0",
		Commit:  "abc1234",
		Built:   "2026-01-15",
	}

	// Verify JSON tags work by marshaling
	data := marshalJSON(t, v)
	if data == "" {
		t.Fatal("marshalJSON returned empty string")
	}

	// Verify the fields are present
	for _, field := range []string{`"version":"1.0.0"`, `"commit":"abc1234"`, `"built":"2026-01-15"`} {
		if !contains(data, field) {
			t.Errorf("JSON output missing %q", field)
		}
	}
}

func TestSetVersionInfo(t *testing.T) {
	// Save original values
	origVersion := AppVersion
	origCommit := AppCommit
	origDate := AppDate
	t.Cleanup(func() {
		AppVersion = origVersion
		AppCommit = origCommit
		AppDate = origDate
		RootCmd.Version = origVersion
	})

	SetVersionInfo("3.0.0", "deadbeef", "2026-06-16")

	if AppVersion != "3.0.0" {
		t.Errorf("AppVersion = %q, want 3.0.0", AppVersion)
	}
	if AppCommit != "deadbeef" {
		t.Errorf("AppCommit = %q, want deadbeef", AppCommit)
	}
	if AppDate != "2026-06-16" {
		t.Errorf("AppDate = %q, want 2026-06-16", AppDate)
	}
	if RootCmd.Version != "3.0.0" {
		t.Errorf("RootCmd.Version = %q, want 3.0.0", RootCmd.Version)
	}
}

func TestAppVersionStr(t *testing.T) {
	origVersion := AppVersion
	t.Cleanup(func() { AppVersion = origVersion })

	AppVersion = "5.5.5"
	if got := AppVersionStr(); got != "5.5.5" {
		t.Errorf("AppVersionStr() = %q, want 5.5.5", got)
	}
}

func TestVersionResult_EmptyFields(t *testing.T) {
	v := VersionResult{}
	got := v.String()
	want := "symvault  (commit: , built: )"
	if got != want {
		t.Errorf("VersionResult.String() = %q, want %q", got, want)
	}
}

func TestVersionResult_YAMLTags(t *testing.T) {
	v := VersionResult{
		Version: "1.0.0",
		Commit:  "abc",
		Built:   "2026-01-01",
	}

	data := marshalYAML(t, v)
	if data == "" {
		t.Fatal("marshalYAML returned empty string")
	}

	// YAML should contain the field names
	for _, field := range []string{"version:", "commit:", "built:"} {
		if !contains(data, field) {
			t.Errorf("YAML output missing %q", field)
		}
	}
}

func marshalJSON(t *testing.T, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}
	return string(data)
}

func marshalYAML(t *testing.T, v interface{}) string {
	t.Helper()
	data, err := yaml.Marshal(v)
	if err != nil {
		t.Fatalf("yaml.Marshal error = %v", err)
	}
	return string(data)
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
