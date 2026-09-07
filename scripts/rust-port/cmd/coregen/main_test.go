package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildErrorFixtureIsDeterministic(t *testing.T) {
	meta := oracle{Commit: "test", Release: "v0.0.0"}
	first, err := marshalJSON(buildErrorFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalJSON(buildErrorFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("error fixture generation is not deterministic")
	}
}

func TestBuildSecretRefFixtureIsDeterministic(t *testing.T) {
	meta := oracle{Commit: "test", Release: "v0.0.0"}
	first, err := marshalJSON(buildSecretRefFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalJSON(buildSecretRefFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("secret-ref fixture generation is not deterministic")
	}
}

func TestBuildRedactFixtureIsDeterministic(t *testing.T) {
	meta := oracle{Commit: "test", Release: "v0.0.0"}
	first, err := marshalJSON(buildRedactFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalJSON(buildRedactFixture(meta))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("redact fixture generation is not deterministic")
	}
}

func TestBuildCryptoFixtureIsDeterministicAndCoversBoundaries(t *testing.T) {
	fixture := buildCryptoFixture(oracle{Commit: "test", Release: "v0.0.0"})
	first, err := marshalJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalJSON(buildCryptoFixture(oracle{Commit: "test", Release: "v0.0.0"}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("password/TOTP fixture generation is not deterministic")
	}
	if len(fixture.PasswordCases) < 5 || len(fixture.StrengthCases) < 5 || len(fixture.TOTPCases) < 5 {
		t.Fatalf("crypto fixture coverage is too small: passwords=%d strengths=%d totp=%d", len(fixture.PasswordCases), len(fixture.StrengthCases), len(fixture.TOTPCases))
	}
	for _, tc := range fixture.PasswordCases {
		if tc.Expected != "" && tc.Error != "" {
			t.Fatalf("password case %q has both result and error", tc.Name)
		}
	}

	strengthByName := make(map[string]strengthCase, len(fixture.StrengthCases))
	for _, tc := range fixture.StrengthCases {
		strengthByName[tc.Name] = tc
	}
	for _, name := range []string{"unicode_decimal_digits_across_scripts", "unicode_decimal_digits"} {
		tc, ok := strengthByName[name]
		if !ok {
			t.Fatalf("missing Unicode decimal-digit fixture case %q", name)
		}
		if containsString(tc.Missing, "digits") {
			t.Fatalf("Go oracle classified decimal digits as missing in %q", name)
		}
	}
	nonDecimal, ok := strengthByName["unicode_non_decimal_numerics"]
	if !ok {
		t.Fatal("missing Unicode non-decimal numeric fixture case")
	}
	if !containsString(nonDecimal.Missing, "digits") {
		t.Fatal("Go oracle classified non-decimal numerics as decimal digits")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestBuildFixtureCoversStableTaxonomy(t *testing.T) {
	fixture := buildErrorFixture(oracle{Commit: "test", Release: "test"})
	wantExitCodes := []namedInt{
		{"success", 0}, {"general", 1}, {"not_found", 2}, {"not_initialized", 3},
		{"locked", 4}, {"permission_denied", 5}, {"config", 6}, {"doctor_warn", 7},
		{"doctor_fail", 8}, {"invalid_input", 9}, {"usage", 9}, {"update_available", 10},
	}
	if !reflect.DeepEqual(fixture.ExitCodes, wantExitCodes) {
		t.Fatalf("exit codes = %#v, want %#v", fixture.ExitCodes, wantExitCodes)
	}
	wantKinds := []namedInt{{"none", 0}, {"not_found", 1}, {"field_not_found", 2}, {"read_failed", 3}, {"write_failed", 4}}
	if !reflect.DeepEqual(fixture.ErrorKinds, wantKinds) {
		t.Fatalf("error kinds = %#v, want %#v", fixture.ErrorKinds, wantKinds)
	}
	if len(fixture.CorekitReverse) != 7 {
		t.Fatalf("corekit reverse mappings = %d, want 7", len(fixture.CorekitReverse))
	}
	wantCases := []string{
		"new", "not_found", "field_not_found", "read_failed", "read_failed_nil",
		"write_failed", "write_failed_nil", "not_initialized", "new_vault_not_initialized",
		"locked", "permission_denied", "invalid_input", "config_error", "internal",
		"already_exists", "custom_hint", "sentinel_priority",
	}
	gotCases := make([]string, len(fixture.Cases))
	for i, item := range fixture.Cases {
		gotCases[i] = item.Name
	}
	if !reflect.DeepEqual(gotCases, wantCases) {
		t.Fatalf("error cases = %#v, want %#v", gotCases, wantCases)
	}
}

func TestBuildSecretRefFixtureCoversGoOracle(t *testing.T) {
	fixture := buildSecretRefFixture(oracle{Commit: "test", Release: "v0.0.0"})
	if len(fixture.ParseRefCases) < 20 {
		t.Fatalf("unexpectedly few ParseRef cases: %d", len(fixture.ParseRefCases))
	}
	if len(fixture.ParseHandleCases) < 10 {
		t.Fatalf("unexpectedly few ParseSecretHandle cases: %d", len(fixture.ParseHandleCases))
	}

	// Verify both valid and invalid partitions exist
	validRef, invalidRef := 0, 0
	for _, tc := range fixture.ParseRefCases {
		if tc.Valid {
			validRef++
			if tc.Path == "" && tc.Input != "op:///github" {
				t.Fatalf("valid case %q has empty path", tc.Name)
			}
			if tc.Field == "" {
				t.Fatalf("valid case %q has empty field", tc.Name)
			}
		} else {
			invalidRef++
			if tc.ErrorMessage == "" {
				t.Fatalf("invalid case %q missing error message", tc.Name)
			}
		}
	}
	if validRef == 0 || invalidRef == 0 {
		t.Fatalf("ParseRef partition empty: valid=%d invalid=%d", validRef, invalidRef)
	}

	validHandles, invalidHandles := 0, 0
	for _, tc := range fixture.ParseHandleCases {
		if tc.Valid {
			validHandles++
			if tc.StringRepr == "" {
				t.Fatalf("valid handle %q missing string_repr", tc.Name)
			}
		} else {
			invalidHandles++
		}
	}
	if validHandles == 0 || invalidHandles == 0 {
		t.Fatalf("ParseHandle partition empty: valid=%d invalid=%d", validHandles, invalidHandles)
	}
}

func TestBuildRedactFixtureCoversGoOracle(t *testing.T) {
	fixture := buildRedactFixture(oracle{Commit: "test", Release: "v0.0.0"})
	if fixture.Constants.Marker != "[REDACTED]" {
		t.Fatalf("unexpected marker: %q", fixture.Constants.Marker)
	}
	if fixture.Constants.BlockedText != "[REDACTED: output withheld]" {
		t.Fatalf("unexpected blocked text: %q", fixture.Constants.BlockedText)
	}
	if fixture.Constants.MinExactValueLen != 4 {
		t.Fatalf("unexpected min exact value len: %d", fixture.Constants.MinExactValueLen)
	}
	if fixture.Constants.MinTokenLen != 20 {
		t.Fatalf("unexpected min token len: %d", fixture.Constants.MinTokenLen)
	}
	if fixture.Constants.MinEntropyBitsPerChar != 4.85 {
		t.Fatalf("unexpected min entropy: %f", fixture.Constants.MinEntropyBitsPerChar)
	}
	if len(fixture.ExactValueCases) < 5 {
		t.Fatalf("unexpectedly few exact value cases: %d", len(fixture.ExactValueCases))
	}
	if len(fixture.EntropyCases) < 7 {
		t.Fatalf("unexpectedly few entropy cases: %d", len(fixture.EntropyCases))
	}
	if len(fixture.ScannerCases) < 8 {
		t.Fatalf("unexpectedly few scanner cases: %d", len(fixture.ScannerCases))
	}
	if len(fixture.TruthyCases) < 15 {
		t.Fatalf("unexpectedly few truthy cases: %d", len(fixture.TruthyCases))
	}
}

func TestNegativeControlFixtureDriftDetection(t *testing.T) {
	// Negative control: proving that drift detection reliably detects stale content
	meta := oracle{Commit: "test", Release: "v0.0.0"}
	expected, err := marshalJSON(buildSecretRefFixture(meta))
	if err != nil {
		t.Fatal(err)
	}

	tampered := bytes.ReplaceAll(expected, []byte(`"schema_version": 1`), []byte(`"schema_version": 99`))
	if bytes.Equal(expected, tampered) {
		t.Fatal("tampering failed to modify fixture")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(existing, expected) {
		t.Fatal("negative control failed: tampered file unexpectedly matches expected")
	}
}

func TestReadHeaderRejectsInvalidSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid_schema.json")
	if err := os.WriteFile(path, []byte(`{"schema_version": 2, "oracle": {"commit":"x","release":"y"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readHeader(path)
	if err == nil {
		t.Fatal("expected rejection of schema_version 2")
	}
	if !strings.Contains(err.Error(), "unsupported schema_version") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestRedactFixtureAuditEventsNeverContainSecrets(t *testing.T) {
	fixture := buildRedactFixture(oracle{Commit: "test", Release: "v0.0.0"})
	for _, sc := range fixture.ScannerCases {
		for _, sec := range sc.Secrets {
			if sec == "" || len(sec) < 4 {
				continue
			}
			for _, evt := range sc.AuditEvents {
				if strings.Contains(evt.Detector, sec) || strings.Contains(evt.Channel, sec) || strings.Contains(evt.CorrelationID, sec) {
					t.Fatalf("secret %q leaked in audit event: %+v", sec, evt)
				}
			}
			for _, f := range sc.Findings {
				if strings.Contains(f.Detector, sec) {
					t.Fatalf("secret %q leaked in finding: %+v", sec, f)
				}
			}
			if sc.ExpectedBlocked && strings.Contains(sc.ExpectedText, sec) {
				t.Fatalf("secret %q leaked in blocked output: %q", sec, sc.ExpectedText)
			}
		}
	}
}
