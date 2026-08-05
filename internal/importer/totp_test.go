package importer

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
)

// validTOTPSecret is a 32-character Base32 secret that decodes to 20 bytes,
// satisfying crypto.ValidateTOTPSecret's 16-byte minimum.
const validTOTPSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

var (
	wantTOTPDefault = map[string]any{
		"secret":    validTOTPSecret,
		"algorithm": "SHA1",
		"digits":    float64(6),
		"period":    float64(30),
	}
	wantTOTPSHA256 = map[string]any{
		"secret":    validTOTPSecret,
		"algorithm": "SHA256",
		"digits":    float64(8),
		"period":    float64(60),
	}
)

func TestParseTOTP(t *testing.T) {
	uri := "otpauth://totp/Example:user@example.com?secret=" + validTOTPSecret + "&issuer=Example"

	tests := []struct {
		name    string
		value   string
		want    map[string]any
		wantErr string
	}{
		{
			name:  "bare base32 secret",
			value: validTOTPSecret,
			want:  wantTOTPDefault,
		},
		{
			name:  "bare secret with spaces",
			value: "JBSWY3DPEHPK3PXP JBSWY3DPEHPK3PXP",
			want: map[string]any{
				"secret":    "JBSWY3DPEHPK3PXP JBSWY3DPEHPK3PXP",
				"algorithm": "SHA1",
				"digits":    float64(6),
				"period":    float64(30),
			},
		},
		{
			name:  "plain otpauth uri with issuer and label",
			value: uri,
			want:  wantTOTPDefault,
		},
		{
			name:  "uri without issuer or label",
			value: "otpauth://totp/Example?secret=" + validTOTPSecret,
			want:  wantTOTPDefault,
		},
		{
			name:  "uri with custom algorithm digits period",
			value: "otpauth://totp/Example?secret=" + validTOTPSecret + "&algorithm=SHA256&digits=8&period=60",
			want:  wantTOTPSHA256,
		},
		{
			name:  "uri with lowercase algorithm",
			value: "otpauth://totp/Example?secret=" + validTOTPSecret + "&algorithm=sha256&digits=8&period=60",
			want:  wantTOTPSHA256,
		},
		{
			name:  "uppercase scheme and type",
			value: "OTPAUTH://TOTP/Example?secret=" + validTOTPSecret,
			want:  wantTOTPDefault,
		},
		{
			name:    "hotp rejected",
			value:   "otpauth://hotp/Example?secret=" + validTOTPSecret,
			wantErr: "only otpauth://totp",
		},
		{
			name:    "missing secret parameter",
			value:   "otpauth://totp/Example?issuer=Example",
			wantErr: "missing the secret parameter",
		},
		{
			name:    "secret too short",
			value:   "JBSWY3DPEHPK3PXP",
			wantErr: "too short",
		},
		{
			name:    "not base32",
			value:   "not-a-valid-base32-secret!!",
			wantErr: "Base32",
		},
		{
			name:    "invalid digits",
			value:   "otpauth://totp/Example?secret=" + validTOTPSecret + "&digits=7",
			wantErr: "digits",
		},
		{
			name:    "invalid period",
			value:   "otpauth://totp/Example?secret=" + validTOTPSecret + "&period=0",
			wantErr: "period",
		},
		{
			name:    "invalid algorithm",
			value:   "otpauth://totp/Example?secret=" + validTOTPSecret + "&algorithm=MD5",
			wantErr: "algorithm",
		},
		{
			name:    "malformed uri",
			value:   "otpauth://to tp/Example?secret=" + validTOTPSecret,
			wantErr: "parse otpauth URI",
		},
		{
			name:    "empty value",
			value:   "",
			wantErr: "empty TOTP value",
		},
		{
			name:    "whitespace only",
			value:   "   ",
			wantErr: "empty TOTP value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTOTP(tt.value)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseTOTP(%q) = %#v, want error containing %q", tt.value, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseTOTP(%q) error = %q, want it to contain %q", tt.value, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTOTP(%q) error = %v", tt.value, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseTOTP(%q) = %#v, want %#v", tt.value, got, tt.want)
			}
		})
	}
}

// TestTOTPRoundTripBitwarden verifies that bitwarden login.totp values (bare
// secret or otpauth:// URI) are normalized into the identical structured
// totp map, that URI parameters are preserved, and that malformed values are
// skipped with a per-entry warning.
func TestTOTPRoundTripBitwarden(t *testing.T) {
	f := openFixture(t, "testdata/totp/bitwarden.json")
	defer f.Close()

	entries, err := (&bitwardenImporter{}).Parse(f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	assertTOTPRoundTripCases(t, entries, NormalizePath)
}

// TestTOTPRoundTripCSV covers the same cases through the CSV otp column.
func TestTOTPRoundTripCSV(t *testing.T) {
	f := openFixture(t, "testdata/totp/csv.csv")
	defer f.Close()

	entries, err := NewCSV("").Parse(f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	assertTOTPRoundTripCases(t, entries, NormalizePath)
}

// TestTOTPRoundTripOnePUX covers the same cases through 1pux OTP section
// fields. 1Password entry paths are not normalized.
func TestTOTPRoundTripOnePUX(t *testing.T) {
	exportJSON, err := os.ReadFile("testdata/totp/onepux.json")
	if err != nil {
		t.Fatalf("read onepux fixture: %v", err)
	}

	entries, err := (&onePUXImporter{}).Parse(bytes.NewReader(onePUXZip(t, string(exportJSON))))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	assertTOTPRoundTripCases(t, entries, func(name string) string { return name })
}

// TestTOTPRoundTripPass covers the same cases through pass otpauth:// lines.
func TestTOTPRoundTripPass(t *testing.T) {
	for _, tt := range []struct {
		fixture string
		want    map[string]any
	}{
		{fixture: "testdata/totp/pass-uri.txt", want: wantTOTPDefault},
		{fixture: "testdata/totp/pass-sha256.txt", want: wantTOTPSHA256},
	} {
		content, err := os.ReadFile(tt.fixture)
		if err != nil {
			t.Fatalf("read fixture %s: %v", tt.fixture, err)
		}

		data, warnings := parsePassEntry(string(content))
		if len(warnings) != 0 {
			t.Fatalf("parsePassEntry(%s) warnings = %v, want none", tt.fixture, warnings)
		}
		assertTOTPMap(t, data, tt.want)
		assertTOTPGenerates(t, data)
	}

	malformed, err := os.ReadFile("testdata/totp/pass-malformed.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	data, warnings := parsePassEntry(string(malformed))
	if _, ok := data["totp"]; ok {
		t.Fatal("malformed pass TOTP line should not produce a totp field")
	}
	if len(warnings) == 0 {
		t.Fatal("malformed pass TOTP line should produce a warning")
	}
	if !strings.Contains(warnings[0], "totp") {
		t.Fatalf("warning %q should mention totp", warnings[0])
	}
}

// assertTOTPRoundTripCases asserts the shared round-trip expectations for the
// four fixture entries (bare secret, plain URI, SHA256 URI, malformed URI).
func assertTOTPRoundTripCases(t *testing.T, entries []ImportedEntry, pathOf func(string) string) {
	t.Helper()

	bare := findEntry(t, entries, pathOf("Bare Secret"))
	uri := findEntry(t, entries, pathOf("Plain URI"))
	sha := findEntry(t, entries, pathOf("SHA256 URI"))
	mal := findEntry(t, entries, pathOf("Malformed URI"))

	for _, entry := range []ImportedEntry{bare, uri, sha} {
		if len(entry.Warnings) != 0 {
			t.Fatalf("entry %q should have no warnings, got %v", entry.Path, entry.Warnings)
		}
	}
	assertTOTPMap(t, bare.Data, wantTOTPDefault)
	assertTOTPMap(t, uri.Data, wantTOTPDefault)
	assertTOTPMap(t, sha.Data, wantTOTPSHA256)

	// A bare Base32 secret and an equivalent otpauth:// URI must produce
	// byte-identical vault entries.
	bareJSON, err := json.Marshal(bare.Data["totp"])
	if err != nil {
		t.Fatalf("marshal bare totp: %v", err)
	}
	uriJSON, err := json.Marshal(uri.Data["totp"])
	if err != nil {
		t.Fatalf("marshal uri totp: %v", err)
	}
	if !bytes.Equal(bareJSON, uriJSON) {
		t.Fatalf("bare secret and URI produced different totp data: %s vs %s", bareJSON, uriJSON)
	}

	// The structured shape validates and generates codes for every importer.
	for _, entry := range []ImportedEntry{bare, uri, sha} {
		if err := cryptopkg.ValidateTOTPData(entry.Data); err != nil {
			t.Fatalf("ValidateTOTPData(%q) error = %v", entry.Path, err)
		}
		assertTOTPGenerates(t, entry.Data)
	}

	// Malformed values are skipped with an actionable per-entry warning.
	if _, ok := mal.Data["totp"]; ok {
		t.Fatal("malformed entry should not carry totp data")
	}
	if len(mal.Warnings) == 0 {
		t.Fatal("malformed entry should carry a TOTP warning")
	}
	if !strings.Contains(mal.Warnings[0], "totp") {
		t.Fatalf("warning %q should mention totp", mal.Warnings[0])
	}
}

// assertTOTPMap asserts that data["totp"] is a map exactly matching want.
func assertTOTPMap(t *testing.T, data map[string]any, want map[string]any) {
	t.Helper()
	got, ok := data["totp"].(map[string]any)
	if !ok {
		t.Fatalf("data[totp] = %#v, want map[string]any %#v", data["totp"], want)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("data[totp] = %#v, want %#v", got, want)
	}
}

// assertTOTPGenerates verifies that the entry's totp configuration produces a
// code with the configured digit count, i.e. the parsed parameters are the
// ones actually used for code generation.
func assertTOTPGenerates(t *testing.T, data map[string]any) {
	t.Helper()
	totp, ok := data["totp"].(map[string]any)
	if !ok {
		t.Fatalf("data[totp] = %#v, want map", data["totp"])
	}
	secret, _ := totp["secret"].(string)
	algorithm, _ := totp["algorithm"].(string)
	digits := int(totp["digits"].(float64))
	period := int(totp["period"].(float64))

	code, err := cryptopkg.GenerateTOTP(secret, algorithm, digits, period)
	if err != nil {
		t.Fatalf("GenerateTOTP(%q, %q, %d, %d) error = %v", secret, algorithm, digits, period, err)
	}
	if len(code.Code) != digits {
		t.Fatalf("generated code %q has %d digits, want %d", code.Code, len(code.Code), digits)
	}
	for _, r := range code.Code {
		if r < '0' || r > '9' {
			t.Fatalf("generated code %q contains non-digit characters", code.Code)
		}
	}
	if code.Period != period {
		t.Fatalf("generated code period = %d, want %d", code.Period, period)
	}
}
