package importer

import (
	"archive/zip"
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseMapping(t *testing.T) {
	tests := []struct {
		name    string
		mapping string
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "valid mapping string",
			mapping: "title=Name, username=Login, password=Secret, otp=Authenticator",
			want: map[string]string{
				"title":    "Name",
				"username": "Login",
				"password": "Secret",
				"otp":      "Authenticator",
			},
		},
		{
			name:    "empty mapping",
			mapping: "",
			want:    nil,
		},
		{
			name:    "invalid format missing equals",
			mapping: "title=Name,password",
			wantErr: true,
		},
		{
			name:    "empty field",
			mapping: "=Name",
			wantErr: true,
		},
		{
			name:    "empty column",
			mapping: "title=",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMapping(tt.mapping)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMapping() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseMapping() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "trims spaces and slashes", path: "  /work/aws/  ", want: "work/aws"},
		{name: "replaces spaces with dashes", path: "Bank Checking", want: "Bank-Checking"},
		{name: "replaces dot dot with dash", path: "../secrets/..", want: "-/secrets/-"},
		{name: "strips windows-invalid chars", path: `Bank "Checking"`, want: "Bank-Checking"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizePath(tt.path); got != tt.want {
				t.Fatalf("NormalizePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestApplyPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		path   string
		want   string
	}{
		{name: "with prefix and path", prefix: "work", path: "aws", want: "work/aws"},
		{name: "empty prefix", prefix: "", path: "github.com", want: "github.com"},
		{name: "empty path", prefix: "personal", path: "", want: "personal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ApplyPrefix(tt.prefix, tt.path); got != tt.want {
				t.Fatalf("ApplyPrefix(%q, %q) = %q, want %q", tt.prefix, tt.path, got, tt.want)
			}
		})
	}
}

func TestOnePUXImporterParse(t *testing.T) {
	f := openFixture(t, "../../testdata/importer/onepux/sample.1pux")
	defer f.Close()

	entries, err := (&onePUXImporter{}).Parse(f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	github := findEntryByUsername(t, entries, "user@example.com")
	assertStringField(t, github.Data, "password", "mysecretpassword")
	assertStringField(t, github.Data, "url", "https://github.com/login")
	assertStringField(t, github.Data, "notes", "Personal GitHub account used for open source.")
	assertStringSliceField(t, github.Data, "tags", []string{"personal", "source control"})

	aws := findEntryByUsername(t, entries, "admin@company.com")
	assertStringField(t, aws.Data, "password", "work-aws-secret")
	assertStringField(t, aws.Data, "url", "https://signin.aws.amazon.com/console")
	assertStringSliceField(t, aws.Data, "tags", []string{"work", "cloud"})

	for _, entry := range entries {
		if got, _ := entry.Data["password"].(string); got == "do-not-import" {
			t.Fatal("trashed 1PUX item was imported")
		}
	}
}

func TestOnePUXImporterParsePathsAndTrashedItems(t *testing.T) {
	data := onePUXZip(t, `{
		"accounts": [{
			"vaults": [{
				"items": [
					{
						"categoryUuid": "001",
						"title": "GitHub",
						"overview": {"urls": [{"url": "https://github.com/login"}]},
						"details": {
							"notesPlain": "active login",
							"loginFields": [
								{"designation": "username", "value": "user@example.com"},
								{"designation": "password", "value": "mysecretpassword"}
							]
						}
					},
					{
						"categoryUuid": "001",
						"title": "Deleted Example",
						"trashed": true,
						"details": {
							"loginFields": [
								{"designation": "password", "value": "do-not-import"}
							]
						}
					},
					{
						"categoryUuid": "003",
						"title": "Secure Note",
						"details": {"notesPlain": "not a login"}
					}
				]
			}]
		}]
	}`)

	entries, err := (&onePUXImporter{}).Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Path != "GitHub" {
		t.Fatalf("entry path = %q, want %q", entry.Path, "GitHub")
	}
	assertStringField(t, entry.Data, "username", "user@example.com")
	assertStringField(t, entry.Data, "password", "mysecretpassword")
	assertStringField(t, entry.Data, "url", "https://github.com/login")
}

func TestBitwardenImporterParse(t *testing.T) {
	f := openFixture(t, "../../testdata/importer/bitwarden/sample.json")
	defer f.Close()

	entries, err := (&bitwardenImporter{}).Parse(f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("Parse() returned %d entries, want 2", len(entries))
	}

	github := findEntry(t, entries, "Personal/GitHub")
	assertStringField(t, github.Data, "username", "user@example.com")
	assertStringField(t, github.Data, "password", "mysecretpassword")
	assertStringField(t, github.Data, "url", "https://github.com/login")
	assertStringSliceField(t, github.Data, "urls", []string{"https://github.com/login", "https://github.com/"})
	assertTOTPSecret(t, github.Data, "JBSWY3DPEHPK3PXP")

	aws := findEntry(t, entries, "Work/AWS-Console")
	assertStringField(t, aws.Data, "username", "admin@company.com")
	assertStringField(t, aws.Data, "password", "")
	assertStringField(t, aws.Data, "url", "https://signin.aws.amazon.com/console")
	if _, ok := aws.Data["totp"]; ok {
		t.Fatal("AWS entry unexpectedly contains TOTP data")
	}
}

func TestBitwardenImporterParseCard(t *testing.T) {
	cardJSON := strings.Join([]string{
		`{"folders":[{"id":"f-pay","name":"Payment"}],`,
		`"items":[{`,
		`"type":2,"name":"Visa Personal","folderId":"f-pay",`,
		`"card":{"cardholderName":"Jane Doe","brand":"Visa",`,
		`"number":"4111111111111111","expMonth":"12","expYear":"2028","code":"123"},`,
		`"fields":[{"name":"notes","value":"primary card"}]`,
		`}]}`,
	}, "")

	entries, err := (&bitwardenImporter{}).Parse(strings.NewReader(cardJSON))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Path != "Payment/Visa-Personal" {
		t.Errorf("path = %q, want Payment/Visa-Personal", entry.Path)
	}
	assertStringField(t, entry.Data, "card_number", "4111111111111111")
	assertStringField(t, entry.Data, "cardholder", "Jane Doe")
	assertStringField(t, entry.Data, "expiry_month", "12")
	assertStringField(t, entry.Data, "expiry_year", "2028")
	assertStringField(t, entry.Data, "cvc", "123")
	assertStringField(t, entry.Data, "subtype", "card")
	assertStringField(t, entry.Data, "notes", "primary card")

	if entry.SecretMetadata == nil {
		t.Fatal("card entry should have SecretMetadata set")
	}
	if entry.SecretMetadata.Type != "payment" {
		t.Errorf("SecretMetadata.Type = %q, want payment", entry.SecretMetadata.Type)
	}
}

func TestCSVImporterParseDefaultMapping(t *testing.T) {
	f := openFixture(t, "../../testdata/importer/csv/sample.csv")
	defer f.Close()

	entries, err := NewCSV("").Parse(f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
	}

	github := findEntry(t, entries, "GitHub,-Personal")
	assertStringField(t, github.Data, "username", "user@example.com")
	assertStringField(t, github.Data, "notes", "Primary account, includes comma in title")

	bank := findEntry(t, entries, "Bank-Checking")
	assertStringField(t, bank.Data, "password", "p@ss,with,commas")
	assertStringField(t, bank.Data, "notes", "Security questions: mother's maiden name? Use generated answers.")
}

func TestCSVImporterParseCustomMapping(t *testing.T) {
	csvData := strings.NewReader(strings.Join([]string{
		"name,login,secret,website,comment,authenticator",
		"Example,user@example.com,password123,https://example.com,custom notes,JBSWY3DPEHPK3PXP",
	}, "\n"))
	mapping := "path=name,username=login,password=secret,url=website,notes=comment,totp.secret=authenticator"

	entries, err := NewCSV(mapping).Parse(csvData)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}

	entry := entries[0]
	if entry.Path != "Example" {
		t.Fatalf("entry path = %q, want %q", entry.Path, "Example")
	}
	assertStringField(t, entry.Data, "username", "user@example.com")
	assertStringField(t, entry.Data, "password", "password123")
	assertStringField(t, entry.Data, "url", "https://example.com")
	assertStringField(t, entry.Data, "notes", "custom notes")
	assertTOTPSecret(t, entry.Data, "JBSWY3DPEHPK3PXP")
}

func TestParsePassEntry(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string]any
	}{
		{
			name:    "password only",
			content: "secret\n",
			want:    map[string]any{"password": "secret"},
		},
		{
			name: "metadata and totp",
			content: strings.Join([]string{
				"work-aws-secret",
				"url: https://aws.amazon.com",
				"username: admin@company.com",
				"otpauth://totp/Amazon?secret=JBSWY3DPEHPK3PXP&issuer=Amazon",
			}, "\n"),
			want: map[string]any{
				"password": "work-aws-secret",
				"url":      "https://aws.amazon.com",
				"username": "admin@company.com",
				"totp":     "otpauth://totp/Amazon?secret=JBSWY3DPEHPK3PXP&issuer=Amazon",
			},
		},
		{
			name: "notes preserve unrecognized lines",
			content: strings.Join([]string{
				"secret",
				"first note line",
				"second note line",
			}, "\r\n"),
			want: map[string]any{
				"password": "secret",
				"notes":    "first note line\nsecond note line",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePassEntry(tt.content)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parsePassEntry() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestPassEntryPath(t *testing.T) {
	tests := []struct {
		relPath string
		want    string
	}{
		{relPath: "github.com.gpg", want: "github.com"},
		{relPath: "work/aws.gpg", want: "work/aws"},
		{relPath: "work/Team Login.gpg", want: "work/Team-Login"},
	}

	for _, tt := range tests {
		t.Run(tt.relPath, func(t *testing.T) {
			if got := passEntryPath(tt.relPath); got != tt.want {
				t.Fatalf("passEntryPath(%q) = %q, want %q", tt.relPath, got, tt.want)
			}
		})
	}
}

func openFixture(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture %s: %v", path, err)
	}
	return f
}

func onePUXZip(t *testing.T, exportJSON string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("export.json")
	if err != nil {
		t.Fatalf("create export.json in zip: %v", err)
	}
	if _, err := w.Write([]byte(exportJSON)); err != nil {
		t.Fatalf("write export.json in zip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func findEntry(t *testing.T, entries []ImportedEntry, path string) ImportedEntry {
	t.Helper()
	for _, entry := range entries {
		if entry.Path == path {
			return entry
		}
	}
	t.Fatalf("entry with path %q not found in %#v", path, entries)
	return ImportedEntry{}
}

func findEntryByUsername(t *testing.T, entries []ImportedEntry, username string) ImportedEntry {
	t.Helper()
	for _, entry := range entries {
		if got, _ := entry.Data["username"].(string); got == username {
			return entry
		}
	}
	t.Fatalf("entry with username %q not found in %#v", username, entries)
	return ImportedEntry{}
}

func assertStringField(t *testing.T, data map[string]any, key, want string) {
	t.Helper()
	got, ok := data[key].(string)
	if !ok {
		t.Fatalf("data[%q] = %#v, want string %q", key, data[key], want)
	}
	if got != want {
		t.Fatalf("data[%q] = %q, want %q", key, got, want)
	}
}

func assertStringSliceField(t *testing.T, data map[string]any, key string, want []string) {
	t.Helper()
	got, ok := data[key].([]string)
	if !ok {
		t.Fatalf("data[%q] = %#v, want []string %#v", key, data[key], want)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("data[%q] = %#v, want %#v", key, got, want)
	}
}

func assertTOTPSecret(t *testing.T, data map[string]any, want string) {
	t.Helper()
	totp, ok := data["totp"].(map[string]any)
	if !ok {
		t.Fatalf("data[totp] = %#v, want map", data["totp"])
	}
	got, ok := totp["secret"].(string)
	if !ok {
		t.Fatalf("totp[secret] = %#v, want string %q", totp["secret"], want)
	}
	if got != want {
		t.Fatalf("totp[secret] = %q, want %q", got, want)
	}
}
