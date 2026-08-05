package importer

import (
	"strings"
	"testing"
)

func TestAppleCSVProfile(t *testing.T) {
	f := openFixture(t, "testdata/csv/apple.csv")
	defer f.Close()

	imp, err := NewCSVProfile(FormatApple, "")
	if err != nil {
		t.Fatalf("NewCSVProfile() error = %v", err)
	}
	entries, err := imp.Parse(f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Parse() returned %d entries, want 3", len(entries))
	}

	github := findEntry(t, entries, "GitHub")
	assertStringField(t, github.Data, "username", "octocat@example.com")
	assertStringField(t, github.Data, "url", "https://github.com/login")
	assertStringField(t, github.Data, "password", "gh-apple-secret")
	assertStringField(t, github.Data, "notes", "Primary GitHub account")
	assertTOTPSecret(t, github.Data, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	assertTOTPParams(t, github.Data, "SHA1", float64(6), float64(30))

	icloud := findEntry(t, entries, "iCloud-Mail")
	if _, ok := icloud.Data["totp"]; ok {
		t.Errorf("entry without OTPAuth should not carry totp data")
	}

	bank := findEntry(t, entries, "Bank-of-Example")
	assertStringField(t, bank.Data, "notes", "Checking account, with comma")
	assertTOTPSecret(t, bank.Data, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
}

func TestChromeCSVProfile(t *testing.T) {
	f := openFixture(t, "testdata/csv/chrome.csv")
	defer f.Close()

	imp, err := NewCSVProfile(FormatChrome, "")
	if err != nil {
		t.Fatalf("NewCSVProfile() error = %v", err)
	}
	entries, err := imp.Parse(f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("Parse() returned %d entries, want 5", len(entries))
	}
	assertUniqueNonEmptyPaths(t, entries)

	github := findEntry(t, entries, "GitHub")
	assertStringField(t, github.Data, "username", "octocat@example.com")
	assertStringField(t, github.Data, "password", "gh-chrome-secret")
	assertStringField(t, github.Data, "notes", "Main GitHub account")

	// Empty name falls back to the URL host.
	google := findEntry(t, entries, "mail.google.com")
	assertStringField(t, google.Data, "username", "user@gmail.com")
	assertStringField(t, google.Data, "notes", "Google account without a name")

	// Duplicate title gets a -2 suffix.
	second := findEntry(t, entries, "GitHub-2")
	assertStringField(t, second.Data, "username", "second@example.com")

	assertStringField(t, findEntry(t, entries, "Company-VPN").Data, "password", "company-vpn-secret")
	assertStringField(t, findEntry(t, entries, "AWS-Console").Data, "password", "aws-admin-secret")
}

func TestFirefoxCSVProfile(t *testing.T) {
	f := openFixture(t, "testdata/csv/firefox.csv")
	defer f.Close()

	imp, err := NewCSVProfile(FormatFirefox, "")
	if err != nil {
		t.Fatalf("NewCSVProfile() error = %v", err)
	}
	entries, err := imp.Parse(f)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("Parse() returned %d entries, want 4", len(entries))
	}
	assertUniqueNonEmptyPaths(t, entries)

	github := findEntry(t, entries, "github.com")
	assertStringField(t, github.Data, "username", "octocat@example.com")
	assertStringField(t, github.Data, "password", "gh-firefox-secret")

	// Same host as the first row gets a -2 suffix.
	second := findEntry(t, entries, "github.com-2")
	assertStringField(t, second.Data, "username", "second@example.com")

	// HTTP basic-auth login derives its path from the URL host too.
	intranet := findEntry(t, entries, "intranet.example.com")
	assertStringField(t, intranet.Data, "username", "jdoe")
	assertStringField(t, intranet.Data, "password", "http-basic-secret")
}

func TestCSVProfileMappingOverride(t *testing.T) {
	csvData := strings.NewReader(strings.Join([]string{
		"name,url,username,password,note",
		"Example,https://example.com,user@example.com,secret,note text",
	}, "\n"))

	imp, err := NewCSVProfile(FormatChrome, "path=name,password=password")
	if err != nil {
		t.Fatalf("NewCSVProfile() error = %v", err)
	}
	entries, err := imp.Parse(csvData)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Path != "Example" {
		t.Errorf("path = %q, want Example", entry.Path)
	}
	assertStringField(t, entry.Data, "password", "secret")
	if _, ok := entry.Data["username"]; ok {
		t.Errorf("username should not be mapped with the override mapping")
	}
	if _, ok := entry.Data["note"]; ok {
		t.Errorf("note should not be mapped with the override mapping")
	}
}

func TestCSVProfileEmptyNameAndURL(t *testing.T) {
	csvData := strings.NewReader(strings.Join([]string{
		"name,url,username,password,note",
		",,user,secret,note text",
	}, "\n"))

	imp, err := NewCSVProfile(FormatChrome, "")
	if err != nil {
		t.Fatalf("NewCSVProfile() error = %v", err)
	}
	entries, err := imp.Parse(csvData)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}
	if entries[0].Path != "" {
		t.Errorf("path = %q, want empty when name and url are both empty", entries[0].Path)
	}
}

func TestCSVProfileInvalidTOTPWarning(t *testing.T) {
	csvData := strings.NewReader(strings.Join([]string{
		"Title,URL,Username,Password,Notes,OTPAuth",
		"Example,https://example.com,user,secret,notes,not-a-totp-value",
	}, "\n"))

	imp, err := NewCSVProfile(FormatApple, "")
	if err != nil {
		t.Fatalf("NewCSVProfile() error = %v", err)
	}
	entries, err := imp.Parse(csvData)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("Parse() returned %d entries, want 1", len(entries))
	}
	entry := entries[0]
	if _, ok := entry.Data["totp"]; ok {
		t.Errorf("invalid OTPAuth should not produce totp data")
	}
	if len(entry.Warnings) == 0 {
		t.Errorf("invalid OTPAuth should produce a warning")
	}
}

func TestDetectCSVProfile(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   Format
	}{
		{"apple", "Title,URL,Username,Password,Notes,OTPAuth", FormatApple},
		{"apple lowercase", "title,url,username,password,notes,otpauth", FormatApple},
		{"apple with spaces", "Title, URL, Username, Password, Notes, OTPAuth", FormatApple},
		{"chrome", "name,url,username,password,note", FormatChrome},
		{"chrome with path", "name,url,username,password,note,extra", FormatChrome},
		{"firefox", "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged", FormatFirefox},
		{"firefox minimal", "url,username,password,httpRealm", FormatFirefox},
		{"generic", "title,username,password,url,notes", FormatCSV},
		{"generic with otp", "title,username,password,url,notes,otp", FormatCSV},
		{"empty", "", FormatCSV},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var header []string
			if tt.header != "" {
				header = strings.Split(tt.header, ",")
			}
			if got := DetectCSVProfile(header); got != tt.want {
				t.Errorf("DetectCSVProfile(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestCSVEffectiveMapping(t *testing.T) {
	t.Run("apple profile default", func(t *testing.T) {
		mapping, err := CSVEffectiveMapping(FormatApple, "")
		if err != nil {
			t.Fatalf("CSVEffectiveMapping() error = %v", err)
		}
		if mapping["otp"] != "OTPAuth" {
			t.Errorf("otp column = %q, want OTPAuth", mapping["otp"])
		}
		if mapping["title"] != "Title" {
			t.Errorf("title column = %q, want Title", mapping["title"])
		}
	})

	t.Run("user mapping overrides profile", func(t *testing.T) {
		mapping, err := CSVEffectiveMapping(FormatChrome, "path=name,password=password")
		if err != nil {
			t.Fatalf("CSVEffectiveMapping() error = %v", err)
		}
		if len(mapping) != 2 {
			t.Errorf("mapping has %d entries, want 2", len(mapping))
		}
	})

	t.Run("generic default", func(t *testing.T) {
		mapping, err := CSVEffectiveMapping(FormatCSV, "")
		if err != nil {
			t.Fatalf("CSVEffectiveMapping() error = %v", err)
		}
		if mapping["title"] != "title" {
			t.Errorf("title column = %q, want title", mapping["title"])
		}
	})

	t.Run("invalid user mapping", func(t *testing.T) {
		if _, err := CSVEffectiveMapping(FormatFirefox, "nonsense"); err == nil {
			t.Fatal("expected error for invalid mapping")
		}
	})
}

func TestNewCSVProfileRejectsGenericFormat(t *testing.T) {
	if _, err := NewCSVProfile(FormatCSV, ""); err == nil {
		t.Fatal("expected error for format without a built-in profile")
	}
}

func TestNewSupportsProfiles(t *testing.T) {
	for _, format := range []Format{FormatApple, FormatChrome, FormatFirefox} {
		imp, err := New(format)
		if err != nil {
			t.Fatalf("New(%q) error = %v", format, err)
		}
		if _, ok := imp.(*csvImporter); !ok {
			t.Errorf("New(%q) = %T, want *csvImporter", format, imp)
		}
	}
}

func TestHostFromURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://github.com/login", "github.com"},
		{"http://example.com", "example.com"},
		{"example.com/path", "example.com"},
		{"user:pass@example.com:8080/x", "example.com"},
		{"https://sub.example.org:8443/a?b=c", "sub.example.org"},
		{"https://[::1]:8080/", "[::1]"},
		{"", ""},
		{"   ", ""},
	}
	for _, tt := range tests {
		if got := hostFromURL(tt.in); got != tt.want {
			t.Errorf("hostFromURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestUniquePath(t *testing.T) {
	used := make(map[string]bool)
	if got := uniquePath(used, "github.com"); got != "github.com" {
		t.Errorf("first path = %q, want github.com", got)
	}
	if got := uniquePath(used, "github.com"); got != "github.com-2" {
		t.Errorf("second path = %q, want github.com-2", got)
	}
	if got := uniquePath(used, "github.com"); got != "github.com-3" {
		t.Errorf("third path = %q, want github.com-3", got)
	}
	if got := uniquePath(used, ""); got != "" {
		t.Errorf("empty path = %q, want empty", got)
	}
}

func assertUniqueNonEmptyPaths(t *testing.T, entries []ImportedEntry) {
	t.Helper()
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.Path == "" {
			t.Errorf("entry has empty path: %#v", entry.Data)
			continue
		}
		if seen[entry.Path] {
			t.Errorf("duplicate path %q", entry.Path)
		}
		seen[entry.Path] = true
	}
}

func assertTOTPParams(t *testing.T, data map[string]any, algorithm string, digits, period float64) {
	t.Helper()
	totp, ok := data["totp"].(map[string]any)
	if !ok {
		t.Fatalf("data[totp] = %#v, want map", data["totp"])
	}
	if got := totp["algorithm"]; got != algorithm {
		t.Errorf("totp[algorithm] = %v, want %s", got, algorithm)
	}
	if got := totp["digits"]; got != digits {
		t.Errorf("totp[digits] = %v, want %v", got, digits)
	}
	if got := totp["period"]; got != period {
		t.Errorf("totp[period] = %v, want %v", got, period)
	}
}
