package importer

import (
	"fmt"
	"strings"
)

// Canonical (lowercase) CSV column names and vault field names used by the
// built-in profiles. They are declared once so header sniffing, profile
// mappings and path derivation share a single vocabulary.
const (
	csvColTitle            = "title"
	csvColURL              = "url"
	csvColUsername         = "username"
	csvColPassword         = "password"
	csvColNotes            = "notes"
	csvColOTPAuth          = "otpauth"
	csvColName             = "name"
	csvColNote             = "note"
	csvColHTTPRealm        = "httprealm"
	csvColFormActionOrigin = "formactionorigin"
	csvColGUID             = "guid"
	csvColTimeCreated      = "timecreated"
)

// CSVProfile is a built-in CSV import profile: the field→column mapping for
// a well-known password-manager export, selected with --format or detected
// from the header row.
type CSVProfile struct {
	// Format is the --format value that selects this profile.
	Format Format
	// Name is the human-readable source name, shown in status output.
	Name string
	// Mapping maps vault fields to CSV columns.
	Mapping map[string]string
	// URLColumn is the CSV column holding the login URL, used to derive
	// entry paths when the source has no usable title column.
	URLColumn string
	// PathFromURL derives the entry path from the URL host when the row has
	// no title (Firefox always; Chrome when the name column is empty).
	PathFromURL bool
	// Required lists the header columns (lowercase) that must all be present
	// for header sniffing to select this profile.
	Required []string
}

// csvProfileApple matches the Apple Passwords / iCloud Keychain CSV export
// (System Settings → Passwords → ⋯ → Export Passwords):
//
//	Title,URL,Username,Password,Notes,OTPAuth
var csvProfileApple = CSVProfile{
	Format:    FormatApple,
	Name:      "Apple Passwords (iCloud Keychain)",
	URLColumn: csvColURL,
	Mapping: map[string]string{
		"title":    "Title",
		"url":      "URL",
		"username": "Username",
		"password": "Password",
		"notes":    "Notes",
		"otp":      "OTPAuth",
	},
	Required: []string{csvColTitle, csvColURL, csvColUsername, csvColPassword, csvColOTPAuth},
}

// csvProfileChrome matches the Chrome / Chromium (Edge, Brave, Opera, ...)
// CSV export (chrome://password-manager/passwords → Export):
//
//	name,url,username,password,note
var csvProfileChrome = CSVProfile{
	Format:      FormatChrome,
	Name:        "Chrome / Chromium",
	URLColumn:   csvColURL,
	PathFromURL: true, // Chrome rows can have an empty name; fall back to the URL host.
	Mapping: map[string]string{
		"title":    "name",
		"url":      "url",
		"username": "username",
		"password": "password",
		"notes":    "note",
	},
	Required: []string{csvColName, csvColURL, csvColUsername, csvColPassword, csvColNote},
}

// csvProfileFirefox matches the Firefox CSV export
// (about:logins → ⋯ → Export Logins):
//
//	url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
var csvProfileFirefox = CSVProfile{
	Format:      FormatFirefox,
	Name:        "Firefox",
	URLColumn:   csvColURL,
	PathFromURL: true, // Firefox has no title column; the path is the URL host.
	Mapping: map[string]string{
		"url":      "url",
		"username": "username",
		"password": "password",
	},
	Required: []string{csvColURL, csvColUsername, csvColPassword, csvColHTTPRealm},
}

// csvProfiles lists the built-in CSV import profiles in header-sniffing
// priority order. Profiles whose Required columns are all present win; the
// first match is returned.
var csvProfiles = []CSVProfile{csvProfileApple, csvProfileChrome, csvProfileFirefox}

// CSVProfileFor returns the built-in CSV profile for format, if any.
func CSVProfileFor(format Format) (*CSVProfile, bool) {
	for i := range csvProfiles {
		if csvProfiles[i].Format == format {
			return &csvProfiles[i], true
		}
	}
	return nil, false
}

// IsCSVFormat reports whether format is CSV-based: the generic format or one
// of the built-in profiles.
func IsCSVFormat(format Format) bool {
	if format == FormatCSV {
		return true
	}
	_, ok := CSVProfileFor(format)
	return ok
}

// NewCSVProfile creates a CSV importer using the built-in profile for format.
// A non-empty userMapping overrides the profile mapping. It returns an error
// for formats without a built-in profile.
func NewCSVProfile(format Format, userMapping string) (Importer, error) {
	profile, ok := CSVProfileFor(format)
	if !ok {
		return nil, fmt.Errorf("no built-in CSV profile for format %q", format)
	}
	return &csvImporter{profile: profile, mapping: userMapping}, nil
}

// DetectCSVProfile matches a CSV header row against the built-in profiles.
// It returns the matching profile format, or FormatCSV when the header does
// not match any known profile (the generic CSV mapping then applies).
func DetectCSVProfile(header []string) Format {
	columns := make(map[string]bool, len(header))
	for _, column := range header {
		column = strings.ToLower(strings.TrimSpace(column))
		if column != "" {
			columns[column] = true
		}
	}
	for i := range csvProfiles {
		if profileColumnsPresent(columns, csvProfiles[i].Required) {
			return csvProfiles[i].Format
		}
	}
	return FormatCSV
}

func profileColumnsPresent(columns map[string]bool, required []string) bool {
	for _, column := range required {
		if !columns[column] {
			return false
		}
	}
	return true
}

// CSVEffectiveMapping returns the field→column mapping in effect for a CSV
// import: the user-provided mapping when non-empty, otherwise the built-in
// profile mapping, otherwise the generic default.
func CSVEffectiveMapping(format Format, userMapping string) (map[string]string, error) {
	var profile *CSVProfile
	if p, ok := CSVProfileFor(format); ok {
		profile = p
	}
	return csvMapping(userMapping, profile)
}

// hostFromURL extracts the host name from a login URL. It tolerates URLs
// without a scheme and strips credentials, ports and paths:
//
//	https://github.com/login → github.com
//	user:pass@example.com:8080/x → example.com
func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.Index(raw, "@"); i >= 0 {
		raw = raw[i+1:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if strings.HasPrefix(raw, "[") {
		if i := strings.Index(raw, "]"); i >= 0 {
			return raw[:i+1]
		}
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

// uniquePath returns path, or a path with a -2/-3/... suffix when the base
// path is already taken within the import batch, so every entry gets a
// distinct vault path. Empty paths pass through unchanged.
func uniquePath(used map[string]bool, path string) string {
	if path == "" {
		return ""
	}
	if !used[path] {
		used[path] = true
		return path
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", path, i)
		if !used[candidate] {
			used[candidate] = true
			return candidate
		}
	}
}
