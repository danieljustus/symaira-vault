// Package importer provides parsers for importing password entries from
// other password managers into Symaira Vault.
package importer

import (
	"fmt"
	"io"
	"strings"
)

// ImportedEntry represents a single entry parsed from an external source.
type ImportedEntry struct {
	// Path is the vault path (e.g., "github.com" or "work/aws").
	Path string
	// Data contains the entry fields (username, password, url, notes, totp, etc.).
	Data map[string]any
}

// Importer parses a password export format and returns imported entries.
type Importer interface {
	// Parse reads the export data and returns a slice of imported entries.
	Parse(r io.Reader) ([]ImportedEntry, error)
}

// ImportOptions controls how entries are imported into the vault.
type ImportOptions struct {
	// DryRun parses but does not write to the vault.
	DryRun bool
	// Prefix prepends a path to all imported entries.
	Prefix string
	// SkipExisting skips entries that already exist in the vault.
	SkipExisting bool
	// Overwrite deletes existing entries before writing.
	Overwrite bool
	// Mapping is a comma-separated list of column mappings for CSV import.
	// Format: "title=column1,username=column2,password=column3,..."
	Mapping string
}

// Format identifies the import format.
type Format string

const (
	Format1Password Format = "1password"
	FormatBitwarden Format = "bitwarden"
	FormatPass      Format = "pass"
	FormatCSV       Format = "csv"
)

// New creates an Importer for the given format.
func New(format Format) (Importer, error) {
	switch format {
	case Format1Password:
		return &onePUXImporter{}, nil
	case FormatBitwarden:
		return &bitwardenImporter{}, nil
	case FormatPass:
		return &passImporter{}, nil
	case FormatCSV:
		return &csvImporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}
}

// ParseMapping parses a mapping string into a map of field names to column names.
// Expected format: "title=path,username=username,password=password,otp=totp"
func ParseMapping(mapping string) (map[string]string, error) {
	if mapping == "" {
		return nil, nil
	}

	result := make(map[string]string)
	pairs := strings.Split(mapping, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid mapping pair: %q", pair)
		}
		field := strings.TrimSpace(parts[0])
		column := strings.TrimSpace(parts[1])
		if field == "" || column == "" {
			return nil, fmt.Errorf("empty field or column in mapping: %q", pair)
		}
		result[field] = column
	}
	return result, nil
}

// windowsInvalidChars contains characters that are invalid in Windows file names.
// Slash is excluded because it serves as the vault path separator.
const windowsInvalidChars = `"*?<>|:\`

// NormalizePath cleans and validates a vault path.
func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, "/")
	path = strings.ReplaceAll(path, " ", "-")
	for _, ch := range windowsInvalidChars {
		path = strings.ReplaceAll(path, string(ch), "")
	}
	path = strings.ReplaceAll(path, "..", "-")
	return path
}

func ApplyPrefix(prefix, path string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return path
	}
	if path == "" {
		return prefix
	}
	return prefix + "/" + path
}
