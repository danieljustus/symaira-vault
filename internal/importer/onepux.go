package importer

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	onePUXLoginCategory    = "001"
	defaultMaxZipEntrySize = 100 * 1024 * 1024 // 100 MB per entry
	maxImportSize          = 100 * 1024 * 1024 // 100 MB total import
)

// maxZipEntrySize is the maximum size allowed for a single ZIP entry.
// It is a variable so tests can override it with a smaller value.
var maxZipEntrySize = defaultMaxZipEntrySize

// MaxImportSize is the maximum allowed size for import sources.
// It is a variable so callers (e.g., cmd/import.go) can reference it.
var MaxImportSize int64 = maxImportSize

type onePUXImporter struct{}

type onePUXExport struct {
	Accounts []onePUXAccount `json:"accounts"`
}

type onePUXAccount struct {
	Vaults []onePUXVault `json:"vaults"`
}

type onePUXVault struct {
	Items []onePUXItem `json:"items"`
}

type onePUXItem struct {
	CategoryUUID string         `json:"categoryUuid"`
	Title        string         `json:"title"`
	Trashed      bool           `json:"trashed"`
	Details      onePUXDetails  `json:"details"`
	Overview     onePUXOverview `json:"overview"`
}

type onePUXDetails struct {
	LoginFields []onePUXLoginField `json:"loginFields"`
	Sections    []onePUXSection    `json:"sections"`
	NotesPlain  string             `json:"notesPlain"`
}

type onePUXLoginField struct {
	FieldType   string `json:"fieldType"`
	Designation string `json:"designation"`
	Value       string `json:"value"`
}

type onePUXSection struct {
	Title  string        `json:"title"`
	Fields []onePUXField `json:"fields"`
}

type onePUXField struct {
	Title string          `json:"title"`
	Value json.RawMessage `json:"value"`
}

type onePUXOverview struct {
	URLs []onePUXURL `json:"urls"`
	Tags []string    `json:"tags"`
}

type onePUXURL struct {
	URL string `json:"url"`
}

func (i *onePUXImporter) Parse(r io.Reader) ([]ImportedEntry, error) {
	limited := io.LimitReader(r, maxImportSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read import source: %w", err)
	}
	if len(data) >= int(maxImportSize) {
		return nil, fmt.Errorf("import source exceeds maximum size of %d bytes", maxImportSize)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open 1pux zip: %w", err)
	}

	exportData, err := readOnePUXExportJSON(zr)
	if err != nil {
		return nil, err
	}

	var export onePUXExport
	if err := json.Unmarshal(exportData, &export); err != nil {
		return nil, fmt.Errorf("parse export.json: %w", err)
	}

	var entries []ImportedEntry
	for _, account := range export.Accounts {
		for _, vault := range account.Vaults {
			for _, item := range vault.Items {
				if item.CategoryUUID != onePUXLoginCategory || item.Trashed {
					continue
				}

				username, password := onePUXCredentials(item.Details.LoginFields)
				entries = append(entries, ImportedEntry{
					Path: item.Title,
					Data: map[string]any{
						"username": username,
						"password": password,
						"url":      onePUXPrimaryURL(item.Overview.URLs),
						"notes":    item.Details.NotesPlain,
						"tags":     onePUXTags(item.Overview.Tags),
						"totp":     onePUXTOTP(item.Details.Sections),
					},
				})
			}
		}
	}

	return entries, nil
}

func readOnePUXExportJSON(zr *zip.Reader) ([]byte, error) {
	for _, file := range zr.File {
		if file.Name != "export.json" && !strings.HasSuffix(file.Name, "/export.json") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open export.json: %w", err)
		}
		defer func() { _ = rc.Close() }()

		limited := io.LimitReader(rc, int64(maxZipEntrySize))
		data, err := io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("read export.json: %w", err)
		}
		if len(data) == maxZipEntrySize {
			return nil, fmt.Errorf("zip entry exceeds maximum size of %d bytes", maxZipEntrySize)
		}
		return data, nil
	}

	return nil, fmt.Errorf("export.json not found in 1pux zip")
}

func onePUXCredentials(fields []onePUXLoginField) (string, string) {
	var username, password string
	for _, field := range fields {
		switch strings.ToLower(field.Designation) {
		case "username":
			username = field.Value
		case "password":
			password = field.Value
		}
	}
	return username, password
}

func onePUXPrimaryURL(urls []onePUXURL) string {
	if len(urls) == 0 {
		return ""
	}
	return urls[0].URL
}

func onePUXTags(tags []string) []string {
	if tags == nil {
		return []string{}
	}
	return tags
}

func onePUXTOTP(sections []onePUXSection) string {
	for _, section := range sections {
		for _, field := range section.Fields {
			if !strings.Contains(strings.ToLower(field.Title), "one-time password") {
				continue
			}

			if otp := onePUXOTPValue(field.Value); otp != "" {
				return otp
			}
		}
	}
	return ""
}

func onePUXOTPValue(value json.RawMessage) string {
	var object struct {
		OTP string `json:"otp"`
	}
	if err := json.Unmarshal(value, &object); err == nil && object.OTP != "" {
		return object.OTP
	}

	var text string
	if err := json.Unmarshal(value, &text); err == nil {
		return text
	}

	return ""
}
