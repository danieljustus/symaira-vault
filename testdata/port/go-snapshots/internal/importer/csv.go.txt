package importer

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
)

type csvImporter struct {
	mapping string
	profile *CSVProfile
}

// NewCSV creates a CSV importer with an optional field-to-column mapping.
func NewCSV(mapping string) Importer {
	return &csvImporter{mapping: mapping}
}

func (i *csvImporter) Parse(r io.Reader) ([]ImportedEntry, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1

	header, err := reader.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return []ImportedEntry{}, nil
		}
		return nil, fmt.Errorf("read csv header: %w", err)
	}

	columnIndex := csvColumnIndex(header)
	mapping, err := csvMapping(i.mapping, i.profile)
	if err != nil {
		return nil, err
	}

	// Profile imports de-duplicate paths so every entry lands on a unique
	// vault path (colliding entries would otherwise fail or overwrite).
	usedPaths := make(map[string]bool)
	var entries []ImportedEntry
	for {
		row, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read csv row: %w", err)
		}

		if csvEmptyRow(row) {
			continue
		}

		entry := ImportedEntry{Data: make(map[string]any)}
		for field, column := range mapping {
			value, ok := csvValue(row, columnIndex, column)
			if !ok {
				continue
			}

			switch field {
			case "title", "path":
				if entry.Path == "" && value != "" {
					entry.Path = NormalizePath(value)
				}
			case "otp", "totp.secret":
				if value != "" {
					totp, err := ParseTOTP(value)
					if err != nil {
						entry.Warnings = append(entry.Warnings, fmt.Sprintf("totp: %v", err))
						break
					}
					entry.Data["totp"] = totp
				}
			default:
				entry.Data[field] = value
			}
		}

		// Sources without a title column (Firefox) — and rows whose title is
		// empty (Chrome) — derive the entry path from the URL host.
		if entry.Path == "" && i.profile != nil && i.profile.PathFromURL {
			if urlValue, ok := csvValue(row, columnIndex, i.profile.URLColumn); ok {
				if host := hostFromURL(urlValue); host != "" {
					entry.Path = NormalizePath(strings.ToLower(host))
				}
			}
		}
		if i.profile != nil {
			entry.Path = uniquePath(usedPaths, entry.Path)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func csvMapping(userMapping string, profile *CSVProfile) (map[string]string, error) {
	if userMapping != "" {
		parsed, err := ParseMapping(userMapping)
		if err != nil {
			return nil, fmt.Errorf("parse csv mapping: %w", err)
		}
		return parsed, nil
	}
	if profile != nil {
		return profile.Mapping, nil
	}
	return map[string]string{
		"title":    "title",
		"username": "username",
		"password": "password",
		"url":      "url",
		"notes":    "notes",
		"otp":      "otp",
	}, nil
}

func csvColumnIndex(header []string) map[string]int {
	columns := make(map[string]int, len(header))
	for index, column := range header {
		column = strings.TrimSpace(column)
		if column == "" {
			continue
		}
		columns[column] = index
		columns[strings.ToLower(column)] = index
	}
	return columns
}

func csvValue(row []string, columnIndex map[string]int, column string) (string, bool) {
	index, ok := columnIndex[column]
	if !ok {
		index, ok = columnIndex[strings.ToLower(column)]
	}
	if !ok || index >= len(row) {
		return "", false
	}
	return row[index], true
}

func csvEmptyRow(row []string) bool {
	for _, value := range row {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
}
