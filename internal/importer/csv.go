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
	mapping, err := csvMapping(i.mapping)
	if err != nil {
		return nil, err
	}

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
				entry.Path = NormalizePath(value)
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

		entries = append(entries, entry)
	}

	return entries, nil
}

func csvMapping(mapping string) (map[string]string, error) {
	parsed, err := ParseMapping(mapping)
	if err != nil {
		return nil, fmt.Errorf("parse csv mapping: %w", err)
	}
	if parsed != nil {
		return parsed, nil
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
