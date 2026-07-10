package importer

import (
	"encoding/json"
	"fmt"
	"io"

	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	bitwardenLoginType = 1
	bitwardenCardType  = 2
)

const (
	bitwardenFieldUsername = "username"
	bitwardenFieldPassword = "password"
	bitwardenFieldURL      = "url"
	bitwardenFieldURLs     = "urls"
	bitwardenFieldNotes    = "notes"
	bitwardenFieldTOTP     = "totp"
	bitwardenFieldSecret   = "secret"
)

type bitwardenImporter struct{}

type bitwardenExport struct {
	Folders []bitwardenFolder `json:"folders"`
	Items   []bitwardenItem   `json:"items"`
}

type bitwardenFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type bitwardenItem struct {
	Type     int              `json:"type"`
	Name     string           `json:"name"`
	FolderID string           `json:"folderId"`
	Login    bitwardenLogin   `json:"login"`
	Card     bitwardenCard    `json:"card"`
	Notes    string           `json:"notes"`
	Fields   []bitwardenField `json:"fields"`
}

type bitwardenLogin struct {
	Username string         `json:"username"`
	Password string         `json:"password"`
	TOTP     string         `json:"totp"`
	URIs     []bitwardenURI `json:"uris"`
}

type bitwardenURI struct {
	URI string `json:"uri"`
}

type bitwardenField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type bitwardenCard struct {
	CardholderName string `json:"cardholderName"`
	Brand          string `json:"brand"`
	Number         string `json:"number"`
	ExpMonth       string `json:"expMonth"`
	ExpYear        string `json:"expYear"`
	Code           string `json:"code"`
}

func (i *bitwardenImporter) Parse(r io.Reader) ([]ImportedEntry, error) {
	var export bitwardenExport
	if err := json.NewDecoder(r).Decode(&export); err != nil {
		return nil, fmt.Errorf("parse bitwarden export: %w", err)
	}

	folders := make(map[string]string, len(export.Folders))
	for _, folder := range export.Folders {
		if folder.ID == "" {
			continue
		}
		folders[folder.ID] = folder.Name
	}

	entries := make([]ImportedEntry, 0, len(export.Items))
	for _, item := range export.Items {
		switch item.Type {
		case bitwardenLoginType:
			entry := bitwardenParseLogin(item, folders)
			entries = append(entries, entry)
		case bitwardenCardType:
			entry := bitwardenParseCard(item, folders)
			entries = append(entries, entry)
		default:
			continue
		}
	}

	return entries, nil
}

func bitwardenPrimaryURI(uris []bitwardenURI) string {
	if len(uris) == 0 {
		return ""
	}
	return uris[0].URI
}

func bitwardenURIs(uris []bitwardenURI) []string {
	result := make([]string, 0, len(uris))
	for _, uri := range uris {
		if uri.URI == "" {
			continue
		}
		result = append(result, uri.URI)
	}
	return result
}

func bitwardenPath(item bitwardenItem, folders map[string]string) string {
	path := item.Name
	if folderName := folders[item.FolderID]; folderName != "" {
		path = ApplyPrefix(folderName, path)
	}
	return NormalizePath(path)
}

func bitwardenParseLogin(item bitwardenItem, folders map[string]string) ImportedEntry {
	data := map[string]any{
		bitwardenFieldUsername: item.Login.Username,
		bitwardenFieldPassword: item.Login.Password,
		bitwardenFieldURL:      bitwardenPrimaryURI(item.Login.URIs),
		bitwardenFieldURLs:     bitwardenURIs(item.Login.URIs),
		bitwardenFieldNotes:    item.Notes,
	}

	for _, field := range item.Fields {
		if field.Name == "" {
			continue
		}
		data[field.Name] = field.Value
	}

	if item.Login.TOTP != "" {
		data[bitwardenFieldTOTP] = map[string]any{bitwardenFieldSecret: item.Login.TOTP}
	}

	return ImportedEntry{
		Path: bitwardenPath(item, folders),
		Data: data,
	}
}

func bitwardenParseCard(item bitwardenItem, folders map[string]string) ImportedEntry {
	data := map[string]any{
		vaultpkg.PaymentFieldCardNumber:  item.Card.Number,
		vaultpkg.PaymentFieldCardholder:  item.Card.CardholderName,
		vaultpkg.PaymentFieldExpiryMonth: item.Card.ExpMonth,
		vaultpkg.PaymentFieldExpiryYear:  item.Card.ExpYear,
		vaultpkg.PaymentFieldCVC:         item.Card.Code,
		vaultpkg.PaymentFieldSubtype:     string(vaultpkg.PaymentSubtypeCard),
	}

	for _, field := range item.Fields {
		if field.Name == "" {
			continue
		}
		data[field.Name] = field.Value
	}

	return ImportedEntry{
		Path: bitwardenPath(item, folders),
		Data: data,
		SecretMetadata: &vaultpkg.SecretMetadata{
			Type:      vaultpkg.SecretTypePayment,
			UsageHint: vaultpkg.UsageHintForType(vaultpkg.SecretTypePayment),
		},
	}
}
