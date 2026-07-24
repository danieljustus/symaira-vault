package file

import (
	"errors"
	"strings"
	"testing"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestSplitPathField(t *testing.T) {
	tests := []struct {
		name      string
		arg       string
		wantPath  string
		wantField string
	}{
		{name: "no separator", arg: "elster/cert", wantPath: "elster/cert", wantField: ""},
		{name: "with field", arg: "elster/cert#cert_p12", wantPath: "elster/cert", wantField: "cert_p12"},
		{name: "hash not at start uses last occurrence", arg: "a#b#c", wantPath: "a#b", wantField: "c"},
		{name: "leading hash is not treated as a separator", arg: "#field", wantPath: "#field", wantField: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, field := splitPathField(tt.arg)
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
			if field != tt.wantField {
				t.Errorf("field = %q, want %q", field, tt.wantField)
			}
		})
	}
}

func TestResolveAttachmentField(t *testing.T) {
	t.Run("explicit field found in metadata", func(t *testing.T) {
		entry := &vaultpkg.Entry{
			SecretMetadata: vaultpkg.SecretMetadata{
				Attachments: map[string]vaultpkg.AttachmentInfo{
					"cert_p12": {Filename: "cert.pfx", Size: 10, SHA256: "abc"},
				},
			},
		}
		field, info, err := resolveAttachmentField(entry, "cert_p12")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if field != "cert_p12" {
			t.Errorf("field = %q, want %q", field, "cert_p12")
		}
		if info == nil || info.SHA256 != "abc" {
			t.Errorf("info = %+v, want SHA256=abc", info)
		}
	})

	t.Run("explicit field not in metadata is not an error", func(t *testing.T) {
		entry := &vaultpkg.Entry{SecretMetadata: vaultpkg.SecretMetadata{}}
		field, info, err := resolveAttachmentField(entry, "custom_field")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if field != "custom_field" {
			t.Errorf("field = %q, want %q", field, "custom_field")
		}
		if info != nil {
			t.Errorf("info = %+v, want nil", info)
		}
	})

	t.Run("no explicit field, zero attachments errors", func(t *testing.T) {
		entry := &vaultpkg.Entry{SecretMetadata: vaultpkg.SecretMetadata{}}
		_, _, err := resolveAttachmentField(entry, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var cliErr *errorspkg.CLIError
		if !errors.As(err, &cliErr) {
			t.Fatalf("expected *errorspkg.CLIError, got %T", err)
		}
		if cliErr.Code != errorspkg.ExitInvalidInput {
			t.Errorf("code = %v, want ExitInvalidInput", cliErr.Code)
		}
	})

	t.Run("no explicit field, exactly one attachment auto-selects it", func(t *testing.T) {
		entry := &vaultpkg.Entry{
			SecretMetadata: vaultpkg.SecretMetadata{
				Attachments: map[string]vaultpkg.AttachmentInfo{
					"only_field": {Filename: "f.bin", Size: 5, SHA256: "deadbeef"},
				},
			},
		}
		field, info, err := resolveAttachmentField(entry, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if field != "only_field" {
			t.Errorf("field = %q, want %q", field, "only_field")
		}
		if info == nil || info.SHA256 != "deadbeef" {
			t.Errorf("info = %+v, want SHA256=deadbeef", info)
		}
	})

	t.Run("no explicit field, multiple attachments errors listing names", func(t *testing.T) {
		entry := &vaultpkg.Entry{
			SecretMetadata: vaultpkg.SecretMetadata{
				Attachments: map[string]vaultpkg.AttachmentInfo{
					"field_b": {SHA256: "b"},
					"field_a": {SHA256: "a"},
				},
			},
		}
		_, _, err := resolveAttachmentField(entry, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var cliErr *errorspkg.CLIError
		if !errors.As(err, &cliErr) {
			t.Fatalf("expected *errorspkg.CLIError, got %T", err)
		}
		if cliErr.Code != errorspkg.ExitInvalidInput {
			t.Errorf("code = %v, want ExitInvalidInput", cliErr.Code)
		}
		msg := cliErr.Error()
		if !strings.Contains(msg, "field_a") || !strings.Contains(msg, "field_b") {
			t.Errorf("error message %q does not list both field names", msg)
		}
	})
}
