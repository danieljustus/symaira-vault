package template

import (
	"context"
	"errors"
	"testing"

	vaultsvc "github.com/danieljustus/symaira-vault/internal/vaultsvc"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		name      string
		ref       string
		wantPath  string
		wantField string
		wantErr   bool
	}{
		{
			name:      "op:// full path",
			ref:       "op://work/aws/password",
			wantPath:  "work/aws",
			wantField: "password",
			wantErr:   false,
		},
		{
			name:      "op:// simple path",
			ref:       "op://github/token",
			wantPath:  "github",
			wantField: "token",
			wantErr:   false,
		},
		{
			name:      "dot notation",
			ref:       "work/aws.password",
			wantPath:  "work/aws",
			wantField: "password",
			wantErr:   false,
		},
		{
			name:      "dot notation simple",
			ref:       "github.token",
			wantPath:  "github",
			wantField: "token",
			wantErr:   false,
		},
		{
			name:      "op:// nested path",
			ref:       "op://work/team/aws/password",
			wantPath:  "work/team/aws",
			wantField: "password",
			wantErr:   false,
		},
		{
			name:    "empty string",
			ref:     "",
			wantErr: true,
		},
		{
			name:      "op:// two segments",
			ref:       "op://work/aws",
			wantPath:  "work",
			wantField: "aws",
			wantErr:   false,
		},
		{
			name:    "op:// trailing slash",
			ref:     "op://work/aws/",
			wantErr: true,
		},
		{
			name:    "dot notation missing field",
			ref:     "work/aws",
			wantErr: true,
		},
		{
			name:    "dot notation leading dot",
			ref:     ".password",
			wantErr: true,
		},
		{
			name:    "dot notation trailing dot",
			ref:     "work/aws.",
			wantErr: true,
		},
		{
			name:    "no dot no op prefix",
			ref:     "notavalidref",
			wantErr: true,
		},
		{
			name:    "just a field name",
			ref:     "password",
			wantErr: true,
		},
		{
			name:      "dot in field name",
			ref:       "work/aws.api.key",
			wantPath:  "work/aws.api",
			wantField: "key",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRef(tt.ref)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRef(%q) expected error, got nil", tt.ref)
				}
				if !errors.Is(err, ErrInvalidRef) {
					t.Fatalf("ParseRef(%q) error = %v, want ErrInvalidRef", tt.ref, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRef(%q) unexpected error: %v", tt.ref, err)
			}
			if got.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tt.wantPath)
			}
			if got.Field != tt.wantField {
				t.Errorf("Field = %q, want %q", got.Field, tt.wantField)
			}
		})
	}
}

func TestResolveRef(t *testing.T) {
	ctx := context.Background()

	t.Run("successful resolution", func(t *testing.T) {
		mock := vaultsvc.NewMockService()
		mock.GetFieldFunc = func(path, field string) (any, error) {
			return "secret-value", nil
		}

		got, err := ResolveRef(ctx, mock, "op://work/aws/password")
		if err != nil {
			t.Fatalf("ResolveRef: %v", err)
		}
		if got != "secret-value" {
			t.Errorf("ResolveRef = %q, want %q", got, "secret-value")
		}
	})

	t.Run("dot notation", func(t *testing.T) {
		mock := vaultsvc.NewMockService()
		mock.GetFieldFunc = func(path, field string) (any, error) {
			return "dot-value", nil
		}

		got, err := ResolveRef(ctx, mock, "work/aws.password")
		if err != nil {
			t.Fatalf("ResolveRef: %v", err)
		}
		if got != "dot-value" {
			t.Errorf("ResolveRef = %q, want %q", got, "dot-value")
		}
	})

	t.Run("numeric value", func(t *testing.T) {
		mock := vaultsvc.NewMockService()
		mock.GetFieldFunc = func(path, field string) (any, error) {
			return 42, nil
		}

		got, err := ResolveRef(ctx, mock, "op://path/field")
		if err != nil {
			t.Fatalf("ResolveRef: %v", err)
		}
		if got != "42" {
			t.Errorf("ResolveRef = %q, want %q", got, "42")
		}
	})

	t.Run("nil value", func(t *testing.T) {
		mock := vaultsvc.NewMockService()
		mock.GetFieldFunc = func(path, field string) (any, error) {
			return nil, nil
		}

		_, err := ResolveRef(ctx, mock, "op://path/field")
		if err == nil {
			t.Fatal("ResolveRef expected error for nil value, got nil")
		}
	})

	t.Run("vault error", func(t *testing.T) {
		mock := vaultsvc.NewMockService()
		mock.GetFieldFunc = func(path, field string) (any, error) {
			return nil, errors.New("vault error")
		}

		_, err := ResolveRef(ctx, mock, "op://missing/entry")
		if err == nil {
			t.Fatal("ResolveRef expected error, got nil")
		}
	})

	t.Run("invalid ref", func(t *testing.T) {
		mock := vaultsvc.NewMockService()
		_, err := ResolveRef(ctx, mock, "invalid-ref")
		if err == nil {
			t.Fatal("ResolveRef expected error for invalid ref, got nil")
		}
		if !errors.Is(err, ErrInvalidRef) {
			t.Fatalf("expected ErrInvalidRef, got %v", err)
		}
	})
}

func TestParsedRefFields(t *testing.T) {
	ref := &ParsedRef{Path: "work/aws", Field: "password"}
	if ref.Path != "work/aws" {
		t.Errorf("Path = %q, want %q", ref.Path, "work/aws")
	}
	if ref.Field != "password" {
		t.Errorf("Field = %q, want %q", ref.Field, "password")
	}
}
