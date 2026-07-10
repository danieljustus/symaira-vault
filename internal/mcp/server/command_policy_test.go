package server

import (
	"math"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
)

func TestParseCommandTimeoutSeconds(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    int
		wantErr string
	}{
		{name: "missing uses default", raw: nil, want: 30},
		{name: "minimum", raw: float64(1), want: 1},
		{name: "maximum", raw: float64(300), want: 300},
		{name: "numeric string", raw: "45", want: 45},
		{name: "zero", raw: float64(0), wantErr: "between 1 and 300"},
		{name: "negative", raw: float64(-1), wantErr: "between 1 and 300"},
		{name: "fractional", raw: float64(1.5), wantErr: "whole number"},
		{name: "nan", raw: math.NaN(), wantErr: "finite"},
		{name: "infinity", raw: math.Inf(1), wantErr: "finite"},
		{name: "too large", raw: float64(301), wantErr: "between 1 and 300"},
		{name: "invalid string", raw: "not-a-number", wantErr: "numeric"},
		{name: "unsupported type", raw: true, wantErr: "numeric"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCommandTimeoutSeconds(tt.raw)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseCommandTimeoutSeconds() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("parseCommandTimeoutSeconds() = %d, want %d", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatal("parseCommandTimeoutSeconds() expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseCommandArray(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    []string
		wantErr string
	}{
		{name: "nil", raw: nil, wantErr: "missing required argument"},
		{name: "not an array", raw: "string", wantErr: "must be an array"},
		{name: "empty array", raw: []any{}, wantErr: "must not be empty"},
		{name: "non-string element", raw: []any{"echo", 123}, wantErr: "must be a string"},
		{name: "valid", raw: []any{"echo", "hello"}, want: []string{"echo", "hello"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCommandArray(tt.raw)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseCommandArray() error = %v", err)
				}
				if len(got) != len(tt.want) {
					t.Fatalf("parseCommandArray() = %v, want %v", got, tt.want)
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
					}
				}
				return
			}
			if err == nil {
				t.Fatal("parseCommandArray() expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestCheckExecutableAllowlist(t *testing.T) {
	tests := []struct {
		name      string
		allowlist []string
		command   []string
		wantErr   string
	}{
		{
			name:      "empty allowlist allows everything",
			allowlist: []string{},
			command:   []string{"sh", "-c", "echo hello"},
			wantErr:   "",
		},
		{
			name:      "allowed executable",
			allowlist: []string{"echo", "cat"},
			command:   []string{"echo", "hello"},
			wantErr:   "",
		},
		{
			name:      "path-qualified allowed executable",
			allowlist: []string{"echo", "cat"},
			command:   []string{"/bin/echo", "hello"},
			wantErr:   "",
		},
		{
			name:      "denied executable",
			allowlist: []string{"echo", "cat"},
			command:   []string{"sh", "-c", "echo hello"},
			wantErr:   "not in agent allowlist",
		},
		{
			name:      "empty command is a noop",
			allowlist: []string{"echo"},
			command:   []string{},
			wantErr:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				agent: &config.AgentProfile{
					AllowedExecutables: tt.allowlist,
				},
			}
			err := s.checkExecutableAllowlist(tt.command)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("checkExecutableAllowlist() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("checkExecutableAllowlist() expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
