package main

import (
	"path/filepath"
	"testing"
)

func TestValidationHelpers(t *testing.T) {
	t.Run("parsePID", func(t *testing.T) {
		tests := []struct {
			name    string
			raw     string
			want    int
			wantErr bool
		}{
			{name: "valid_minimum", raw: "2", want: 2, wantErr: false},
			{name: "valid_typical", raw: "1234", want: 1234, wantErr: false},
			{name: "valid_large", raw: "65535", want: 65535, wantErr: false},
			{name: "invalid_one", raw: "1", wantErr: true},
			{name: "invalid_zero", raw: "0", wantErr: true},
			{name: "invalid_negative", raw: "-1", wantErr: true},
			{name: "invalid_negative_group", raw: "-1234", wantErr: true},
			{name: "invalid_empty", raw: "", wantErr: true},
			{name: "invalid_nonnumeric", raw: "abc", wantErr: true},
			{name: "invalid_nonnumeric_suffix", raw: "123x", wantErr: true},
			{name: "invalid_positive_sign", raw: "+123", wantErr: true},
			{name: "invalid_injection_semicolon", raw: "123; rm -rf", wantErr: true},
			{name: "invalid_injection_newline", raw: "123\n", wantErr: true},
			{name: "invalid_injection_space", raw: "12 34", wantErr: true},
			{name: "invalid_injection_command", raw: "123$(id)", wantErr: true},
			{name: "invalid_overflow_int32", raw: "3000000000", wantErr: true},
			{name: "invalid_overflow_int64", raw: "999999999999999999999999999999999999", wantErr: true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := parsePID(tc.raw)
				if (err != nil) != tc.wantErr {
					t.Fatalf("parsePID(%q) err = %v, wantErr = %v", tc.raw, err, tc.wantErr)
				}
				if !tc.wantErr && got != tc.want {
					t.Fatalf("parsePID(%q) = %d, want %d", tc.raw, got, tc.want)
				}
			})
		}
	})

	t.Run("validateOutputPath", func(t *testing.T) {
		root := filepath.Join(string(filepath.Separator), "repo")
		tests := []struct {
			name    string
			output  string
			wantErr bool
		}{
			{name: "valid_relative", output: "testdata/port/sync/git-io.json", wantErr: false},
			{name: "valid_nested", output: "sub/dir/fixture.json", wantErr: false},
			{name: "valid_single_file", output: "git-io.json", wantErr: false},
			{name: "valid_dot_slash", output: "./testdata/port/sync/git-io.json", wantErr: false},
			{name: "invalid_parent", output: "..", wantErr: true},
			{name: "invalid_traversal_parent_slash", output: "../escaped.json", wantErr: true},
			{name: "invalid_traversal_nested", output: "a/../../escaped.json", wantErr: true},
			{name: "invalid_traversal_deep", output: "../../etc/passwd", wantErr: true},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := validateOutputPath(root, tc.output)
				if (err != nil) != tc.wantErr {
					t.Fatalf("validateOutputPath(%q, %q) err = %v, wantErr = %v", root, tc.output, err, tc.wantErr)
				}
				if !tc.wantErr {
					expected := filepath.Join(root, filepath.FromSlash(tc.output))
					if got != expected {
						t.Fatalf("validateOutputPath(%q, %q) = %q, want %q", root, tc.output, got, expected)
					}
				}
			})
		}
	})
}
