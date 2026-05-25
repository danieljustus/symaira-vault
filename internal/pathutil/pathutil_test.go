package pathutil

import (
	"strings"
	"testing"
)

func TestHasTraversal(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "relative parent", path: "../vault", want: true},
		{name: "nested parent", path: "vault/../other", want: true},
		{name: "absolute parent", path: "/tmp/../etc", want: true},
		{name: "literal dots", path: "/tmp/my..vault", want: false},
		{name: "normal path", path: "/tmp/symvault/vault", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasTraversal(tt.path); got != tt.want {
				t.Fatalf("HasTraversal(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{name: "simple entry", path: "github.com/user", wantErr: false},
		{name: "nested entry", path: "work/servers/prod/db", wantErr: false},
		{name: "entry with hyphen", path: "my-passwords", wantErr: false},
		{name: "entry with underscore", path: "my_passwords", wantErr: false},
		{name: "entry with dot", path: "my.vault", wantErr: false},
		{name: "entry with spaces", path: "path/with spaces", wantErr: false},
		{name: "entry with unicode", path: "日本語/パス", wantErr: false},
		{name: "entry with emoji", path: "path/emoji/🎉", wantErr: false},
		{name: "entry with tab in middle", path: "path/with\ttab", wantErr: false},
		{name: "entry with newline in middle", path: "path/with\nnewline", wantErr: false},
		{name: "Windows backslash path", path: "github\\user", wantErr: false},
		{name: "empty path", path: "", wantErr: true, errMsg: "path is empty"},
		{name: "null byte", path: "path/with\x00null", wantErr: true, errMsg: "null byte"},
		{name: "leading null byte", path: "\x00path", wantErr: true, errMsg: "null byte"},
		{name: "multiple null bytes", path: "path\x00\x00\x00", wantErr: true, errMsg: "null byte"},
		{name: "bell character", path: "path\x07file", wantErr: true, errMsg: "control character"},
		{name: "backspace", path: "path\x08file", wantErr: true, errMsg: "control character"},
		{name: "form feed", path: "path\x0cfile", wantErr: true, errMsg: "control character"},
		{name: "vertical tab", path: "path\x0bfile", wantErr: true, errMsg: "control character"},
		{name: "start of heading", path: "path\x01file", wantErr: true, errMsg: "control character"},
		{name: "parent directory", path: "../vault", wantErr: true, errMsg: "'..' segment"},
		{name: "nested parent", path: "vault/../other", wantErr: true, errMsg: "'..' segment"},
		{name: "trailing parent", path: "path/..", wantErr: true, errMsg: "'..' segment"},
		{name: "leading parent", path: "../path", wantErr: true, errMsg: "'..' segment"},
		{name: "multiple parents", path: "a/../../b", wantErr: true, errMsg: "'..' segment"},
		//nolint:misspell // "other" is intentionally part of the test path
		{name: "Windows parent", path: "path\\..\\other", wantErr: true, errMsg: "'..' segment"},
		{name: "absolute path", path: "/etc/passwd", wantErr: true, errMsg: "must be relative"},
		{name: "leading slash", path: "/path", wantErr: true, errMsg: "must be relative"},
		{name: "double slash", path: "path//file", wantErr: true, errMsg: "empty segment"},
		{name: "leading double slash", path: "//path", wantErr: true, errMsg: "must be relative"},

		{name: "delete char 0x7f allowed", path: "path\x7ffile", wantErr: false},
		{name: "high unicode 0xff allowed", path: "path\xfffile", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidatePath(%q) = nil, want error", tt.path)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("ValidatePath(%q) error = %q, want error containing %q", tt.path, err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("ValidatePath(%q) = %v, want nil", tt.path, err)
				}
			}
		})
	}
}

func TestValidatePathDeterministic(t *testing.T) {
	paths := []string{
		"github.com/user",
		"path/with spaces",
		"日本語/パス",
		"../parent",
		"path\x00null",
		"",
	}

	for _, path := range paths {
		err1 := ValidatePath(path)
		err2 := ValidatePath(path)
		if (err1 == nil) != (err2 == nil) {
			t.Errorf("ValidatePath(%q) not deterministic: first=%v, second=%v", path, err1, err2)
		}
	}
}

// FuzzValidatePath tests path validation with various edge cases.
func FuzzValidatePath(f *testing.F) {
	f.Add("github.com/user")
	f.Add("../vault")
	f.Add("vault/../other")
	f.Add("/tmp/../etc")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("...")
	f.Add("./path")
	f.Add("path/.")
	f.Add("path/./file")
	f.Add("//double/slash")
	f.Add("path//double")
	f.Add("/absolute/path")
	f.Add("relative/path")
	f.Add("path/with spaces")
	f.Add("path/with\ttab")
	f.Add("path/with\nnewline")
	f.Add("path/with\rcarriage")
	f.Add("path/with\x00null")
	f.Add("path/with\x01control")
	f.Add("path/with\x7fdel")
	f.Add("path/with\xffhigh")
	f.Add("日本語/パス")
	f.Add("path/emoji/🎉")
	f.Add("path/\u2028line")
	f.Add("path/\u2029para")
	f.Add("path/\x00\x00\x00")
	f.Add(strings.Repeat("a", 4096))
	f.Add(strings.Repeat("../", 1000))
	f.Add("%2e%2e%2f")
	f.Add("..%2f")
	f.Add("%2e.")
	f.Add(".%2e")
	f.Add("....//....//etc/passwd")
	f.Add("..\\windows")
	f.Add("path/../../../etc/passwd")
	f.Add("/etc/passwd")
	f.Add("C:\\Windows\\System32")
	f.Add("~/.ssh/id_rsa")
	f.Add("$HOME/.config")
	f.Add("path/${VAR}/file")
	f.Add("path/$(cmd)/file")
	f.Add("path/`cmd`/file")

	f.Fuzz(func(t *testing.T, path string) {
		err := ValidatePath(path)

		// Verify deterministic behavior
		err2 := ValidatePath(path)
		if (err == nil) != (err2 == nil) {
			t.Errorf("ValidatePath not deterministic: %v vs %v for %q", err, err2, path)
		}

		// Null bytes must always cause error
		if strings.Contains(path, "\x00") {
			if err == nil {
				t.Errorf("ValidatePath(%q) = nil, want error for path with null byte", path)
			}
		}

		// Paths with .. segment must cause error
		normalized := strings.ReplaceAll(path, "\\", "/")
		hasDots := false
		for _, seg := range strings.Split(normalized, "/") {
			if seg == ".." {
				hasDots = true
				break
			}
		}
		if hasDots && !strings.HasPrefix(normalized, "/") {
			if err == nil {
				t.Errorf("ValidatePath(%q) = nil, want error for path with .. segment", path)
			}
		}

		// Empty path must cause error
		if path == "" && err == nil {
			t.Errorf("ValidatePath(%q) = nil, want error for empty path", path)
		}
	})
}

// FuzzHasTraversal tests path validation with various edge cases including
// null bytes, control characters, Unicode, and very long paths.
// The fuzzer ensures HasTraversal never panics and correctly identifies
// directory traversal attempts.
func FuzzHasTraversal(f *testing.F) {
	// Seed corpus with known cases
	f.Add("../vault")
	f.Add("vault/../other")
	f.Add("/tmp/../etc")
	f.Add("/tmp/my..vault")
	f.Add("/tmp/symvault/vault")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("...")
	f.Add("./path")
	f.Add("path/.")
	f.Add("path/./file")
	f.Add("//double/slash")
	f.Add("path//double")
	f.Add("/absolute/path")
	f.Add("relative/path")
	f.Add("path/with spaces")
	f.Add("path/with\ttab")
	f.Add("path/with\nnewline")
	f.Add("path/with\rcarriage")
	f.Add("path/with\x00null")
	f.Add("path/with\x01control")
	f.Add("path/with\x7fdel")
	f.Add("path/with\xffhigh")
	f.Add("日本語/パス")
	f.Add("path/emoji/🎉")
	f.Add("path/\u2028line")
	f.Add("path/\u2029para")
	f.Add("path/\x00\x00\x00")
	f.Add(strings.Repeat("a", 4096))
	f.Add(strings.Repeat("../", 1000))
	f.Add("%2e%2e%2f") // URL encoded ..
	f.Add("..%2f")
	f.Add("%2e.")
	f.Add(".%2e")
	f.Add("....//....//etc/passwd")
	f.Add("..\\windows") // Windows backslash
	f.Add("path/../../../etc/passwd")
	f.Add("/etc/passwd")
	f.Add("C:\\Windows\\System32")
	f.Add("~/.ssh/id_rsa")
	f.Add("$HOME/.config")
	f.Add("path/${VAR}/file")
	f.Add("path/$(cmd)/file")
	f.Add("path/`cmd`/file")

	f.Fuzz(func(t *testing.T, path string) {
		// Ensure no panic on any input
		result := HasTraversal(path)

		// Verify deterministic behavior - same input should produce same output
		result2 := HasTraversal(path)
		if result != result2 {
			t.Errorf("HasTraversal not deterministic: %v vs %v for %q", result, result2, path)
		}

		// Any path containing ".." as a segment should be detected
		// Note: We don't check for false positives here since the function
		// may legitimately flag other patterns as traversal attempts
		if strings.Contains(path, "/../") || strings.HasPrefix(path, "../") || strings.HasSuffix(path, "/..") || path == ".." {
			if !result {
				t.Errorf("HasTraversal(%q) = %v, want true for path with .. segment", path, result)
			}
		}
	})
}
