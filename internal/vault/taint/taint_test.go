package taint

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestUntrustedHasNoStringer(t *testing.T) {
	u := Wrap("test", Provenance{Source: "test"})
	_, ok := interface{}(u).(fmt.Stringer)
	if ok {
		t.Fatal("Untrusted must not implement fmt.Stringer")
	}
}

func TestUntrustedFormatProducesPlaceholder(t *testing.T) {
	u := Wrap("sensitive", Provenance{Source: "vault.field"})
	result := fmt.Sprintf("%s", u)
	want := "<untrusted:vault.field>"
	if result != want {
		t.Fatalf("%%s = %q, want %q", result, want)
	}
}

func TestUntrustedFormatVProducesPlaceholder(t *testing.T) {
	u := Wrap("sensitive", Provenance{Source: "test"})
	result := fmt.Sprintf("%v", u)
	want := "<untrusted:test>"
	if result != want {
		t.Fatalf("%%v = %q, want %q", result, want)
	}
}

func TestUntrustedFormatQProducesPlaceholder(t *testing.T) {
	u := Wrap("sensitive", Provenance{Source: "test"})
	result := fmt.Sprintf("%q", u)
	want := "<untrusted:test>"
	if result != want {
		t.Fatalf("%%q = %q, want %q", result, want)
	}
}

func TestUntrustedFormatAllowsPercentHashV(t *testing.T) {
	u := Wrap("sensitive-data", Provenance{Source: "vault.field", EntryPath: "personal/notes", FieldName: "content"})
	result := fmt.Sprintf("%#v", u)
	if !strings.Contains(result, "untrusted") {
		t.Fatalf("%%#v output should contain 'untrusted', got: %s", result)
	}
	if !strings.Contains(result, "vault.field") {
		t.Fatalf("%%#v output should contain source, got: %s", result)
	}
	if !strings.Contains(result, "14") {
		t.Fatalf("%%#v output should contain length, got: %s", result)
	}
}

func TestWrapCreatesUntrustedWithProvenance(t *testing.T) {
	prov := Provenance{Source: "vault.field", EntryPath: "test/entry", FieldName: "password"}
	u := Wrap("secret-value", prov)

	if u.raw != "secret-value" {
		t.Fatalf("raw = %q, want %q", u.raw, "secret-value")
	}
	if u.prov.Source != "vault.field" {
		t.Fatalf("source = %q, want %q", u.prov.Source, "vault.field")
	}
	if u.prov.EntryPath != "test/entry" {
		t.Fatalf("EntryPath = %q, want %q", u.prov.EntryPath, "test/entry")
	}
	if u.prov.FieldName != "password" {
		t.Fatalf("FieldName = %q, want %q", u.prov.FieldName, "password")
	}
}

func TestProvenance(t *testing.T) {
	prov := Provenance{Source: "test", EntryPath: "a/b", FieldName: "c"}
	u := Wrap("x", prov)
	got := u.Provenance()
	if got != prov {
		t.Fatalf("Provenance() = %+v, want %+v", got, prov)
	}
}

func TestRenderReturnsRenderedFragment(t *testing.T) {
	u := Wrap("hello", Provenance{Source: "test"})
	rf := u.Render(Terminal)

	if rf.Target() != Terminal {
		t.Fatalf("Target() = %v, want %v", rf.Target(), Terminal)
	}
	if rf.String() != "hello" {
		t.Fatalf("value = %q, want %q", rf.String(), "hello")
	}
}

func TestRenderWithMCPTarget(t *testing.T) {
	u := Wrap("data", Provenance{Source: "test"})
	rf := u.Render(MCP)

	if rf.Target() != MCP {
		t.Fatalf("Target() = %v, want %v", rf.Target(), MCP)
	}
}

func TestBytesReturnsRawData(t *testing.T) {
	u := Wrap("binary\x00data", Provenance{Source: "test"})
	b := u.Bytes()

	if string(b) != "binary\x00data" {
		t.Fatalf("Bytes() = %v, want %v", b, []byte("binary\x00data"))
	}
}

func TestUnsafeRawForStorageReturnsRaw(t *testing.T) {
	u := Wrap("raw-value", Provenance{Source: "test"})
	s := u.UnsafeRawForStorage()

	if s != "raw-value" {
		t.Fatalf("UnsafeRawForStorage() = %q, want %q", s, "raw-value")
	}
}

func TestUntrustedEmptyString(t *testing.T) {
	u := Wrap("", Provenance{Source: "test"})
	if u.Render(Terminal).String() != "" {
		t.Fatal("empty Untrusted should render empty string")
	}
	if len(u.Bytes()) != 0 {
		t.Fatal("empty Untrusted should have empty Bytes")
	}
}

func TestUntrustedLongString(t *testing.T) {
	long := strings.Repeat("a", 10000)
	u := Wrap(long, Provenance{Source: "test"})

	rf := u.Render(Terminal)
	if len(rf.String()) != 10000 {
		t.Fatalf("expected 10000 chars, got %d", len(rf.String()))
	}

	s := fmt.Sprintf("%#v", u)
	if !strings.Contains(s, "10000") {
		t.Fatalf("%%#v should contain length 10000, got: %s", s)
	}
}

func TestUntrustedFormatAnyVerbProducesPlaceholder(t *testing.T) {
	u := Wrap("data", Provenance{Source: "test"})
	result := fmt.Sprintf("%x", u)
	want := "<untrusted:test>"
	if result != want {
		t.Fatalf("%%x = %q, want %q", result, want)
	}
}

func TestRenderedFragmentTarget(t *testing.T) {
	tests := []struct {
		name   string
		target RenderTarget
	}{
		{"terminal", Terminal},
		{"mcp", MCP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rf := RenderedFragment{target: tt.target, value: "test"}
			if rf.Target() != tt.target {
				t.Fatalf("Target() = %v, want %v", rf.Target(), tt.target)
			}
		})
	}
}

func TestRenderedFragmentString(t *testing.T) {
	rf := RenderedFragment{target: Terminal, value: "output"}
	if rf.String() != "output" {
		t.Fatalf("String() = %q, want %q", rf.String(), "output")
	}
}

func TestUntrustedImplementsFormatter(t *testing.T) {
	u := Wrap("test", Provenance{Source: "test"})
	_, ok := interface{}(u).(fmt.Formatter)
	if !ok {
		t.Fatal("Untrusted must implement fmt.Formatter")
	}
}

func TestUntrustedFormatHashVShowsDebug(t *testing.T) {
	u := Wrap("secret", Provenance{Source: "my-source"})
	result := fmt.Sprintf("%#v", u)
	if !strings.Contains(result, "untrusted") {
		t.Fatalf("%%#v should contain 'untrusted', got: %s", result)
	}
	if !strings.Contains(result, "my-source") {
		t.Fatalf("%%#v should contain source, got: %s", result)
	}
}

func TestWrapRenderRoundtrip(t *testing.T) {
	inputs := []string{"", "a", "hello world", "line1\nline2", "data\x00with\x00nulls"}
	for _, input := range inputs {
		t.Run(fmt.Sprintf("len=%d", len(input)), func(t *testing.T) {
			u := Wrap(input, Provenance{Source: "test"})
			rf := u.Render(Terminal)
		if rf.String() != input {
				t.Fatalf("Render() = %q, want %q", rf.String(), input)
			}
		})
	}
}

func TestUntrustedReflectNoStringMethod(t *testing.T) {
	u := Wrap("x", Provenance{Source: "test"})
	typ := reflect.TypeOf(u)
	_, hasString := typ.MethodByName("String")
	if hasString {
		t.Fatal("Untrusted must not have a String method")
	}
}
