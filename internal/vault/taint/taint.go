// Package taint provides types for distinguishing trusted from untrusted data
// at compile time. Untrusted values carry provenance information and enforce
// explicit rendering before they can be used in output contexts. The
// fmt.Formatter implementation panics on %s/%v/%q to prevent accidental
// stringification of untrusted content.
package taint

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUntrustedFormat is returned when an Untrusted value is used in an
// unsafe context. Call .Render() or .UnsafeRawForStorage() explicitly.
var ErrUntrustedFormat = errors.New("taint: use of Untrusted in format argument")

// SecretHandle is a reference to a specific field in the vault using the
// op:// scheme. It is the safe alternative to embedding raw secret values
// in MCP responses.
type SecretHandle struct {
	Path  string
	Field string
}

// String returns the op:// representation of the handle.
func (h SecretHandle) String() string {
	return "op://" + h.Path + "/" + h.Field
}

// ParseSecretHandle parses an op:// handle string into its components.
// Expected format: op://path/field
// Returns (SecretHandle{}, false) for invalid formats.
func ParseSecretHandle(s string) (SecretHandle, bool) {
	if !strings.HasPrefix(s, "op://") {
		return SecretHandle{}, false
	}
	rest := s[5:]
	if rest == "" || rest[0] == '/' {
		return SecretHandle{}, false
	}

	if idx := strings.LastIndex(rest, "/"); idx > 0 && idx < len(rest)-1 {
		return SecretHandle{Path: rest[:idx], Field: rest[idx+1:]}, true
	}

	return SecretHandle{Path: rest}, true
}

// Provenance describes the origin of an untrusted value.
type Provenance struct {
	// Source identifies the subsystem that produced the value
	// (e.g. "vault.field", "vault.tag", "vault.usage_hint").
	Source string

	// EntryPath is the vault path the value originated from (may be empty).
	EntryPath string

	// FieldName is the specific field the value originated from (may be empty).
	FieldName string
}

// RenderTarget specifies the output context for rendering.
type RenderTarget int

const (
	// Terminal indicates output intended for a terminal/TUI.
	Terminal RenderTarget = iota
	// MCP indicates output intended for the MCP protocol response.
	MCP
)

// RenderedFragment is the final, target-specific output produced by
// rendering an Untrusted value. It carries the target information so
// downstream code can verify correctness at the type level.
type RenderedFragment struct {
	target RenderTarget
	value  string
}

// Target returns the render target this fragment was produced for.
func (rf RenderedFragment) Target() RenderTarget { return rf.target }

// String returns the rendered string value.
func (rf RenderedFragment) String() string { return rf.value }

// Untrusted represents data that has not been validated as safe for output.
// It carries provenance metadata and enforces explicit rendering.
//
// Untrusted does NOT implement fmt.Stringer — calling fmt.Sprintf("%s", u)
// or similar will panic with ErrUntrustedFormat. Use .Render(target) or
// .UnsafeRawForStorage() instead.
type Untrusted struct {
	raw  string
	prov Provenance
}

// Wrap creates a new Untrusted value from a raw string and its provenance.
func Wrap(raw string, prov Provenance) Untrusted {
	return Untrusted{raw: raw, prov: prov}
}

// Render produces a RenderedFragment for the given target. The returned
// fragment is safe to use in the target context — it has been sanitized
// according to the target's escaping rules (this base implementation
// returns the raw value; target-specific sanitization happens in the
// render package).
func (u Untrusted) Render(target RenderTarget) RenderedFragment {
	return RenderedFragment{target: target, value: u.raw}
}

// Bytes returns the raw underlying data as a byte slice. Use this only
// for cryptographic or storage operations where the data must not be
// modified (hashing, encryption, etc.).
func (u Untrusted) Bytes() []byte {
	return []byte(u.raw)
}

// UnsafeRawForStorage returns the raw string value for explicit storage
// operations. The name includes "Unsafe" as a reminder that this bypasses
// the Format safety net — only use when you need the original string for
// serialization or persistence.
func (u Untrusted) UnsafeRawForStorage() string {
	return u.raw
}

// Provenance returns the provenance metadata attached to this value.
func (u Untrusted) Provenance() Provenance {
	return u.prov
}

// Format implements fmt.Formatter.
//
// %#v produces debug output showing source and length:
//
//	<untrusted source=vault.field len=12>
//
// %s, %v, %q, and other verbs produce a placeholder:
//
//	<untrusted source=vault.field>
//
// This is a safety net — the placeholder makes misuse visible while
// keeping the program running. Phase E adds a go vet analyzer
// (cmd/passlint) to catch these at compile time.
func (u Untrusted) Format(f fmt.State, verb rune) {
	switch verb {
	case 'v':
		if f.Flag('#') {
			fmt.Fprintf(f, "<untrusted source=%s len=%d>", u.prov.Source, len(u.raw))
			return
		}
		fallthrough
	default:
		fmt.Fprintf(f, "<untrusted:%s>", u.prov.Source)
	}
}
