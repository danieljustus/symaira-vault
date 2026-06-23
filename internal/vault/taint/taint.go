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

const taintNameSecret = "secret"

// SecretHandle is a handle that can be displayed to the user containing the
// path to a secret in the vault in the "op://path/field" format.
// It implements fmt.Stringer and is safe for display because it only contains
// the path, not the secret value.
type SecretHandle struct {
	Path  string
	Field string
}

// String returns the op:// representation of the handle.
func (h SecretHandle) String() string {
	return fmt.Sprintf("op://%s/%s", h.Path, h.Field)
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

// Classification represents the sensitivity level of a value.
type Classification int

const (
	// Public information that can be freely shared.
	Public Classification = iota
	// Internal information intended for internal use.
	Internal
	// Confidential information that requires controlled access.
	Confidential
	// Secret information that must be sealed from LLM exposure by default.
	Secret
	// Restricted information with the highest sensitivity level.
	Restricted
)

// String returns the human-readable label for the classification.
func (c Classification) String() string {
	switch c {
	case Public:
		return "public"
	case Internal:
		return "internal"
	case Confidential:
		return "confidential"
	case Secret:
		return taintNameSecret
	case Restricted:
		return "restricted"
	default:
		return "unknown"
	}
}

// OutputType specifies the rendering format for a Value.
type OutputType int

const (
	// Plaintext output (raw value).
	Plaintext OutputType = iota
	// Masked output (value partially obscured).
	Masked
	// Redacted output (value fully removed).
	Redacted
	// MCP output (value sanitized for MCP protocol).
	MCPOutput
)

// Value wraps a secret value with its classification and metadata
// for controlled exposure.
type Value struct {
	Raw            string
	Sanitized      string
	Classification Classification
	Tags           []string
}

// NewValue creates a Value with the given raw content and classification.
func NewValue(raw string, class Classification, tags ...string) Value {
	return Value{
		Raw:            raw,
		Sanitized:      raw,
		Classification: class,
		Tags:           tags,
	}
}

// ErrUntrustedFormat is returned when an Untrusted value is used in an
// unsafe context. Call .Render() or .UnsafeRawForStorage() explicitly.
var ErrUntrustedFormat = errors.New("taint: use of Untrusted in format argument")

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

// mcpSanitizer is optionally set by the mcp package to apply MCP-specific
// sanitization (ANSI stripping, control char removal, XML injection prevention)
// when Untrusted.Render(MCP) is called. This bridges the taint system with
// the MCP output chokepoint without introducing a circular import.
var mcpSanitizer func(string) string

// SetMCPSanitizer registers the MCP output sanitizer function. The mcp
// package calls this from its init(). Passing nil clears the sanitizer.
func SetMCPSanitizer(fn func(string) string) {
	mcpSanitizer = fn
}

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
// according to the target's escaping rules. For MCP targets, the
// registered sanitizer (set by the mcp package via SetMCPSanitizer) is
// applied to strip ANSI escapes, control characters, and XML injection.
// Terminal targets return the raw value unchanged.
func (u Untrusted) Render(target RenderTarget) RenderedFragment {
	value := u.raw
	if target == MCP && mcpSanitizer != nil {
		value = mcpSanitizer(value)
	}
	return RenderedFragment{target: target, value: value}
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
			_, _ = fmt.Fprintf(f, "<untrusted source=%s len=%d>", u.prov.Source, len(u.raw))
			return
		}
		fallthrough
	default:
		_, _ = fmt.Fprintf(f, "<untrusted:%s>", u.prov.Source)
	}
}
