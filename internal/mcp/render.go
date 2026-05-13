package mcp

import (
	"fmt"
	"strings"
)

// globalChokepoint is the shared MCP output sanitizer instance.
// It is used by callToolResultPayload and handleSanitizeOutput.
var globalChokepoint = &RenderChokepoint{}

// RenderChokepoint is the central output sanitization point for MCP responses.
// All tool responses should pass through this chokepoint before being sent
// to the MCP client to prevent prompt injection via vault content.
type RenderChokepoint struct{}

// NewRenderChokepoint creates a new RenderChokepoint instance.
func NewRenderChokepoint() *RenderChokepoint {
	return &RenderChokepoint{}
}

// SanitizeForMCP sanitizes text for safe inclusion in MCP responses.
// Strips ANSI escape sequences, control characters, OSC-8 hyperlinks,
// and neutralizes XML structure injection (e.g. </data>).
func (rc *RenderChokepoint) SanitizeForMCP(text string) string {
	return sanitizeMCPText(text)
}

// sanitizeMCPText is the core MCP text sanitizer.
func sanitizeMCPText(text string) string {
	var out strings.Builder
	out.Grow(len(text))

	inEscape := false
	inOSC := false

	for i := 0; i < len(text); i++ {
		ch := text[i]

		if inEscape {
			if ch == '[' || (ch >= '0' && ch <= '9') || ch == ';' || ch == '?' {
				continue
			}
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inEscape = false
				continue
			}
			inEscape = false
			continue
		}

		if inOSC {
			if ch == 0x07 {
				inOSC = false
				continue
			}
			if ch == '\\' && i+1 < len(text) {
				inOSC = false
				i++
				continue
			}
			continue
		}

		if ch == 0x1b {
			if i+1 < len(text) && text[i+1] == ']' {
				inOSC = true
				i++
				continue
			}
			inEscape = true
			continue
		}

		if ch < 0x20 && ch != '\t' && ch != '\n' && ch != '\r' {
			continue
		}
		if ch == 0x7f {
			continue
		}

		if ch == '<' && i+6 < len(text) {
			rest := text[i:]
			if strings.HasPrefix(rest, "</data>") {
				out.WriteString("</ data>")
				i += 6
				continue
			}
		}

		out.WriteByte(ch)
	}

	return out.String()
}

// EmbedAsData wraps untrusted content in a <data> block with the given
// label. The content is sanitized: ANSI/control sequences are stripped,
// </data> is neutralized to prevent tag injection. This ensures the
// wrapped text is treated as inert data by the LLM.
func EmbedAsData(label, untrusted string) string {
	safe := sanitizeMCPText(untrusted)
	return fmt.Sprintf("<data label=%q>%s</data>", label, safe)
}
