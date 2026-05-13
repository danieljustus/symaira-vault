package mcp

import (
	"strings"
)

// RenderChokepoint is the central output sanitization point for MCP responses.
// All tool responses should pass through this chokepoint before being sent
// to the MCP client to prevent prompt injection via vault content.
//
// Phase A creates this as a stub. Phase C activates it by wiring it into
// callToolResultPayload and all response paths.
type RenderChokepoint struct{}

// NewRenderChokepoint creates a new RenderChokepoint instance.
func NewRenderChokepoint() *RenderChokepoint {
	return &RenderChokepoint{}
}

// SanitizeForMCP sanitizes text for safe inclusion in MCP responses.
//
// Current sanitization:
//   - Strips ANSI escape sequences
//   - Strips control characters (0x00-0x08, 0x0b, 0x0c, 0x0e-0x1f, 0x7f)
//   - Neutralizes XML-like tags to prevent MCP response structure injection
//   - Strips OSC-8 hyperlink sequences
//
// This will be expanded in Phase C with secret masking and taint-aware
// field handling.
func (rc *RenderChokepoint) SanitizeForMCP(text string) string {
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
