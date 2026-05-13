package mcp

import (
	"context"
	"fmt"

	"github.com/danieljustus/OpenPass/internal/vault/taint"
)

// Intent describes a sensitive operation that requires user approval.
type Intent struct {
	// Action is the operation being performed (e.g. "get_entry_value",
	// "set_entry_field", "delete_entry").
	Action string
	// EntryPath is the vault path the operation targets.
	EntryPath string
	// FieldName is the specific field being accessed, if applicable.
	FieldName string
	// Summary is a human-readable description shown in the approval prompt.
	Summary string
}

// requireApproval checks whether the current agent profile requires approval
// for the given intent. Returns nil if the operation is allowed, or an error
// if it is denied or the user did not approve.
func (s *Server) requireApproval(ctx context.Context, intent Intent) error {
	if s == nil || s.agent == nil {
		return fmt.Errorf("server not initialized")
	}

	mode := s.agent.ApprovalMode
	if mode == "" {
		if s.agent.RequireApproval {
			mode = "prompt"
		} else {
			mode = "none"
		}
	}

	switch mode {
	case "none", "auto":
		return nil
	case "deny":
		s.logAudit(ctx, "approval."+intent.Action+".denied", intent.EntryPath, false)
		return fmt.Errorf("%s denied: approval mode is 'deny'", intent.Action)
	case "prompt":
		if !IsTTYPresent() {
			s.logAudit(ctx, "approval."+intent.Action+".denied", intent.EntryPath, false)
			return fmt.Errorf("%s requires approval but no TTY available", intent.Action)
		}

		s.logAudit(ctx, "approval."+intent.Action+".requested", intent.EntryPath, true)
		timeout := s.agent.ApprovalTimeout
		if timeout <= 0 {
			timeout = defaultTimeout
		}
		result := RequestApproval(ApprovalRequest{
			Operation: intent.Action,
			Details:   intent.Summary,
			Timeout:   timeout,
		})
		if result.Error != nil {
			return fmt.Errorf("%s approval failed: %w", intent.Action, result.Error)
		}
		if !result.Approved {
			s.logAudit(ctx, "approval."+intent.Action+".denied", intent.EntryPath, false)
			return fmt.Errorf("%s denied: user did not approve", intent.Action)
		}
		s.logAudit(ctx, "approval."+intent.Action+".granted", intent.EntryPath, true)
		return nil
	default:
		return nil
	}
}

// RenderSummary produces a safe terminal summary for an approval prompt.
// It strips ANSI/control characters from the entry path and field name.
func RenderSummary(action, entryPath, fieldName string) string {
	safePath := sanitizeForSummary(entryPath)
	safeField := sanitizeForSummary(fieldName)
	if safeField != "" {
		return fmt.Sprintf("%s on %s field %s", action, safePath, safeField)
	}
	return fmt.Sprintf("%s on %s", action, safePath)
}

// sanitizeForSummary strips ANSI and control characters from a string
// for inclusion in terminal approval prompts.
func sanitizeForSummary(s string) string {
	if s == "" {
		return s
	}
	// Use the terminal render's ANSI stripping logic
	u := taint.Wrap(s, taint.Provenance{Source: "summary"})
	return stripTerminalControl(u.UnsafeRawForStorage())
}

// stripTerminalControl removes ANSI escape sequences and control characters.
func stripTerminalControl(s string) string {
	out := make([]byte, 0, len(s))
	inEscape := false
	inOSC := false
	for i := 0; i < len(s); i++ {
		b := s[i]
		if inEscape {
			if b == '[' || (b >= '0' && b <= '9') || b == ';' {
				continue
			}
			if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
				inEscape = false
				continue
			}
			inEscape = false
			continue
		}
		if inOSC {
			if b == 0x07 {
				inOSC = false
				continue
			}
			if b == '\\' {
				inOSC = false
				continue
			}
			continue
		}
		if b == 0x1b {
			if i+1 < len(s) && s[i+1] == '[' {
				inEscape = true
				continue
			}
			if i+1 < len(s) && s[i+1] == ']' {
				inOSC = true
				i++
				continue
			}
			continue
		}
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			continue
		}
		if b == 0x7f {
			continue
		}
		out = append(out, b)
	}
	return string(out)
}
