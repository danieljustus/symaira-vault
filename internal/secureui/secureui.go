// Package secureui provides cross-platform secure input prompts for sensitive
// data. It supports interactive TTY prompts and native OS GUI dialogs
// (osascript on macOS, zenity/kdialog on Linux, PowerShell on Windows) so that
// the Symaira Vault MCP server can collect secrets from the user even when no
// terminal is attached (HTTP transport, LaunchAgent, GUI-launched agent).
package secureui

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Capability identifies which secure-input backend is available.
type Capability int

const (
	// CapNone means no usable backend is available on this host.
	CapNone Capability = iota
	// CapTTY means an interactive terminal is available.
	CapTTY
	// CapGUI means a native OS dialog backend is available.
	CapGUI
)

// String returns a short identifier for the capability.
func (c Capability) String() string {
	switch c {
	case CapTTY:
		return "tty"
	case CapGUI:
		return "gui"
	default:
		return "none"
	}
}

// PromptRequest describes a request for secure user input. Title/Path/Field/
// Description are shown to the user. The returned value is never logged.
type PromptRequest struct {
	Title       string
	Path        string
	Field       string
	Description string
	Hidden      bool
	Timeout     time.Duration
}

// Sentinel errors returned by Prompt.
var (
	ErrCanceled    = errors.New("secure input canceled by user")
	ErrTimeout     = errors.New("secure input timed out")
	ErrUnavailable = errors.New("no secure input backend available")
)

const defaultTimeout = 60 * time.Second

// Detect returns the best available backend on this host.
func Detect() Capability {
	return chooseBackend().capability()
}

// Prompt asks the user for sensitive data using the best available backend.
// The returned value is never logged or written to the server's stdout.
func Prompt(req PromptRequest) (string, error) {
	if req.Timeout <= 0 {
		req.Timeout = defaultTimeout
	}
	b := chooseBackend()
	if b.capability() == CapNone {
		return "", ErrUnavailable
	}
	value, err := b.prompt(req)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", ErrCanceled
	}
	return value, nil
}

// ApprovalRequest describes a request for user approval of a sensitive operation.
type ApprovalRequest struct {
	// Operation is the name of the operation being approved (e.g., "set_entry_field").
	Operation string
	// Details is a human-readable description of what the operation does.
	Details string
	// Timeout is the maximum time to wait for user input.
	Timeout time.Duration
	// CanRemember indicates whether the "remember for session" option is offered.
	CanRemember bool
}

// ApprovalResult represents the outcome of an approval request.
type ApprovalResult struct {
	Approved   bool
	Remembered bool
}

// PromptApproval asks the user to approve or deny a sensitive operation using
// the best available backend (TTY or GUI). Returns the approval result or
// ErrUnavailable if no backend is available.
func PromptApproval(req ApprovalRequest) (ApprovalResult, error) {
	if req.Timeout <= 0 {
		req.Timeout = defaultTimeout
	}
	b := chooseBackend()
	switch b.capability() {
	case CapTTY:
		return promptApprovalTTY(req)
	case CapGUI:
		return promptApprovalGUI(req)
	default:
		return ApprovalResult{}, ErrUnavailable
	}
}

// promptApprovalTTY shows the approval prompt via TTY and reads the user's response.
func promptApprovalTTY(req ApprovalRequest) (ApprovalResult, error) {
	dev, err := openTTYDevice()
	if err != nil {
		return ApprovalResult{}, fmt.Errorf("failed to open TTY: %w", err)
	}
	defer func() { _ = dev.Close() }()

	if out := dev.Output(); out != nil {
		prompt := buildApprovalPrompt(req)
		if _, werr := out.WriteString(prompt); werr != nil {
			return ApprovalResult{}, fmt.Errorf("failed to write to TTY: %w", werr)
		}
	}

	response, rerr := readTTY(dev, req.Timeout)
	if rerr != nil {
		if errors.Is(rerr, ErrCanceled) {
			return ApprovalResult{}, ErrCanceled
		}
		if isTimeout(rerr) {
			return ApprovalResult{}, ErrTimeout
		}
		return ApprovalResult{}, fmt.Errorf("failed to read from TTY: %w", rerr)
	}

	approved := parseApprovalResponse(response)
	remembered := req.CanRemember && parseRememberResponse(response)

	if out := dev.Output(); out != nil {
		if approved || remembered {
			_, _ = fmt.Fprintln(out, "yes")
		} else {
			_, _ = fmt.Fprintln(out, "no")
		}
	}

	return ApprovalResult{
		Approved:   approved || remembered,
		Remembered: remembered,
	}, nil
}

// promptApprovalGUI shows the approval dialog via GUI backend (osascript, zenity, etc.).
func promptApprovalGUI(req ApprovalRequest) (ApprovalResult, error) {
	b := chooseBackend()
	if b.capability() != CapGUI {
		return ApprovalResult{}, ErrUnavailable
	}

	// For GUI, we use the existing prompt function with a special request
	// that asks for "y" or "n" input instead of a secret value.
	guiReq := PromptRequest{
		Title:       "Symaira Vault: Approval Required",
		Description: buildApprovalDescription(req),
		Hidden:      false,
		Timeout:     req.Timeout,
	}

	value, err := b.prompt(guiReq)
	if err != nil {
		return ApprovalResult{}, err
	}

	approved := parseApprovalResponse(value)
	remembered := req.CanRemember && parseRememberResponse(value)

	return ApprovalResult{
		Approved:   approved || remembered,
		Remembered: remembered,
	}, nil
}

// buildApprovalPrompt creates the approval prompt string for TTY display.
func buildApprovalPrompt(req ApprovalRequest) string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                 MCP OPERATION APPROVAL REQUIRED              ║\n")
	sb.WriteString("╠══════════════════════════════════════════════════════════════╣\n")
	if req.Operation != "" {
		fmt.Fprintf(&sb, "║ Operation: %-50s ║\n", truncate(req.Operation))
	}
	if req.Details != "" {
		fmt.Fprintf(&sb, "║ Details:   %-50s ║\n", truncate(req.Details))
	}
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n")
	if req.CanRemember {
		sb.WriteString("\nApprove this operation? (y/n/r, r=remember for session): ")
	} else {
		sb.WriteString("\nApprove this operation? (y/n): ")
	}
	return sb.String()
}

// buildApprovalDescription creates the approval description for GUI display.
func buildApprovalDescription(req ApprovalRequest) string {
	var sb strings.Builder
	sb.WriteString("MCP Operation Approval Required\n\n")
	if req.Operation != "" {
		fmt.Fprintf(&sb, "Operation: %s\n", req.Operation)
	}
	if req.Details != "" {
		fmt.Fprintf(&sb, "Details: %s\n", req.Details)
	}
	if req.CanRemember {
		sb.WriteString("\nType 'y' to approve, 'n' to deny, or 'r' to remember for session.")
	} else {
		sb.WriteString("\nType 'y' to approve or 'n' to deny.")
	}
	return sb.String()
}

// parseApprovalResponse determines if the user approved the operation.
func parseApprovalResponse(response string) bool {
	lower := strings.ToLower(strings.TrimSpace(response))
	return lower == "y" || lower == "yes" || lower == "r" || lower == "remember"
}

// parseRememberResponse determines if the user opted to remember the approval.
func parseRememberResponse(response string) bool {
	lower := strings.ToLower(strings.TrimSpace(response))
	return lower == "r" || lower == "remember"
}

// FormatPrompt renders the request body for backends that take a single text
// blob (osascript, zenity, kdialog, PowerShell). Path/Field/Description are
// joined with newlines.
func FormatPrompt(req PromptRequest) string {
	switch {
	case req.Description != "" && req.Path != "" && req.Field != "":
		return fmt.Sprintf("%s\n\nEntry: %s\nField: %s", req.Description, req.Path, req.Field)
	case req.Path != "" && req.Field != "":
		return fmt.Sprintf("Entry: %s\nField: %s", req.Path, req.Field)
	case req.Description != "":
		return req.Description
	default:
		return "Symaira Vault requires a value."
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
