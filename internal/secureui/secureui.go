// Package secureui provides cross-platform secure input prompts for sensitive
// data. It supports interactive TTY prompts and native OS GUI dialogs
// (osascript on macOS, zenity/kdialog on Linux, PowerShell on Windows) so that
// the OpenPass MCP server can collect secrets from the user even when no
// terminal is attached (HTTP transport, LaunchAgent, GUI-launched agent).
package secureui

import (
	"errors"
	"fmt"
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
		return "OpenPass requires a value."
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
