package mcp

import (
	"github.com/danieljustus/OpenPass/internal/secureui"
)

// secureInputPromptFn is the indirection used by handleSecureInput and
// handleRequestCredential. Tests override it to bypass real OS dialogs.
var secureInputPromptFn = secureui.Prompt

// secureInputCapabilityFn is the indirection used by secureInputToolAvailable.
// Tests override it to simulate TTY/GUI/none environments.
var secureInputCapabilityFn = secureui.Detect

// secureInputToolAvailable returns true when at least one secure-input backend
// (TTY or native GUI) is reachable. It does not depend on the transport, so
// the secure_input and request_credential tools become available in HTTP mode
// whenever the host has a usable GUI dialog.
func secureInputToolAvailable(_ *Server) bool {
	return secureInputCapabilityFn() != secureui.CapNone
}
