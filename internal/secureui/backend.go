package secureui

import "os"

// backend is the internal interface implemented by each input source.
type backend interface {
	capability() Capability
	prompt(req PromptRequest) (string, error)
}

// chooseBackend picks the best available backend, honoring the
// SYMVAULT_SECUREUI environment override (or OPENPASS_SECUREUI as fallback)
// ("tty", "gui", or "none").
//
// Default order: TTY (interactive run) → GUI (HTTP server, LaunchAgent, etc.).
func chooseBackend() backend {
	v := os.Getenv("SYMVAULT_SECUREUI")
	if v == "" {
		v = os.Getenv("OPENPASS_SECUREUI")
	}
	switch v {
	case "tty":
		if b := newTTYBackend(); b != nil {
			return b
		}
		return noneBackend{}
	case "gui":
		if b := newGUIBackend(defaultRunner); b != nil {
			return b
		}
		return noneBackend{}
	case "none":
		return noneBackend{}
	}

	if b := newTTYBackend(); b != nil {
		return b
	}
	if b := newGUIBackend(defaultRunner); b != nil {
		return b
	}
	return noneBackend{}
}

type noneBackend struct{}

func (noneBackend) capability() Capability                 { return CapNone }
func (noneBackend) prompt(_ PromptRequest) (string, error) { return "", ErrUnavailable }
