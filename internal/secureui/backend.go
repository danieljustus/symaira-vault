package secureui

import "os"

// backend is the internal interface implemented by each input source.
type backend interface {
	capability() Capability
	prompt(req PromptRequest) (string, error)
}

// chooseBackend picks the best available backend, honoring the
// OPENPASS_SECUREUI environment override ("tty", "gui", or "none").
//
// Default order: TTY (interactive run) → GUI (HTTP server, LaunchAgent, etc.).
func chooseBackend() backend {
	switch os.Getenv("OPENPASS_SECUREUI") {
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
