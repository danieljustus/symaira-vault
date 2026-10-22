//go:build linux

package main

import (
	"os"

	"github.com/danieljustus/symaira-vault/internal/autotype"
)

const strictEnv = "SYMVAULT_AUTOTYPE_STRICT_FOCUS"

// runAutotypeCase drives the production autotype.NewLinuxAutotype with fake
// tools on a disposable PATH. The environment is restored afterwards.
func runAutotypeCase(c autotypeCase) (autotypeCase, error) {
	sb, err := newSandbox(c.Tools, toolParams{exit: c.TypeExit, focus1: c.Focus[0], focus2: c.Focus[1], focusExit: c.FocusExit}, "")
	if err != nil {
		return c, err
	}
	defer sb.close()
	restore := setEnv(map[string]*string{
		"PATH":            ptr(sb.bin),
		"HOME":            ptr(sb.home),
		"TMPDIR":          ptr(sb.root),
		"WAYLAND_DISPLAY": waylandValue(c.WaylandDisplay, c.WaylandEmptySet),
		strictEnv:         strictValue(c.Strict),
	})
	defer restore()
	if err := autotype.NewLinuxAutotype().Type(c.Text); err != nil {
		c.Error = err.Error()
	}
	c.Calls, err = sb.readCalls()
	return c, err
}

func ptr(s string) *string { return &s }

func waylandValue(value string, emptySet bool) *string {
	if value == "" && !emptySet {
		return nil
	}
	return ptr(value)
}

func strictValue(value string) *string {
	if value == "" {
		return nil
	}
	return ptr(value)
}

func setEnv(values map[string]*string) func() {
	type saved struct {
		value string
		set   bool
	}
	previous := make(map[string]saved, len(values))
	for key, value := range values {
		old, set := os.LookupEnv(key)
		previous[key] = saved{old, set}
		if value == nil {
			_ = os.Unsetenv(key)
		} else {
			_ = os.Setenv(key, *value)
		}
	}
	return func() {
		for key, p := range previous {
			if p.set {
				_ = os.Setenv(key, p.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}
}
