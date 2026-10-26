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
	sb, err := newPlacedSandbox(placement{Tools: c.Tools, RelTools: c.RelTools, CwdTools: c.CwdTools}, toolParams{exit: c.TypeExit, focus1: c.Focus[0], focus2: c.Focus[1], focusExit: c.FocusExit}, "")
	if err != nil {
		return c, err
	}
	defer sb.close()
	// Relative and empty PATH entries resolve against the process working
	// directory, so the in-process Go code runs inside the scenario cwd.
	previousDir, err := os.Getwd()
	if err != nil {
		return c, err
	}
	if chdirErr := os.Chdir(sb.cwd); chdirErr != nil {
		return c, chdirErr
	}
	defer func() { _ = os.Chdir(previousDir) }()
	restore := setEnv(map[string]*string{
		"PATH":            ptr(sb.pathValue(c.PathSpec)),
		"HOME":            ptr(sb.home),
		"TMPDIR":          ptr(sb.root),
		"WAYLAND_DISPLAY": waylandValue(c.WaylandDisplay, c.WaylandEmptySet),
		strictEnv:         strictValue(c.Strict),
	})
	defer restore()
	if typeErr := autotype.NewLinuxAutotype().Type(c.Text); typeErr != nil {
		c.Error = typeErr.Error()
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
