package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestUICommandExperimentalRequired(t *testing.T) {
	// Snapshot the flag-bound package variables; the cobra flag bound to
	// --experimental shares its address with the package-level `uiExperimental`
	// var, so toggling the bound value is enough to simulate a flag flip.
	origExperimental := uiExperimental
	origPrintKeybindings := uiPrintKeybindings
	t.Cleanup(func() {
		uiExperimental = origExperimental
		uiPrintKeybindings = origPrintKeybindings
	})

	// Disable the early --print-keybindings shortcut so the gate runs.
	uiPrintKeybindings = false
	uiExperimental = false

	var errBuf bytes.Buffer
	rootCmd.SetErr(&errBuf)
	rootCmd.SetArgs([]string{"ui"})

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected ui command to fail without --experimental flag")
	} else if !strings.Contains(err.Error(), "experimental") {
		t.Errorf("expected error message to mention 'experimental', got: %q", err.Error())
	}
}

func TestUICommandExperimentalFlagRegistered(t *testing.T) {
	flag := uiCmd.Flags().Lookup("experimental")
	if flag == nil {
		t.Fatal("expected --experimental flag to be registered on uiCmd")
	}
	if flag.DefValue != "false" {
		t.Errorf("expected --experimental default value 'false', got %q", flag.DefValue)
	}
}
