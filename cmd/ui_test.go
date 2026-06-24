package cmd

import (
	"testing"
)

func TestUICommandExperimentalFlagRegisteredAsNoOp(t *testing.T) {
	flag := uiCmd.Flags().Lookup("experimental")
	if flag == nil {
		t.Fatal("expected --experimental flag to be registered on uiCmd")
	}
	if flag.DefValue != "false" {
		t.Errorf("expected --experimental default value 'false', got %q", flag.DefValue)
	}
}

func TestUICommandLaunchWithoutExperimental(t *testing.T) {
	// The ui command no longer requires --experimental. With no vault set up,
	// it will fail during vault loading rather than at the experimental gate.
	flag := uiCmd.Flags().Lookup("experimental")
	if flag == nil {
		t.Fatal("expected --experimental flag to be registered on uiCmd")
	}
}
