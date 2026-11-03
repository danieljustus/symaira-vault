package main

import (
	"strings"
	"testing"
)

func TestBareDashInputsAreUniqueAndStateful(t *testing.T) {
	seen := map[string]bool{}
	states := map[string]int{}
	for _, in := range bareDashInputs() {
		if seen[in.name] {
			t.Errorf("duplicate %s", in.name)
		}
		seen[in.name] = true
		states[in.state]++
		if !strings.HasPrefix(in.name, "dash_") || !strings.HasSuffix(in.name, "_"+in.state) {
			t.Errorf("%s does not name its state %s", in.name, in.state)
		}
		if in.description == "" {
			t.Errorf("%s needs a description", in.name)
		}
		if _, err := specForState(in.state, testSeed()); err != nil {
			t.Errorf("%s: %v", in.name, err)
		}
	}
	if states[stateUninitialized] == 0 || states[stateInitialized] == 0 {
		t.Fatalf("states = %v", states)
	}
}

// Each class of CLI-005 must stay in the corpus: a generator edit that silently
// dropped one would leave the replay green.
func TestBareDashInputsCoverEveryClass(t *testing.T) {
	want := map[string]func(args []string) bool{
		"no arguments":                 func(a []string) bool { return len(a) == 0 },
		"lone dash alone":              func(a []string) bool { return len(a) == 1 && a[0] == "-" },
		"double dash alone":            func(a []string) bool { return len(a) == 1 && a[0] == "--" },
		"persistent flag alone":        func(a []string) bool { return len(a) == 1 && a[0] == "--json" },
		"command after double dash":    func(a []string) bool { return len(a) == 2 && a[0] == "--" && a[1] == "list" },
		"flag after double dash":       func(a []string) bool { return len(a) == 2 && a[0] == "--" && a[1] == "--json" },
		"dash before command":          func(a []string) bool { return len(a) == 2 && a[0] == "-" && a[1] == "list" },
		"dash before group command":    func(a []string) bool { return len(a) == 3 && a[0] == "-" && a[1] == "share" && a[2] == "list" },
		"dash inside group":            func(a []string) bool { return len(a) == 3 && a[0] == "share" && a[1] == "-" && a[2] == "list" },
		"dash counted by pflag":        func(a []string) bool { return len(a) == 3 && a[0] == "-" && a[1] == "get" && a[2] == "x" },
		"dash value of a flag":         func(a []string) bool { return len(a) == 3 && a[0] == "--vault" && a[1] == "-" && a[2] == "list" },
		"dash before flag and command": func(a []string) bool { return len(a) == 3 && a[0] == "-" && a[1] == "--json" && a[2] == "list" },
		"help topic after dash":        func(a []string) bool { return len(a) == 3 && a[0] == "help" && a[1] == "-" && a[2] == "list" },
		"help of only a dash":          func(a []string) bool { return len(a) == 2 && a[0] == "help" && a[1] == "-" },
		"unknown topic with dash":      func(a []string) bool { return len(a) == 3 && a[0] == "help" && a[1] == "foo" && a[2] == "-" },
		"dash before help":             func(a []string) bool { return len(a) == 2 && a[0] == "-" && a[1] == "help" },
		"flag after a positional":      func(a []string) bool { return len(a) == 3 && a[0] == "version" && a[1] == "-" && a[2] == "--json" },
	}
	covered := map[string]bool{}
	for _, in := range bareDashInputs() {
		for name, match := range want {
			if match(in.args) {
				covered[name] = true
			}
		}
	}
	for name := range want {
		if !covered[name] {
			t.Errorf("no bare-dash scenario covers %s", name)
		}
	}
}

// A case that reads the vault runs where the vault exists; the shapes that end
// in a diagnostic before any vault access run in the empty sandbox only.
func TestBareDashVaultCasesRunInBothStates(t *testing.T) {
	perSlug := map[string][]string{}
	for _, c := range bareDashCases() {
		perSlug[c.slug] = c.states
	}
	for _, slug := range []string{"dash_before_list", "dash_after_list", "dash_inside_group_list", "dash_before_group_list"} {
		if len(perSlug[slug]) != 2 {
			t.Errorf("%s states = %v, want both", slug, perSlug[slug])
		}
	}
	for _, slug := range []string{"root_dash", "after_double_dash_command", "dash_before_get_name"} {
		if got := perSlug[slug]; len(got) != 1 || got[0] != stateUninitialized {
			t.Errorf("%s states = %v, want uninitialized only", slug, got)
		}
	}
}
