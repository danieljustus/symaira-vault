package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScenariosAreDeterministicAndCoverEveryRule(t *testing.T) {
	first, err := marshal(buildScenarios())
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshal(buildScenarios())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("anomaly scenarios are not deterministic")
	}
	seen := map[string]bool{}
	for _, s := range buildScenarios() {
		for _, e := range s.Events {
			for _, h := range e.Hooks {
				seen[h.Type] = true
			}
		}
	}
	for _, kind := range []string{"canary_access", "off_hours", "sweep", "rate_anomaly", "tool_chain"} {
		if !seen[kind] {
			t.Fatalf("no scenario produces a %s alert", kind)
		}
	}
}

func TestDispatchFactsRejectChangedSource(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(root, dispatchFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extractDispatch(src); err != nil {
		t.Fatalf("pinned source: %v", err)
	}
	for _, mutation := range []struct{ from, to string }{
		{`"anomaly_"+string(alert.Type), alert.Path, false)`, `"anomaly_"+string(alert.Type), alert.Path, true)`},
		{`s.invalidateApprovalCache()`, `_ = 0`},
		{`agentName == ""`, `false`},
		{`s.logAudit(context.Background(), "anomaly_"`, `s.logAudit(ctx, "anomaly_"`},
	} {
		mutated := strings.Replace(string(src), mutation.from, mutation.to, 1)
		if mutated == string(src) {
			t.Fatalf("mutation %q did not apply", mutation.from)
		}
		if _, err := extractDispatch([]byte(mutated)); err == nil {
			t.Fatalf("dispatch facts accepted mutation %q", mutation.from)
		}
	}
}
