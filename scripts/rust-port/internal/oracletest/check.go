// Package oracletest runs ordinary generator tests through the same immutable
// two-reference acceptance path as the native MCP fixture gate.
package oracletest

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Check returns the freshly checked historical fixture, never a capture from
// the current product compiled under a historical revision label.
func Check(t *testing.T, generator string, cases int) []byte {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate oracle acceptance helper")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../.."))
	output := filepath.Join(t.TempDir(), "evidence")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-B", "scripts/rust-port/mcp_fixture_contract.py", "--generator", generator, "--output", output)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.6", "GOWORK=off", "GOENV=off")
	log, err := cmd.CombinedOutput()
	t.Log(string(log))
	if err != nil {
		t.Fatalf("two-reference generator acceptance: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(output, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		Passed   bool
		Compiler struct{ Version string }
		Lanes    []struct {
			Lane         string
			SourceCommit string `json:"source_commit"`
			Passed       bool
			Cases        int
			Fixtures     int
		}
	}
	if err = json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.Passed || receipt.Compiler.Version != "go1.26.6" || len(receipt.Lanes) != 2 {
		t.Fatal("missing passing two-reference receipt with actual historical compiler")
	}
	for i, expected := range []struct{ lane, commit string }{
		{"historical", "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"},
		{"corrected", "24acdb08fcc7021262717aa803d72eb8d151c66a"},
	} {
		lane := receipt.Lanes[i]
		if lane.Lane != expected.lane || lane.SourceCommit != expected.commit || !lane.Passed || lane.Cases != cases || lane.Fixtures != 1 {
			t.Fatalf("incomplete %s generator acceptance", expected.lane)
		}
	}
	data, err = os.ReadFile(filepath.Join(output, "historical", generator+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
