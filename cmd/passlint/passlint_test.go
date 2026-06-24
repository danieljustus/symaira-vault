// Package passlint_test tests the passlint analyzers using analysistest.
package passlint_test

import (
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/danieljustus/symaira-vault/cmd/passlint"
)

func countDiagnostics(results []*analysistest.Result) int {
	var n int
	for _, r := range results {
		n += len(r.Diagnostics)
	}
	return n
}

func diagnosticMessages(results []*analysistest.Result) []string {
	var msgs []string
	for _, r := range results {
		for _, d := range r.Diagnostics {
			msgs = append(msgs, d.Message)
		}
	}
	return msgs
}

func TestAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, passlint.Analyzer, "p/a")
	if len(results) == 0 {
		t.Fatal("expected at least one analysistest result")
	}
	got := countDiagnostics(results)
	if got != 11 {
		t.Errorf("passlint Analyzer: expected 11 diagnostics, got %d", got)
	}
	msgs := diagnosticMessages(results)
	for _, m := range msgs {
		if !strings.Contains(m, "use of taint.Untrusted") {
			t.Errorf("unexpected diagnostic message: %q", m)
		}
	}
}

func TestMCPCkeckScopeAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, passlint.MCPCkeckScopeAnalyzer, "mcp/handlers")
	if len(results) == 0 {
		t.Fatal("expected at least one analysistest result")
	}
	got := countDiagnostics(results)
	if got != 1 {
		t.Errorf("MCPCkeckScopeAnalyzer: expected 1 diagnostic, got %d", got)
	}
	msgs := diagnosticMessages(results)
	if len(msgs) > 0 && !strings.Contains(msgs[0], "does not call s.checkScope()") {
		t.Errorf("unexpected diagnostic message: %q", msgs[0])
	}
}

func TestMCPStringSafelyAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, passlint.MCPStringSafelyAnalyzer, "mcp/strings")
	if len(results) == 0 {
		t.Fatal("expected at least one analysistest result")
	}
	got := countDiagnostics(results)
	if got != 1 {
		t.Errorf("MCPStringSafelyAnalyzer: expected 1 diagnostic, got %d", got)
	}
	msgs := diagnosticMessages(results)
	if len(msgs) > 0 && !strings.Contains(msgs[0], "string() cast on taint.Untrusted") {
		t.Errorf("unexpected diagnostic message: %q", msgs[0])
	}
}

func TestMCPMarshalAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, passlint.MCPMarshalAnalyzer, "mcp/marshal")
	if len(results) == 0 {
		t.Fatal("expected at least one analysistest result")
	}
	got := countDiagnostics(results)
	if got != 2 {
		t.Errorf("MCPMarshalAnalyzer: expected 2 diagnostics, got %d", got)
	}
	msgs := diagnosticMessages(results)
	for _, m := range msgs {
		if !strings.Contains(m, "json.Marshal in MCP code") {
			t.Errorf("unexpected diagnostic message: %q", m)
		}
	}
}

func TestCLIErrorAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	results := analysistest.Run(t, testdata, passlint.CLIErrorAnalyzer, "clierror/a")
	if len(results) == 0 {
		t.Fatal("expected at least one analysistest result")
	}
	got := countDiagnostics(results)
	if got != 1 {
		t.Errorf("CLIErrorAnalyzer: expected 1 diagnostic, got %d", got)
	}
	msgs := diagnosticMessages(results)
	if len(msgs) > 0 && !strings.Contains(msgs[0], "fmt.Errorf in RunE handlers") {
		t.Errorf("unexpected diagnostic message: %q", msgs[0])
	}
}
