// Package passlint_test tests the passlint analyzers using analysistest.
package passlint_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/danieljustus/symaira-vault/cmd/passlint"
)

func TestAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, passlint.Analyzer, "p/a")
}

func TestMCPCkeckScopeAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, passlint.MCPCkeckScopeAnalyzer, "mcp/handlers")
}

func TestMCPStringSafelyAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, passlint.MCPStringSafelyAnalyzer, "mcp/strings")
}

func TestMCPMarshalAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, passlint.MCPMarshalAnalyzer, "mcp/marshal")
}

func TestCLIErrorAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, passlint.CLIErrorAnalyzer, "clierror/a")
}
