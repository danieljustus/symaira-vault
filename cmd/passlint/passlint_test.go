// Package passlint_test tests the passlint analyzer using analysistest.
package passlint_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/danieljustus/OpenPass/cmd/passlint"
)

func TestAnalyzer(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(t, testdata, passlint.Analyzer, "p/a")
}
