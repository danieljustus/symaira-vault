package passlint

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

var MCPStringSafelyAnalyzer = &analysis.Analyzer{
	Name: "mcpstringsafely",
	Doc:  "detects direct string() casts on taint.Untrusted values",
	Run:  runStringSafely,
}

func runStringSafely(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if len(call.Args) != 1 {
				return true
			}
			if call.Fun == nil {
				return true
			}
			argType := pass.TypesInfo.TypeOf(call.Args[0])
			if !isUntrustedType(argType) {
				return true
			}
			funType := pass.TypesInfo.TypeOf(call.Fun)
			if funType == nil {
				return true
			}
			if isBasicString(funType) {
				pass.Reportf(call.Pos(), "direct string() cast on taint.Untrusted — use .Render() or .UnsafeRawForStorage() instead")
			}
			return true
		})
	}
	return nil, nil
}

func isBasicString(t types.Type) bool {
	bt, ok := t.(*types.Basic)
	return ok && bt.Kind() == types.String
}
