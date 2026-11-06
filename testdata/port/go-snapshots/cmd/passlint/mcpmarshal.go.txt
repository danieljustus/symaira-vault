package passlint

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
)

var MCPMarshalAnalyzer = &analysis.Analyzer{
	Name: "mcpmarshal",
	Doc:  "detects unsanitized json.Marshal of vault data in MCP handlers",
	Run:  runMarshal,
}

func runMarshal(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name != "Marshal" {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkgIdent.Name != "json" {
				return true
			}
			if len(call.Args) == 0 {
				return true
			}
			pass.Reportf(call.Pos(), "json.Marshal in MCP code — ensure data is sanitized via SanitizeForMCP() or redactEntry() before marshaling")
			return true
		})
	}
	return nil, nil
}
