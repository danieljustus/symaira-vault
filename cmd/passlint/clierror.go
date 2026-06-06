package passlint

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// CLIErrorAnalyzer flags bare fmt.Errorf calls inside cobra RunE handlers.
//
// RunE handlers must return errors built from the standardized constructors
// in internal/errors (errors.NotFound, errors.ReadFailed, errors.Wrap, ...)
// so exit codes stay stable across the CLI. A bare fmt.Errorf collapses
// every failure into ExitGeneralError (1) and breaks the scripting contract
// documented in docs/cli-exit-codes.md.
var CLIErrorAnalyzer = &analysis.Analyzer{
	Name: "clierror",
	Doc:  "flags bare fmt.Errorf in cobra RunE handlers; use the standardized constructors in internal/errors instead",
	Run:  runCLIError,
}

// runCLIError walks every function literal assigned to a RunE field on a
// *cobra.Command literal and reports any fmt.Errorf call in its body.
func runCLIError(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if !isCobraCommandLit(pass, cl) {
				return true
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "RunE" {
					continue
				}
				fnLit, ok := kv.Value.(*ast.FuncLit)
				if !ok {
					continue
				}
				scanFuncLitBody(pass, fnLit)
			}
			return true
		})
	}
	return nil, nil
}

// scanFuncLitBody reports every fmt.Errorf call inside the function body.
func scanFuncLitBody(pass *analysis.Pass, fn *ast.FuncLit) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isFmtErrorf(pass, call) {
			pass.Reportf(call.Pos(), "do not use fmt.Errorf in RunE handlers; use the standardized constructors in internal/errors (e.g. errors.NotFound, errors.InvalidInput, errors.Wrap)")
		}
		return true
	})
}

// isCobraCommandLit reports whether cl is a composite literal whose type
// resolves to *cobra.Command.
//
// We match by local package name ("cobra") and type name ("Command") rather
// than the full import path. This keeps the analyzer portable across testdata
// (where the package can be a local stub) and production (where it lives at
// import path "github.com/spf13/cobra").
func isCobraCommandLit(pass *analysis.Pass, cl *ast.CompositeLit) bool {
	t := pass.TypesInfo.TypeOf(cl)
	if t == nil {
		return false
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Name() == "cobra" && obj.Name() == "Command"
}

// isFmtErrorf reports whether call is a direct fmt.Errorf call.
func isFmtErrorf(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name != "Errorf" {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	obj := pass.TypesInfo.ObjectOf(pkgIdent)
	if obj == nil {
		return false
	}
	pkgName, ok := obj.(*types.PkgName)
	if !ok {
		return false
	}
	return pkgName.Imported().Path() == "fmt"
}
