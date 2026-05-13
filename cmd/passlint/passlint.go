// Package passlint defines an analyzer that detects misuse of
// taint.Untrusted values in formatted output calls and string concatenation.
//
// The analyzer flags:
//   - taint.Untrusted values passed as arguments to fmt.Print*, fmt.Sprintf*,
//     fmt.Fprint*, fmt.Sprint*, etc.
//   - taint.Untrusted values used as operands in string concatenation (+)
//
// Safe uses (Render, Bytes, UnsafeRawForStorage, Provenance, Tags) and
// the Untrusted.Format() method itself are excluded.
package passlint

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// Analyzer is the passlint analyzer instance.
var Analyzer = &analysis.Analyzer{
	Name: "passlint",
	Doc:  "detects use of taint.Untrusted in fmt.Print* calls and string concatenation",
	Run:  run,
}

// untrustedPkgName is the package name of the taint package.
const untrustedPkgName = "taint"

// untrustedTypeName is the type name.
const untrustedTypeName = "Untrusted"

// fmtPrintFuncs is the set of fmt functions whose arguments we check.
var fmtPrintFuncs = map[string]bool{
	"Print": true, "Printf": true, "Println": true,
	"Sprint": true, "Sprintf": true, "Sprintln": true,
	"Fprint": true, "Fprintf": true, "Fprintln": true,
}

func run(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncDecl:
				// Skip inspection inside Untrusted.Format() itself.
				if isUntrustedFormatMethod(pass, n) {
					return false
				}
			case *ast.CallExpr:
				checkCall(pass, n)
			case *ast.BinaryExpr:
				if n.Op == token.ADD {
					checkBinary(pass, n)
				}
			}
			return true
		})
	}
	return nil, nil
}

// isUntrustedType reports whether the given type is taint.Untrusted.
// We match by package name ("taint") and type name ("Untrusted") rather than
// the full import path. This keeps the analyzer portable across testdata
// (where the package lives at import path "taint") and production (where
// it lives at "github.com/danieljustus/OpenPass/internal/vault/taint").
func isUntrustedType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil {
		return false
	}
	pkg := obj.Pkg()
	if pkg == nil {
		return false
	}
	return pkg.Name() == untrustedPkgName && obj.Name() == untrustedTypeName
}

// isUntrustedFormatMethod reports whether fd is the Format method on Untrusted.
func isUntrustedFormatMethod(pass *analysis.Pass, fd *ast.FuncDecl) bool {
	if fd.Name.Name != "Format" || fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	t := pass.TypesInfo.TypeOf(fd.Recv.List[0].Type)
	if t == nil {
		return false
	}
	// Dereference pointer receiver (*Untrusted -> Untrusted).
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	return isUntrustedType(t)
}

// isFmtPrintFunc reports whether the call expression refers to one of the
// target fmt printing functions (e.g. fmt.Sprintf, fmt.Print, etc.).
func isFmtPrintFunc(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
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
	return pkgName.Imported().Path() == "fmt" && fmtPrintFuncs[sel.Sel.Name]
}

// checkCall reports diagnostics for fmt print calls that receive Untrusted args.
func checkCall(pass *analysis.Pass, call *ast.CallExpr) {
	if !isFmtPrintFunc(pass, call) {
		return
	}
	for _, arg := range call.Args {
		t := pass.TypesInfo.TypeOf(arg)
		if isUntrustedType(t) {
			pass.Reportf(arg.Pos(), "use of taint.Untrusted in format argument: call .Render() or .UnsafeRawForStorage() explicitly")
		}
	}
}

// checkBinary reports diagnostics for string concatenation with Untrusted values.
func checkBinary(pass *analysis.Pass, expr *ast.BinaryExpr) {
	if isUntrustedType(pass.TypesInfo.TypeOf(expr.X)) {
		pass.Reportf(expr.X.Pos(), "use of taint.Untrusted in format argument: call .Render() or .UnsafeRawForStorage() explicitly")
	}
	if isUntrustedType(pass.TypesInfo.TypeOf(expr.Y)) {
		pass.Reportf(expr.Y.Pos(), "use of taint.Untrusted in format argument: call .Render() or .UnsafeRawForStorage() explicitly")
	}
}

// NewAnalyzer returns the passlint analyzer (convenience for embedding).
func NewAnalyzer() *analysis.Analyzer {
	return Analyzer
}

func init() {
	// Ensure Analyzer is properly set up.
	if Analyzer == nil {
		panic(fmt.Errorf("passlint: Analyzer is nil"))
	}
}
