package passlint

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

var MCPCkeckScopeAnalyzer = &analysis.Analyzer{
	Name: "mcpcheckscope",
	Doc:  "detects MCP tool handlers that do not call s.checkScope() after parameter parsing",
	Run:  runCheckScope,
}

func isMCPHandler(pass *analysis.Pass, fd *ast.FuncDecl) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	recvType := pass.TypesInfo.TypeOf(fd.Recv.List[0].Type)
	if recvType == nil {
		return false
	}
	ptr, ok := recvType.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}
	if named.Obj().Name() != "Server" {
		return false
	}
	if !strings.HasPrefix(fd.Name.Name, "handle") {
		return false
	}
	if fd.Type.Params == nil || fd.Type.Params.NumFields() != 2 {
		return false
	}
	if fd.Type.Results == nil || fd.Type.Results.NumFields() != 2 {
		return false
	}
	return true
}

func hasCheckScopeCall(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "checkScope" {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "s" {
			found = true
			return false
		}
		return true
	})
	return found
}

func runCheckScope(pass *analysis.Pass) (interface{}, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if !isMCPHandler(pass, fd) {
				return true
			}
			if !hasCheckScopeCall(fd.Body) {
				pass.Reportf(fd.Name.Pos(), "MCP handler %s does not call s.checkScope() — add scope validation after parameter parsing", fd.Name.Name)
			}
			return true
		})
	}
	return nil, nil
}
