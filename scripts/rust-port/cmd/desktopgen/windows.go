package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
)

// windowsExtract is a literal read out of a GOOS=windows source file with
// go/parser. It is NOT executed: the production code is windows-only and the
// generator never runs on Windows. The fixture labels it accordingly.
type windowsExtract struct {
	File  string   `json:"file"`
	Kind  string   `json:"kind"`
	Name  string   `json:"name"`
	Value string   `json:"value,omitempty"`
	Argv  []string `json:"argv,omitempty"`
}

var windowsFiles = []string{
	"internal/autotype/autotype_windows.go",
	"internal/autotype/focus_windows.go",
}

func extractWindowsConstants(root string) ([]windowsExtract, error) {
	var out []windowsExtract
	for _, name := range windowsFiles {
		extracts, err := extractFile(filepath.Join(root, name), name)
		if err != nil {
			return nil, err
		}
		out = append(out, extracts...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no Windows constants extracted")
	}
	return out, nil
}

func extractFile(path, display string) ([]windowsExtract, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	consts := map[string]string{}
	var out []windowsExtract
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					return nil, err
				}
				consts[ident.Name] = value
				out = append(out, windowsExtract{File: display, Kind: "const", Name: ident.Name, Value: value})
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Command" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "exec" {
			return true
		}
		var argv []string
		for _, arg := range call.Args {
			switch v := arg.(type) {
			case *ast.BasicLit:
				s, err := strconv.Unquote(v.Value)
				if err != nil {
					return true
				}
				argv = append(argv, s)
			case *ast.Ident:
				argv = append(argv, consts[v.Name])
			}
		}
		out = append(out, windowsExtract{File: display, Kind: "exec_command", Name: "exec.Command", Argv: argv})
		return true
	})
	return out, nil
}
