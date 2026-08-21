package audit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoEmptyVaultDirOutsideAuditPackage guards against a whole class of
// test pollution: audit.New falls back to $HOME/.symvault when vaultDir is
// empty, so any caller passing "" that does not also redirect HOME appends
// to the developer's real audit log. That is how internal/mcp/server's
// newTestServer helper silently grew ~/.symvault/audit-test.log to 132k
// lines across 52 call sites.
//
// The audit package's own tests use the fallback deliberately and always
// pair it with t.Setenv("HOME", ...), so they are exempt. Everywhere else,
// pass a real directory (t.TempDir() in tests, the vault dir in production).
func TestNoEmptyVaultDirOutsideAuditPackage(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	// The audit package owns the fallback and tests it directly.
	exempt := filepath.Join(repoRoot, "internal", "audit")

	var offenders []string
	fset := token.NewFileSet()

	walkErr := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "testdata" || base == "node_modules" {
				return filepath.SkipDir
			}
			if path == exempt {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			// Unparseable files are the compiler's problem, not this guard's.
			return nil //nolint:nilerr // deliberate: skip, do not fail the guard
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "New" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "audit" {
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if lit.Value == `""` {
				rel, relErr := filepath.Rel(repoRoot, path)
				if relErr != nil {
					rel = path
				}
				offenders = append(offenders, rel+":"+
					fset.Position(call.Pos()).String()[len(fset.Position(call.Pos()).Filename)+1:])
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk repo: %v", walkErr)
	}

	if len(offenders) > 0 {
		t.Errorf("audit.New called with an empty vaultDir outside internal/audit at %d site(s):\n  %s\n\n"+
			"An empty vaultDir falls back to $HOME/.symvault and writes to the developer's real "+
			"audit log. Pass t.TempDir() in tests or the vault directory in production.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}
