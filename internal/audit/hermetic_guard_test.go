package audit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// skippedGuardDirs are directories the guard never descends into: version
// control internals, test fixtures, vendored JS packages, and — crucially —
// gitignored nested git worktrees (".worktrees", ".claude/worktrees") that
// routinely hold stale or in-progress checkouts of this same repository.
// Without the worktree entries, a leftover local worktree makes this guard
// fail on old source nobody can fix, since it is not the tree actually being
// built or reviewed.
var skippedGuardDirs = map[string]bool{
	".git":         true,
	"testdata":     true,
	"node_modules": true,
	".worktrees":   true,
	".claude":      true,
}

// scanForEmptyVaultDirCalls walks root (skipping skippedGuardDirs and the
// exempt directory) and returns "path:line:col" locations of every
// audit.New(..., "", ...) call site — a call whose second argument is the
// empty string literal.
func scanForEmptyVaultDirCalls(root, exempt string) ([]string, error) {
	var offenders []string
	fset := token.NewFileSet()

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedGuardDirs[d.Name()] {
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
				rel, relErr := filepath.Rel(root, path)
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
		return nil, walkErr
	}
	return offenders, nil
}

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

	offenders, err := scanForEmptyVaultDirCalls(repoRoot, exempt)
	if err != nil {
		t.Fatalf("walk repo: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("audit.New called with an empty vaultDir outside internal/audit at %d site(s):\n  %s\n\n"+
			"An empty vaultDir falls back to $HOME/.symvault and writes to the developer's real "+
			"audit log. Pass t.TempDir() in tests or the vault directory in production.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// TestScanForEmptyVaultDirCallsSkipsNestedWorktrees is the regression test
// for #837: a stale nested git worktree checked out under ".worktrees" or
// ".claude/worktrees" must never surface as an offender, since it is not the
// tree actually being built or reviewed. A genuine offender in the tracked
// tree must still be reported, so the guard keeps catching real violations.
func TestScanForEmptyVaultDirCallsSkipsNestedWorktrees(t *testing.T) {
	root := t.TempDir()

	writeGoFile(t, root, filepath.Join(".worktrees", "stale-task", "pkg", "helper_test.go"),
		`package pkg

import "github.com/danieljustus/symaira-vault/internal/audit"

func helper() { audit.New("test", "", nil) }
`)
	writeGoFile(t, root, filepath.Join(".claude", "worktrees", "stale-task", "pkg", "helper_test.go"),
		`package pkg

import "github.com/danieljustus/symaira-vault/internal/audit"

func helper() { audit.New("test", "", nil) }
`)
	writeGoFile(t, root, filepath.Join("pkg", "real_offender.go"),
		`package pkg

import "github.com/danieljustus/symaira-vault/internal/audit"

func helper() { audit.New("test", "", nil) }
`)

	offenders, err := scanForEmptyVaultDirCalls(root, "")
	if err != nil {
		t.Fatalf("scanForEmptyVaultDirCalls: %v", err)
	}

	if len(offenders) != 1 {
		t.Fatalf("offenders = %v, want exactly 1 (the tracked-tree offender, not the worktree copies)", offenders)
	}
	if !strings.HasPrefix(offenders[0], filepath.Join("pkg", "real_offender.go")+":") {
		t.Errorf("offenders[0] = %q, want it to point at pkg/real_offender.go", offenders[0])
	}
}

func writeGoFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
