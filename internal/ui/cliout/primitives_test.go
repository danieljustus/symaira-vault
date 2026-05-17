package cliout

import (
	"strings"
	"testing"
)

func TestTable_RenderBasic(t *testing.T) {
	tbl := NewTable("Path", "Tags")
	tbl.AddRow("github", "work,public")
	tbl.AddRow("aws", "work")
	out := tbl.Render()

	for _, want := range []string{"Path", "Tags", "github", "aws", "work,public"} {
		if !strings.Contains(out, want) {
			t.Errorf("Render() missing %q in:\n%s", want, out)
		}
	}
}

func TestTable_HandlesShortRows(t *testing.T) {
	tbl := NewTable("A", "B", "C")
	tbl.AddRow("x") // shorter than headers
	out := tbl.Render()
	if !strings.Contains(out, "x") {
		t.Errorf("expected 'x' in render output: %s", out)
	}
}

func TestTable_DropsExtraCells(t *testing.T) {
	tbl := NewTable("A")
	tbl.AddRow("x", "y", "z")
	out := tbl.Render()
	// Only "x" should appear because only 1 column is defined.
	if strings.Contains(out, "z") {
		t.Errorf("extra cells should be dropped, got: %s", out)
	}
}

func TestTable_Empty(t *testing.T) {
	tbl := NewTable()
	if got := tbl.Render(); got != "" {
		t.Errorf("Render() on empty table = %q, want empty", got)
	}
}

func TestTermWidthSafeFallback(t *testing.T) {
	// In tests stderr is typically not a TTY; we should get the 80-column
	// fallback rather than 0 or a negative number.
	w := TermWidth()
	if w <= 0 {
		t.Errorf("TermWidth() = %d, want > 0", w)
	}
}
