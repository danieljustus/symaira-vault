package cliout

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// TermWidth returns the width of stderr's terminal in columns. Returns 80 when
// stderr is not a TTY (so callers wrap to a sane default in CI/pipes).
func TermWidth() int {
	fd := int(os.Stderr.Fd())
	if !term.IsTerminal(fd) {
		return 80
	}
	w, _, err := term.GetSize(fd)
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// Table is a minimal-dependency ASCII table renderer. Use it from commands
// that need human-readable tabular output but don't want a heavy dependency
// (we already have charmbracelet/lipgloss but the lipgloss table API has
// non-trivial breaking changes between versions).
//
// Usage:
//
//	tbl := cliout.NewTable("Path", "Updated", "Tags")
//	for _, e := range entries {
//	    tbl.AddRow(e.Path, e.Updated, e.Tags)
//	}
//	fmt.Print(tbl.Render())
type Table struct {
	headers []string
	rows    [][]string
}

// NewTable creates a Table with the given column headers.
func NewTable(headers ...string) *Table {
	t := &Table{headers: make([]string, len(headers))}
	copy(t.headers, headers)
	return t
}

// AddRow appends a row. Cells beyond len(headers) are dropped; missing cells
// are filled with empty strings.
func (t *Table) AddRow(cells ...string) {
	row := make([]string, len(t.headers))
	for i := range row {
		if i < len(cells) {
			row[i] = cells[i]
		}
	}
	t.rows = append(t.rows, row)
}

// Render produces a stringified table sized to the current terminal width.
func (t *Table) Render() string {
	if len(t.headers) == 0 {
		return ""
	}
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = len(h)
	}
	for _, r := range t.rows {
		for i, c := range r {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}

	max := TermWidth() - len(widths) - 1
	if max > 0 {
		// Cap column widths so long values don't blow up the layout.
		colCap := max / len(widths)
		if colCap < 8 {
			colCap = 8
		}
		for i := range widths {
			if widths[i] > colCap {
				widths[i] = colCap
			}
		}
	}

	var sb strings.Builder
	writeRow(&sb, t.headers, widths)
	separator := make([]string, len(widths))
	for i, w := range widths {
		separator[i] = strings.Repeat("-", w)
	}
	writeRow(&sb, separator, widths)
	for _, r := range t.rows {
		writeRow(&sb, r, widths)
	}
	return sb.String()
}

func writeRow(sb *strings.Builder, cells []string, widths []int) {
	for i, c := range cells {
		if len(c) > widths[i] {
			c = c[:widths[i]-1] + "…"
		}
		fmt.Fprintf(sb, "%-*s", widths[i], c)
		if i < len(cells)-1 {
			sb.WriteString("  ")
		}
	}
	sb.WriteByte('\n')
}

// Pager pipes the supplied text through $PAGER (typically `less -R`) when
// stderr is a TTY and PAGER is set, otherwise writes directly to stdout.
// Errors from the pager fall through to direct print so the user always
// sees the content.
func Pager(text string) error {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		_, err := fmt.Print(text)
		return err
	}
	pager := strings.TrimSpace(os.Getenv("PAGER"))
	if pager == "" || pager == "cat" {
		_, err := fmt.Print(text)
		return err
	}
	// PAGER may include args (e.g. "less -R"); split on whitespace.
	fields := strings.Fields(pager)
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		// Fall back so the user still sees the output.
		_, perr := fmt.Print(text)
		if perr != nil {
			return perr
		}
		return err
	}
	return nil
}

// Spinner is a minimal text-only progress indicator. On a non-TTY it is a
// no-op so logs and CI output stay clean. The Stop function must be called.
// For richer progress bars use bubbles/spinner from a Bubble Tea program.
type Spinner struct {
	stopCh chan struct{}
	doneCh chan struct{}
	out    io.Writer
}

// NewSpinner returns a Spinner that writes to stderr unless stderr is not a TTY.
// In the non-TTY case the returned spinner's Start is a no-op.
func NewSpinner(label string) *Spinner {
	s := &Spinner{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
		out:    os.Stderr,
	}
	s.start(label)
	return s
}

func (s *Spinner) start(label string) {
	if !term.IsTerminal(int(os.Stderr.Fd())) {
		close(s.doneCh)
		return
	}
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	go func() {
		defer close(s.doneCh)
		i := 0
		ticker := newTicker()
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				_, _ = fmt.Fprintf(s.out, "\r%s\r", strings.Repeat(" ", len(label)+3))
				return
			case <-ticker.C:
				_, _ = fmt.Fprintf(s.out, "\r%s %s", frames[i%len(frames)], label)
				i++
			}
		}
	}()
}

// Stop ends the spinner and clears its line.
func (s *Spinner) Stop() {
	select {
	case <-s.stopCh:
		// already stopped
	default:
		close(s.stopCh)
	}
	<-s.doneCh
}
