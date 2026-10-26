package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Placeholders substituted into the fake-tool templates. The templates live in
// the fixture so the Rust replay runs byte-identical tools.
var scriptPlaceholders = []string{"@REC@", "@EXIT@", "@FOCUS1@", "@FOCUS2@", "@FOCUSEXIT@"}

// toolSpec describes how one fake tool classifies an invocation.
type toolSpec struct {
	name string
	// mode is the fixed mode, or empty when classify is used.
	mode string
	// copyFlag makes the tool a "dual" xclip/xsel style tool: it copies when
	// the flag is present among its arguments and pastes otherwise.
	copyFlag string
	// focusSub makes the tool answer `getactivewindow` as a focus probe.
	focusSub string
}

var toolSpecs = []toolSpec{
	{name: "wl-copy", mode: "copy"},
	{name: "wl-paste", mode: "paste"},
	{name: "xclip", copyFlag: "-in"},
	{name: "xsel", copyFlag: "--input"},
	{name: "termux-clipboard-set", mode: "copy"},
	{name: "termux-clipboard-get", mode: "paste"},
	{name: "clip.exe", mode: "copy"},
	{name: "powershell.exe", mode: "paste"},
	{name: "xdotool", mode: "type", focusSub: "getactivewindow"},
	{name: "wtype", mode: "type"},
	{name: "ydotool", mode: "type"},
}

func specFor(name string) (toolSpec, bool) {
	for _, spec := range toolSpecs {
		if spec.name == name {
			return spec, true
		}
	}
	return toolSpec{}, false
}

// template renders the POSIX shell body of one fake tool with the scenario
// placeholders left in place. Every invocation is logged to $REC/call.N (tool,
// mode, argc, one argument per line) and the stdin it received to
// $REC/call.N.stdin. Only /bin/cat and shell builtins are used.
func (s toolSpec) template() string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("REC='@REC@'\n")
	b.WriteString("n=$(/bin/cat \"$REC/seq\" 2>/dev/null || echo 0)\n")
	b.WriteString("n=$((n+1))\n")
	b.WriteString("echo \"$n\" > \"$REC/seq\"\n")
	switch {
	case s.copyFlag != "":
		fmt.Fprintf(&b, "mode=paste\nfor a in \"$@\"; do case \"$a\" in %s) mode=copy;; esac; done\n", s.copyFlag)
	case s.focusSub != "":
		fmt.Fprintf(&b, "mode=%s\n[ \"$1\" = %s ] && mode=focus\n", s.mode, s.focusSub)
	default:
		fmt.Fprintf(&b, "mode=%s\n", s.mode)
	}
	fmt.Fprintf(&b, "{ printf '%%s\\n' '%s' \"$mode\" \"$#\"; for a in \"$@\"; do printf '%%s\\n' \"$a\"; done; } > \"$REC/call.$n\"\n", s.name)
	b.WriteString("case \"$mode\" in\n")
	b.WriteString("copy|type) /bin/cat > \"$REC/call.$n.stdin\"; exit @EXIT@ ;;\n")
	b.WriteString("paste) /bin/cat \"$REC/paste\"; exit @EXIT@ ;;\n")
	b.WriteString("focus)\n")
	b.WriteString("  f=$(/bin/cat \"$REC/focus.n\" 2>/dev/null || echo 0)\n")
	b.WriteString("  f=$((f+1))\n")
	b.WriteString("  echo \"$f\" > \"$REC/focus.n\"\n")
	b.WriteString("  if [ \"$f\" = 1 ]; then printf '%s\\n' '@FOCUS1@'; else printf '%s\\n' '@FOCUS2@'; fi\n")
	b.WriteString("  exit @FOCUSEXIT@ ;;\n")
	b.WriteString("esac\n")
	return b.String()
}

func fakeToolTemplates() map[string]string {
	out := make(map[string]string, len(toolSpecs))
	for _, spec := range toolSpecs {
		out[spec.name] = spec.template()
	}
	return out
}

// sandbox is one disposable scenario root: a PATH directory holding only the
// requested fake tools, a record directory and a scratch HOME.
type sandbox struct {
	root string
	bin  string
	rec  string
	home string
	// cwd is the working directory scenarios run in; rel is cwd/rel. They let a
	// scenario put a tool where a relative or empty PATH entry resolves to.
	cwd string
	rel string
}

// placement says where each fake tool is installed. Tools are the absolute
// bin directory (the default); RelTools live in <cwd>/rel; CwdTools directly
// in <cwd>.
type placement struct {
	Tools    []string
	RelTools []string
	CwdTools []string
}

// pathValue renders a scenario PATH. nil means the absolute bin directory
// alone; otherwise "{bin}" is replaced by that directory.
func (sb *sandbox) pathValue(spec *string) string {
	if spec == nil {
		return sb.bin
	}
	return strings.ReplaceAll(*spec, "{bin}", sb.bin)
}

type toolParams struct {
	exit      int
	focus1    string
	focus2    string
	focusExit int
}

func newSandbox(tools []string, p toolParams, paste string) (*sandbox, error) {
	return newPlacedSandbox(placement{Tools: tools}, p, paste)
}

func newPlacedSandbox(place placement, p toolParams, paste string) (*sandbox, error) {
	root, err := os.MkdirTemp("", "desktopgen-")
	if err != nil {
		return nil, err
	}
	cwd := filepath.Join(root, "cwd")
	sb := &sandbox{root: root, bin: filepath.Join(root, "bin"), rec: filepath.Join(root, "rec"), home: filepath.Join(root, "home"), cwd: cwd, rel: filepath.Join(cwd, "rel")}
	for _, dir := range []string{sb.bin, sb.rec, sb.home, sb.cwd, sb.rel} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			_ = os.RemoveAll(root)
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(sb.rec, "paste"), []byte(paste), 0o600); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	for dir, names := range map[string][]string{sb.bin: place.Tools, sb.rel: place.RelTools, sb.cwd: place.CwdTools} {
		for _, name := range names {
			spec, ok := specFor(name)
			if !ok {
				_ = os.RemoveAll(root)
				return nil, fmt.Errorf("unknown fake tool %q", name)
			}
			body := renderTemplate(spec.template(), sb.rec, p)
			// #nosec G306 -- a fake desktop tool must be executable; it lives in a private scratch directory
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
				_ = os.RemoveAll(root)
				return nil, err
			}
		}
	}
	return sb, nil
}

func (sb *sandbox) close() { _ = os.RemoveAll(sb.root) }

func renderTemplate(tpl, rec string, p toolParams) string {
	return strings.NewReplacer(
		"@REC@", rec,
		"@EXIT@", strconv.Itoa(p.exit),
		"@FOCUS1@", p.focus1,
		"@FOCUS2@", p.focus2,
		"@FOCUSEXIT@", strconv.Itoa(p.focusExit),
	).Replace(tpl)
}

// recordedCall is one fake-tool invocation as logged by the template.
type recordedCall struct {
	Tool  string   `json:"tool"`
	Mode  string   `json:"mode"`
	Argv  []string `json:"argv"`
	Stdin string   `json:"stdin"`
}

// readCalls returns the logged invocations in execution order.
func (sb *sandbox) readCalls() ([]recordedCall, error) {
	seqRaw, err := os.ReadFile(filepath.Join(sb.rec, "seq")) // #nosec G304 -- scratch directory created by this generator
	if err != nil {
		if os.IsNotExist(err) {
			return []recordedCall{}, nil
		}
		return nil, err
	}
	total, err := strconv.Atoi(strings.TrimSpace(string(seqRaw)))
	if err != nil {
		return nil, fmt.Errorf("bad seq file: %w", err)
	}
	calls := make([]recordedCall, 0, total)
	for i := 1; i <= total; i++ {
		call, err := parseCall(filepath.Join(sb.rec, fmt.Sprintf("call.%d", i)))
		if err != nil {
			return nil, err
		}
		stdin, err := os.ReadFile(filepath.Join(sb.rec, fmt.Sprintf("call.%d.stdin", i))) // #nosec G304 -- scratch directory created by this generator
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		call.Stdin = string(stdin)
		calls = append(calls, call)
	}
	return calls, nil
}

func parseCall(path string) (recordedCall, error) {
	file, err := os.Open(path) // #nosec G304 -- scratch directory created by this generator
	if err != nil {
		return recordedCall{}, err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return recordedCall{}, scanErr
	}
	if len(lines) < 3 {
		return recordedCall{}, fmt.Errorf("short call record %s", path)
	}
	argc, err := strconv.Atoi(lines[2])
	if err != nil || len(lines) != 3+argc {
		return recordedCall{}, fmt.Errorf("malformed call record %s", path)
	}
	argv := append([]string{}, lines[3:]...)
	return recordedCall{Tool: lines[0], Mode: lines[1], Argv: argv}, nil
}
