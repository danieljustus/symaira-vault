// Command outputmodegen freezes the pinned Go CLI's ACCEPTED output for every
// command path whose output-format gate lets `--json` and/or `--output`
// through (CLI-006, positive side). The refusal side of the gate is pinned
// separately by errtaxgen (testdata/port/cli/error-taxonomy.json `gate`).
//
// For each accepting path the generator runs one or more scenarios against the
// pinned Go binary and records stdout, stderr, exit status and the file-system
// side effects of the plain text rendering, `--json`, `--output yaml`,
// `--output json` and `--quiet`. Only the modes the gate accepts for that path
// are run: a refused mode is already a byte-compared refusal in errtaxgen.
//
// Every scenario runs in its own disposable HOME/XDG/cwd sandbox. The starting
// vault of a scenario is a frozen seed: a tree built once by the oracle from a
// recorded command list (`init`, `add`, ...) and stored in the fixture, so the
// age identity, entry timestamps and audit lines are deterministic and the
// native replay needs no Go toolchain and no secret randomness.
//
// Documented normalization. This is the ONE numbered list: the same ids, in the
// same order, are generated into the fixture notes from normalizationRules, listed
// in the header of crates/symvault-cli/tests/output_modes.rs and implemented by
// its replay; that test fails when any of the four disagrees. Anything not
// listed here stays a byte-for-byte difference.
//
//  1. `root`: the sandbox root and its symlink-resolved form become "$ROOT" in
//     stdout, stderr, tree paths, observed text files, archive members and the
//     text files of a seed (re-expanded when the seed is materialised).
//  2. `bin`: the absolute path of the executed binary (and its symlink-resolved
//     form) becomes "$BIN" (update apply/info print the running executable).
//  3. `dated-id`: "<prefix>-YYYYMMDD-<8 lowercase hex>" for the prefixes tok,
//     intake and import, with a valid calendar date, becomes
//     "<prefix>-<DATE>-<RAND>".
//  4. `tmp-suffix`: a failed write's temporary suffix ".age.tmp-<digits>" becomes
//     ".age.tmp-<N>".
//  5. `touch-id`: "Touch ID available: true|false" and
//     "\"touchIDAvailable\":true|false" of `auth status` become "<BOOL>": the
//     value depends on the Mac's sensor, not on the command. On darwin the Rust
//     replay also compares the live Go and Rust values in the same sandbox
//     (SYMVAULT_OUTPUT_MODES_GO_BINARY), so a wrong probe is not hidden.
//  6. `gen-pw`: a case that declares `gen-pw:N` must print exactly one run of N
//     characters from [A-Za-z0-9] delimited by a line boundary, space or quote;
//     it becomes "<PW>". The shape is verified by the generator, so a command
//     that stops generating is a failure, not a pass.
//  7. `pair-token`: a case that declares it has its 32-character upper-case
//     base32 token (and the 6-character prefix repeated in the join
//     instructions) replaced by "<TOKEN>"/"<TOKEN6>".
//  8. `now-ts`: a case that declares it has every RFC 3339 timestamp within one
//     hour of the run replaced by "<NOW>"; timestamps frozen in a seed are far
//     from it and stay visible. It does not pin the fractional-second spelling
//     of a run-time stamp.
//  9. `man-date`: a case that declares it has the date field of a roff `.TH`
//     header ("Nov 2026", the month of the run) replaced by "<MAN-DATE>".
//  10. `opaque`: a case that declares path prefixes has those tree paths recorded
//     by presence only (their bytes are random or clock values: the invitation
//     file of `device pair`, the token store `doctor` creates).
//  11. `encrypted-store`: the vault's encrypted store (entries, manifest,
//     identity, lock, search index, .git) is not part of the tree diff: its
//     bytes carry fresh randomness. `post` commands pin the resulting vault.
//  12. `audit-fields`: an audit log (audit-*.log) is recorded as the decoded
//     stable fields of every line (agent, action, path, field, ok, argv_hash
//     length, signed), never as bytes: ts, kid, hmac and the hash are volatile.
//  13. `archive-members`: a case that declares `archives` path prefixes has every
//     file below them decoded as .tar.gz and recorded as its members (name,
//     type, mode, sha256 of the normalized content), sorted by name because Go
//     writes them in map iteration order; header times, owners and the
//     compression bytes are not compared.
//  14. `managed-fields`: inside an archive member, a line "managed_hash:
//     sha256:<64 hex>" has its digits replaced by "<HASH>" (the digest of a body
//     that embeds the install clock) and a line `managed_installed_at:
//     "<RFC 3339 UTC>"` its stamp by "<NOW>"; both are install-time values.
//
// Every tree entry also records the permission bits of files and directories
// (`mode`, compared as is); a file the case made unreadable (mode 000) has no
// content to hash and is recorded by kind and mode only. The generator and the
// replay both execute the binary under umask 022 so the bits do not depend on the
// invoking shell.
//
// Sandbox: TZ=UTC, NO_COLOR=1, CI=1, SYMVAULT_PASSPHRASE with
// SYMVAULT_ALLOW_ENV_PASSPHRASE=1, stdin is /dev/null unless a case supplies
// text. The `$ROOT`-relative file tree after a case is recorded for every path
// outside the encrypted store (rule 11) as path + kind + mode + sha256 of the
// normalized text (or the audit fields / archive members of rules 12 and 13).
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleRelease = "unreleased"
	defaultOutput       = "testdata/port/cli/output-modes.json"
	gateFixture         = "testdata/port/cli/error-taxonomy.json"
	commandTimeout      = 60 * time.Second
	passphrase          = "correct horse battery staple"
	rootMarker          = "$ROOT"
	binMarker           = "$BIN"
)

// pinnedOracleCommit is only reassigned by tests that run main against a
// disposable repository.
var pinnedOracleCommit = "bf7f687bb8f57316e8333965635e733b8f567c72"

var (
	exit           = os.Exit
	validateOracle = validateGoBinary
	locateRoot     = repositoryRoot
)

// generatorFiles are digested separately from the production sources so a
// harness change forces a deliberate regeneration without relabeling the
// oracle.
var generatorFiles = []string{
	"scripts/rust-port/check_output_modes_cli.sh",
	"scripts/rust-port/cmd/outputmodegen/cases.go",
	"scripts/rust-port/cmd/outputmodegen/main.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	GoVersion       string   `json:"go_version"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
	GateDigest      string   `json:"gate_digest"`
	// GOOS is the platform the corpus was recorded on: doctor probes the host
	// (osascript, pbcopy) and several commands print platform paths, so the
	// replay only compares on the recording platform.
	GOOS string `json:"goos"`
}

// fileNode is one entry of a frozen seed tree or of an observed tree.
type fileNode struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	Mode uint32 `json:"mode,omitempty"`
	Data string `json:"data,omitempty"`
	B64  string `json:"b64,omitempty"`
}

// seedStep is one oracle command (or file copy) that builds a frozen seed.
type seedStep struct {
	Argv     []string `json:"argv,omitempty"`
	CopyFrom string   `json:"copy_from,omitempty"`
	CopyTo   string   `json:"copy_to,omitempty"`
	WriteTo  string   `json:"write_to,omitempty"`
	Text     string   `json:"text,omitempty"`
	Env      []string `json:"env,omitempty"`
}

type seedResult struct {
	Name  string     `json:"name"`
	Steps []seedStep `json:"steps"`
	Files []fileNode `json:"files"`
}

// workFile is an extra file placed in the sandbox working directory.
type workFile struct {
	Name string `json:"name"`
	Text string `json:"text,omitempty"`
	Mode string `json:"mode,omitempty"`
	Dir  bool   `json:"dir,omitempty"`
}

type step struct {
	Argv   []string `json:"argv"`
	Exit   int      `json:"exit"`
	Stdout string   `json:"stdout"`
}

type treeEntry struct {
	Path   string `json:"path"`
	Change string `json:"change"` // added | removed | changed
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256,omitempty"`
	// Mode is the permission bits of a file or directory (zero for a symlink).
	Mode uint32 `json:"mode,omitempty"`
	// Members is the decoded content of a case-declared archive.
	Members []archiveMember `json:"members,omitempty"`
	// Audit is the decoded stable fields of every line of a presence-only audit
	// log (the bytes carry clock values and HMACs, the fields below do not).
	Audit []auditLine `json:"audit,omitempty"`
}

// archiveMember is one entry of a case-declared .tar.gz: its name, tar type
// flag, permission bits and the sha256 of the normalized content (regular files
// only). Header times, owners and the compression bytes are volatile.
type archiveMember struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Mode   int64  `json:"mode"`
	SHA256 string `json:"sha256,omitempty"`
}

// auditLine is the stable part of one audit log line: who (agent, which Go
// leaves empty for the CLI's own records), what, on which path and field, the
// outcome, and the SHAPE of the volatile parts (argv_hash length, whether the
// line is signed). ts, kid, hmac and the hash itself are never recorded.
type auditLine struct {
	Agent       string `json:"agent"`
	Action      string `json:"action"`
	Path        string `json:"path,omitempty"`
	Field       string `json:"field,omitempty"`
	OK          bool   `json:"ok"`
	ArgvHashLen int    `json:"argv_hash_len"`
	Signed      bool   `json:"signed"`
}

// isArchive reports a path below a case-declared archive prefix (rule 13).
func (s *sandbox) isArchive(rel string) bool {
	for _, prefix := range s.archives {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

// decodeArchive lists a gzip-compressed tar with the sha256 of every regular
// member's normalized content.
func (s *sandbox) decodeArchive(data []byte) ([]archiveMember, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	reader := tar.NewReader(gz)
	members := []archiveMember{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			sort.Slice(members, func(i, j int) bool { return members[i].Name < members[j].Name })
			return members, nil
		}
		if err != nil {
			return nil, err
		}
		member := archiveMember{Name: header.Name, Type: string(rune(header.Typeflag)), Mode: header.Mode}
		if header.Typeflag == tar.TypeReg {
			content, err := io.ReadAll(reader)
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256([]byte(normalizeManagedFields(s.normalize(string(content)))))
			member.SHA256 = hex.EncodeToString(sum[:])
		}
		members = append(members, member)
	}
}

// normalizeManagedFields is rule 14: the two install-time lines of a managed
// skill file, matched at the start of a line with exactly the recorded shape.
func normalizeManagedFields(text string) string {
	const (
		hashPrefix  = "managed_hash: sha256:"
		stampPrefix = `managed_installed_at: "`
	)
	lines := strings.SplitAfter(text, "\n")
	for i, line := range lines {
		body := strings.TrimSuffix(line, "\n")
		ending := line[len(body):]
		switch {
		case strings.HasPrefix(body, hashPrefix):
			if digits := strings.TrimPrefix(body, hashPrefix); len(digits) == 64 && allLowerHex(digits) {
				lines[i] = hashPrefix + "<HASH>" + ending
			}
		case strings.HasPrefix(body, stampPrefix) && strings.HasSuffix(body, `"`):
			stamp := strings.TrimSuffix(strings.TrimPrefix(body, stampPrefix), `"`)
			if parsed, err := time.Parse(time.RFC3339, stamp); err == nil && parsed.UTC().Format(time.RFC3339) == stamp {
				lines[i] = stampPrefix + "<NOW>\"" + ending
			}
		}
	}
	return strings.Join(lines, "")
}

// decodeAuditLines parses a presence-only audit log into its stable fields. A
// line that is not a JSON object is an error: dropping it would hide a diff.
func decodeAuditLines(data []byte) ([]auditLine, error) {
	var lines []auditLine
	for _, raw := range strings.Split(string(data), "\n") {
		if raw == "" {
			continue
		}
		var entry struct {
			Agent    string `json:"agent"`
			Action   string `json:"action"`
			Path     string `json:"path"`
			Field    string `json:"field"`
			OK       bool   `json:"ok"`
			ArgvHash string `json:"argv_hash"`
			KID      string `json:"kid"`
			HMAC     string `json:"hmac"`
		}
		if err := json.Unmarshal([]byte(raw), &entry); err != nil {
			return nil, fmt.Errorf("audit line %q: %w", raw, err)
		}
		lines = append(lines, auditLine{
			Agent: entry.Agent, Action: entry.Action, Path: entry.Path, Field: entry.Field, OK: entry.OK,
			ArgvHashLen: len(entry.ArgvHash), Signed: entry.KID != "" && entry.HMAC != "",
		})
	}
	return lines, nil
}

type caseResult struct {
	ID       string            `json:"id"`
	Path     string            `json:"path"`
	Scenario string            `json:"scenario"`
	Mode     string            `json:"mode"`
	Desc     string            `json:"desc"`
	Seed     string            `json:"seed"`
	Env      map[string]string `json:"env,omitempty"`
	Stdin    string            `json:"stdin,omitempty"`
	Files    []workFile        `json:"files,omitempty"`
	Rules    []string          `json:"rules,omitempty"`
	Opaque   []string          `json:"opaque,omitempty"`
	Archives []string          `json:"archives,omitempty"`
	Argv     []string          `json:"argv"`
	Exit     int               `json:"exit"`
	Stdout   string            `json:"stdout"`
	Stderr   string            `json:"stderr"`
	// StdoutB64/StderrB64 hold the exact normalized bytes when they are not
	// valid UTF-8 (Stdout/Stderr then carry U+FFFD for readers only).
	StdoutB64 string      `json:"stdout_b64,omitempty"`
	StderrB64 string      `json:"stderr_b64,omitempty"`
	Tree      []treeEntry `json:"tree"`
	Post      []step      `json:"post,omitempty"`
}

// residual records a path (or one of its modes) the matrix cannot pin
// byte-for-byte, with the reason and the partial case that is pinned instead.
type residual struct {
	Path    string `json:"path"`
	Reason  string `json:"reason"`
	Partial string `json:"partial"`
}

type fixture struct {
	SchemaVersion int          `json:"schema_version"`
	Oracle        oracle       `json:"oracle"`
	Notes         []string     `json:"notes"`
	Seeds         []seedResult `json:"seeds"`
	Residuals     []residual   `json:"residuals"`
	Cases         []caseResult `json:"cases"`
}

// gateRow is the part of error-taxonomy.json `gate` this generator needs.
type gateRow struct {
	Path          string `json:"path"`
	JSONRefused   bool   `json:"json_refused"`
	OutputRefused bool   `json:"output_refused"`
}

type sandbox struct {
	root, home, work, vault, bin string
	// archives are the root-relative path prefixes of the running case whose
	// files are decoded as .tar.gz (rule 13).
	archives []string
}

func newSandbox(bin string) (*sandbox, error) {
	root, err := os.MkdirTemp("", "outputmodegen-")
	if err != nil {
		return nil, err
	}
	box := &sandbox{
		root: root, home: filepath.Join(root, "home"), work: filepath.Join(root, "work"),
		vault: filepath.Join(root, "home", "vault"), bin: bin,
	}
	for _, dir := range []string{box.home, box.work} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			_ = os.RemoveAll(root)
			return nil, err
		}
	}
	return box, nil
}

func (s *sandbox) remove() {
	_ = filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, err error) error {
		if err == nil {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(s.root)
}

func (s *sandbox) env(extra map[string]string) []string {
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + s.home,
		"USERPROFILE=" + s.home,
		"XDG_CONFIG_HOME=" + filepath.Join(s.root, "xdg-config"),
		"XDG_DATA_HOME=" + filepath.Join(s.root, "xdg-data"),
		"XDG_CACHE_HOME=" + filepath.Join(s.root, "xdg-cache"),
		"TMPDIR=" + s.root,
		"TZ=UTC",
		"SYMVAULT_VAULT=" + s.vault,
		"SYMVAULT_PASSPHRASE=" + passphrase,
		"SYMVAULT_ALLOW_ENV_PASSPHRASE=1",
		"CI=1",
		"NO_COLOR=1",
	}
	keys := make([]string, 0, len(extra))
	for key := range extra {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+strings.ReplaceAll(extra[key], rootMarker, s.root))
	}
	return env
}

// expand re-expands $ROOT in an argv element, so a case can name sandbox paths.
func (s *sandbox) expand(args []string) []string {
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = strings.ReplaceAll(arg, rootMarker, s.root)
	}
	return out
}

type observed struct {
	exit           int
	stdout, stderr string
}

func (s *sandbox) run(args []string, extraEnv map[string]string, stdin string) (observed, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	// #nosec G204 -- validateGoBinary checked the pinned, clean oracle before this command.
	// The binary runs under umask 022 (exec replaces the shell) so the recorded
	// permission bits do not depend on the invoking shell.
	cmd := exec.CommandContext(ctx, "/bin/sh", append([]string{"-c", `umask 022; exec "$0" "$@"`, s.bin}, s.expand(args)...)...)
	cmd.Dir = s.work
	cmd.Env = s.env(extraEnv)
	cmd.WaitDelay = time.Second
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	out := observed{}
	if ctx.Err() != nil {
		return out, fmt.Errorf("%v timed out", args)
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return out, runErr
		}
		out.exit = exitErr.ExitCode()
	}
	// Output is kept as raw bytes: yaml.v3 cuts a value at seven BYTES, so an
	// error line can end inside a UTF-8 sequence. runCase records such text
	// exactly (stdout_b64/stderr_b64) next to a lossy readable rendering.
	out.stdout, out.stderr = stdout.String(), stderr.String()
	return out, nil
}

// rootForms are the textual forms of the sandbox root (symlink-resolved first).
func (s *sandbox) rootForms() []string {
	forms := []string{s.root}
	if resolved, err := filepath.EvalSymlinks(s.root); err == nil && resolved != s.root {
		forms = []string{resolved, s.root}
	}
	return forms
}

func (s *sandbox) binForms() []string {
	forms := []string{s.bin}
	if resolved, err := filepath.EvalSymlinks(s.bin); err == nil && resolved != s.bin {
		forms = []string{resolved, s.bin}
	}
	return forms
}

// normalize applies rules 1, 2, 3 and 6.
func (s *sandbox) normalize(text string) string {
	for _, form := range s.binForms() {
		text = strings.ReplaceAll(text, form, binMarker)
	}
	for _, form := range s.rootForms() {
		text = strings.ReplaceAll(text, form, rootMarker)
	}
	text = normalizeTempSuffixes(text)
	return normalizeTouchID(normalizeDatedIDs(text))
}

// touchIDForms are the two spellings in which `auth status` reports the
// hardware probe (rule 7).
var touchIDForms = []string{"Touch ID available: ", `"touchIDAvailable":`}

// normalizeTouchID is rule 7: whether this Mac offers Touch ID is a hardware
// probe, not command behavior, so its boolean becomes "<BOOL>".
func normalizeTouchID(text string) string {
	for _, form := range touchIDForms {
		for _, value := range []string{"true", "false"} {
			text = strings.ReplaceAll(text, form+value, form+"<BOOL>")
		}
	}
	return text
}

// normalizeTempSuffixes is rule 6.
func normalizeTempSuffixes(text string) string {
	const mark = ".age.tmp-"
	var out strings.Builder
	for i := 0; i < len(text); {
		if strings.HasPrefix(text[i:], mark) {
			j := i + len(mark)
			for j < len(text) && text[j] >= '0' && text[j] <= '9' {
				j++
			}
			if j > i+len(mark) {
				out.WriteString(".age.tmp-<N>")
				i = j
				continue
			}
		}
		out.WriteByte(text[i])
		i++
	}
	return out.String()
}

var datedIDPrefixes = []string{"tok", "intake", "import"}

// normalizeDatedIDs is rule 3: prefix-YYYYMMDD-8hex with a valid date.
func normalizeDatedIDs(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); {
		replaced := false
		for _, prefix := range datedIDPrefixes {
			head := prefix + "-"
			if !strings.HasPrefix(text[i:], head) {
				continue
			}
			rest := text[i+len(head):]
			if len(rest) < 17 || !allDigits(rest[:8]) || rest[8] != '-' || !allLowerHex(rest[9:17]) {
				continue
			}
			if _, err := time.Parse("20060102", rest[:8]); err != nil {
				continue
			}
			out.WriteString(prefix + "-<DATE>-<RAND>")
			i += len(head) + 17
			replaced = true
			break
		}
		if !replaced {
			out.WriteByte(text[i])
			i++
		}
	}
	return out.String()
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func allLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// volatile applies the declared per-case rules (4, 5 and the timestamp rule 7)
// to every observed text. The pairing token is discovered in stdout and then
// replaced everywhere (stderr, tree paths, observed file contents).
type volatile struct {
	rules  []string
	opaque []string
	token  string
	now    time.Time
}

// isOpaque reports a tree path recorded by presence only (case-declared).
func (v *volatile) isOpaque(path string) bool {
	for _, prefix := range v.opaque {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func (v *volatile) has(rule string) bool {
	for _, r := range v.rules {
		if r == rule {
			return true
		}
	}
	return false
}

// discover verifies the declared shapes on stdout (a command that stops
// generating a password or token is a failure, not a pass) and rewrites it.
func (v *volatile) discover(stdout string) (string, error) {
	for _, rule := range v.rules {
		switch {
		case strings.HasPrefix(rule, "gen-pw:"):
			var length int
			if _, err := fmt.Sscanf(rule, "gen-pw:%d", &length); err != nil || length < 1 {
				return "", fmt.Errorf("bad rule %q", rule)
			}
			out, err := replaceGeneratedPassword(stdout, length)
			if err != nil {
				return "", err
			}
			stdout = out
		case rule == "pair-token":
			if stdout == "" {
				// --quiet prints nothing: there is no token to find.
				continue
			}
			token, err := findPairToken(stdout)
			if err != nil {
				return "", err
			}
			v.token = token
		case rule == "now-ts", rule == "man-date":
		default:
			return "", fmt.Errorf("unknown rule %q", rule)
		}
	}
	return v.apply(stdout), nil
}

// apply rewrites the pairing token (rule 5) and wall-clock timestamps (rule 7).
func (v *volatile) apply(text string) string {
	if v.token != "" {
		text = strings.ReplaceAll(text, v.token, "<TOKEN>")
		text = strings.ReplaceAll(text, v.token[:6], "<TOKEN6>")
	}
	if v.has("now-ts") {
		text = replaceNowTimestamps(text, v.now)
	}
	if v.has("man-date") {
		text = replaceManDate(text)
	}
	return text
}

// replaceManDate is rule 9: the date field of a roff `.TH` header ("Nov 2026")
// is the month of the run, so it becomes "<MAN-DATE>". Only the fourth quoted
// field of a line starting with `.TH ` and shaped like `Mon YYYY` is touched.
func replaceManDate(text string) string {
	lines := strings.SplitAfter(text, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, ".TH ") {
			continue
		}
		parts := strings.Split(line, `"`)
		// .TH "NAME" "1" "Nov 2026" "source" "manual": the date is parts[5].
		if len(parts) > 5 && manDateShape(parts[5]) {
			parts[5] = "<MAN-DATE>"
			lines[i] = strings.Join(parts, `"`)
		}
	}
	return strings.Join(lines, "")
}

// manDateShape reports "Mon YYYY": a capitalized three-letter month and a
// four-digit year.
func manDateShape(field string) bool {
	return len(field) == 8 && field[0] >= 'A' && field[0] <= 'Z' && field[1] >= 'a' && field[1] <= 'z' &&
		field[2] >= 'a' && field[2] <= 'z' && field[3] == ' ' && allDigits(field[4:])
}

func isPWBoundaryBefore(b byte) bool { return b == '\n' || b == ' ' || b == '"' }
func isPWBoundaryAfter(b byte) bool  { return b == '\n' || b == '"' || b == ' ' }

// replaceGeneratedPassword is rule 4. Exactly one delimited run of `length`
// alphanumerics must exist.
func replaceGeneratedPassword(text string, length int) (string, error) {
	found := -1
	for i := 0; i+length <= len(text); i++ {
		if i > 0 && !isPWBoundaryBefore(text[i-1]) {
			continue
		}
		if i+length < len(text) && !isPWBoundaryAfter(text[i+length]) {
			continue
		}
		ok := true
		for j := i; j < i+length; j++ {
			if !isAlnum(text[j]) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if found >= 0 {
			return "", fmt.Errorf("gen-pw:%d is ambiguous in %q", length, text)
		}
		found = i
	}
	if found < 0 {
		return "", fmt.Errorf("gen-pw:%d: no generated password in %q", length, text)
	}
	return text[:found] + "<PW>" + text[found+length:], nil
}

func isBase32Upper(b byte) bool { return b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' }

// findPairToken is rule 5: the "Token: " line carries a 32-character base32
// token.
func findPairToken(text string) (string, error) {
	const head = "Token: "
	idx := strings.Index(text, head)
	if idx < 0 {
		return "", fmt.Errorf("pair-token: no %q line in %q", head, text)
	}
	start := idx + len(head)
	if start+32 > len(text) {
		return "", fmt.Errorf("pair-token: short token in %q", text)
	}
	token := text[start : start+32]
	for i := 0; i < len(token); i++ {
		if !isBase32Upper(token[i]) {
			return "", fmt.Errorf("pair-token: %q is not upper-case alphanumeric", token)
		}
	}
	return token, nil
}

// pairTokenFromTree finds the invitation artifact name when stdout (--quiet)
// does not carry the token.
func pairTokenFromTree(after map[string]treeNode) string {
	const dir, ext = "home/vault/.symvault/pairing/", ".json"
	for path := range after {
		if strings.HasPrefix(path, dir) && strings.HasSuffix(path, ext) && len(path) == len(dir)+32+len(ext) {
			return path[len(dir) : len(dir)+32]
		}
	}
	return ""
}

// scanTimestamp returns the length of an RFC 3339 timestamp at the start of s
// (YYYY-MM-DDTHH:MM:SS, optional .fraction, then Z or +-HH:MM), or 0.
func scanTimestamp(s string) int {
	if len(s) < 20 || !allDigits(s[0:4]) || s[4] != '-' || !allDigits(s[5:7]) || s[7] != '-' ||
		!allDigits(s[8:10]) || s[10] != 'T' || !allDigits(s[11:13]) || s[13] != ':' ||
		!allDigits(s[14:16]) || s[16] != ':' || !allDigits(s[17:19]) {
		return 0
	}
	n := 19
	if n < len(s) && s[n] == '.' {
		m := n + 1
		for m < len(s) && s[m] >= '0' && s[m] <= '9' {
			m++
		}
		if m == n+1 {
			return 0
		}
		n = m
	}
	switch {
	case n < len(s) && s[n] == 'Z':
		return n + 1
	case n+6 <= len(s) && (s[n] == '+' || s[n] == '-') && allDigits(s[n+1:n+3]) && s[n+3] == ':' && allDigits(s[n+4:n+6]):
		return n + 6
	}
	return 0
}

// replaceNowTimestamps is rule 7: an RFC 3339 timestamp within one hour of the
// run becomes <NOW>. Timestamps frozen in a seed are far from it and stay.
func replaceNowTimestamps(text string, now time.Time) string {
	var out strings.Builder
	for i := 0; i < len(text); {
		if n := scanTimestamp(text[i:]); n > 0 {
			if ts, err := time.Parse(time.RFC3339Nano, text[i:i+n]); err == nil {
				if d := ts.Sub(now); d > -time.Hour && d < time.Hour {
					out.WriteString("<NOW>")
					i += n
					continue
				}
			}
		}
		out.WriteByte(text[i])
		i++
	}
	return out.String()
}

// --- trees -----------------------------------------------------------------

// encryptedStore reports whether a root-relative path belongs to the vault's
// encrypted store, whose bytes carry fresh randomness on every write.
func encryptedStore(rel string) bool {
	const prefix = "home/vault/"
	if !strings.HasPrefix(rel, prefix) {
		return false
	}
	rest := strings.TrimPrefix(rel, prefix)
	return rest == ".lock" || rest == "identity.age" || rest == "manifest.age" || rest == ".search-index" ||
		rest == "entries" || strings.HasPrefix(rest, "entries/") ||
		rest == ".git" || strings.HasPrefix(rest, ".git/")
}

// presenceOnly reports files whose bytes carry per-run randomness or clock
// values (audit lines with timestamps and HMACs): only their existence is
// observed.
func presenceOnly(rel string) bool {
	base := rel[strings.LastIndex(rel, "/")+1:]
	return strings.HasPrefix(base, "audit-") && strings.HasSuffix(base, ".log")
}

type treeNode struct {
	kind    string
	content string
	hasData bool
	// audit is the canonical JSON of the decoded lines of an audit log.
	audit string
	// members is the canonical JSON of a decoded archive.
	members string
	// mode is the permission bits of a file or directory.
	mode uint32
}

// snapshot walks the sandbox root (not the work/bin or sysbin plumbing) and
// records every observable path for the tree diff.
func (s *sandbox) snapshot() (map[string]treeNode, error) {
	out := map[string]treeNode{}
	err := filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		node := treeNode{kind: "file"}
		if info, err := entry.Info(); err == nil && entry.Type()&fs.ModeSymlink == 0 {
			node.mode = uint32(info.Mode().Perm())
		}
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			node.kind = "symlink"
		case entry.IsDir():
			node.kind = "dir"
		default:
			if encryptedStore(rel) || strings.HasSuffix(rel, ".age") {
				break
			}
			data, err := os.ReadFile(path) // #nosec G304 -- sandbox path
			if errors.Is(err, fs.ErrPermission) {
				break // a file the case made unreadable: kind and mode only
			}
			if err != nil {
				return err
			}
			if s.isArchive(rel) {
				members, err := s.decodeArchive(data)
				if err != nil {
					return fmt.Errorf("%s: %w", rel, err)
				}
				encoded, err := json.Marshal(members)
				if err != nil {
					return err
				}
				node.members = string(encoded)
				break
			}
			if presenceOnly(rel) {
				lines, err := decodeAuditLines(data)
				if err != nil {
					return fmt.Errorf("%s: %w", rel, err)
				}
				encoded, err := json.Marshal(lines)
				if err != nil {
					return err
				}
				node.audit = string(encoded)
				break
			}
			node.content, node.hasData = s.normalize(string(data)), true
		}
		out[rel] = node
		return nil
	})
	return out, err
}

func diffTrees(before, after map[string]treeNode, v *volatile) []treeEntry {
	var out []treeEntry
	for path, node := range after {
		old, existed := before[path]
		sha := ""
		if node.hasData && !v.isOpaque(path) {
			sum := sha256.Sum256([]byte(v.apply(node.content)))
			sha = hex.EncodeToString(sum[:])
		}
		var lines []auditLine
		if node.audit != "" {
			if err := json.Unmarshal([]byte(node.audit), &lines); err != nil {
				panic(err) // node.audit was produced by json.Marshal above
			}
		}
		var members []archiveMember
		if node.members != "" {
			if err := json.Unmarshal([]byte(node.members), &members); err != nil {
				panic(err) // node.members was produced by json.Marshal above
			}
		}
		entry := treeEntry{Path: v.apply(path), Kind: node.kind, SHA256: sha, Mode: node.mode, Members: members, Audit: lines}
		switch {
		case !existed:
			entry.Change = "added"
			out = append(out, entry)
		case old != node:
			entry.Change = "changed"
			out = append(out, entry)
		}
	}
	for path, node := range before {
		if _, ok := after[path]; !ok {
			out = append(out, treeEntry{Path: v.apply(path), Change: "removed", Kind: node.kind, Mode: node.mode})
		}
	}
	// The encrypted store and the work/bin plumbing are not observed.
	filtered := out[:0]
	for _, entry := range out {
		if encryptedStore(entry.Path) {
			continue
		}
		filtered = append(filtered, entry)
	}
	_ = filtered
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Path < filtered[j].Path })
	if filtered == nil {
		filtered = []treeEntry{}
	}
	return filtered
}

// --- seeds -----------------------------------------------------------------

func setData(node *fileNode, data []byte) {
	if utf8.Valid(data) && !bytes.ContainsAny(data, "\x00") {
		node.Data = string(data)
		return
	}
	node.B64 = base64.StdEncoding.EncodeToString(data)
}

func nodeBytes(node fileNode) ([]byte, error) {
	if node.B64 != "" {
		return base64.StdEncoding.DecodeString(node.B64)
	}
	return []byte(node.Data), nil
}

// collectSeed records the whole sandbox root except the work directory, with
// every root occurrence in text files replaced by $ROOT.
func (s *sandbox) collectSeed() ([]fileNode, error) {
	var nodes []fileNode
	err := filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || rel == "work" || strings.HasPrefix(rel, "work/") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		node := fileNode{Path: rel, Mode: uint32(info.Mode().Perm())}
		switch {
		case info.IsDir():
			node.Kind = "dir"
		case info.Mode().IsRegular():
			node.Kind = "file"
			data, err := os.ReadFile(path) // #nosec G304 -- sandbox path
			if err != nil {
				return err
			}
			if utf8.Valid(data) && !bytes.ContainsAny(data, "\x00") {
				for _, form := range s.rootForms() {
					data = bytes.ReplaceAll(data, []byte(form), []byte(rootMarker))
				}
			}
			setData(&node, data)
		default:
			return fmt.Errorf("seed contains unsupported file %s (%v)", path, info.Mode())
		}
		nodes = append(nodes, node)
		return nil
	})
	return nodes, err
}

// materialize writes a frozen seed under the sandbox root.
func (s *sandbox) materialize(nodes []fileNode) error {
	for _, node := range nodes {
		target := filepath.Join(s.root, filepath.FromSlash(node.Path))
		if node.Kind == "dir" {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		data, err := nodeBytes(node)
		if err != nil {
			return err
		}
		if node.B64 == "" {
			data = []byte(strings.ReplaceAll(string(data), rootMarker, s.root))
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return err
		}
	}
	// Modes last (parents were created 0700, read-only git objects must be
	// writable while the tree is built).
	for i := len(nodes) - 1; i >= 0; i-- {
		node := nodes[i]
		if err := os.Chmod(filepath.Join(s.root, filepath.FromSlash(node.Path)), os.FileMode(node.Mode)); err != nil {
			return err
		}
	}
	return nil
}

func (s *sandbox) materializeFiles(files []workFile) error {
	for _, file := range files {
		target := filepath.Join(s.work, filepath.FromSlash(file.Name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if file.Dir {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		mode := os.FileMode(0o600)
		if file.Mode != "" {
			var parsed uint32
			if _, err := fmt.Sscanf(file.Mode, "%o", &parsed); err != nil {
				return fmt.Errorf("file %s: bad mode %q", file.Name, file.Mode)
			}
			mode = os.FileMode(parsed)
		}
		if err := os.WriteFile(target, []byte(strings.ReplaceAll(file.Text, rootMarker, s.root)), 0o600); err != nil {
			return err
		}
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
	}
	return nil
}

func buildSeed(goBinary, name string, steps []seedStep) (seedResult, error) {
	box, err := newSandbox(goBinary)
	if err != nil {
		return seedResult{}, err
	}
	defer box.remove()
	for _, st := range steps {
		if st.WriteTo != "" {
			target := filepath.Join(box.root, filepath.FromSlash(st.WriteTo))
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return seedResult{}, err
			}
			if err := os.WriteFile(target, []byte(st.Text), 0o600); err != nil {
				return seedResult{}, err
			}
			continue
		}
		if st.CopyFrom != "" {
			data, err := os.ReadFile(filepath.Join(box.root, filepath.FromSlash(st.CopyFrom))) // #nosec G304 -- sandbox path
			if err != nil {
				return seedResult{}, fmt.Errorf("seed %s copy: %w", name, err)
			}
			target := filepath.Join(box.root, filepath.FromSlash(st.CopyTo))
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return seedResult{}, err
			}
			if err := os.WriteFile(target, data, 0o600); err != nil {
				return seedResult{}, err
			}
			continue
		}
		extra := map[string]string{}
		for _, pair := range st.Env {
			key, value, _ := strings.Cut(pair, "=")
			extra[key] = value
		}
		got, err := box.run(st.Argv, extra, "")
		if err != nil {
			return seedResult{}, fmt.Errorf("seed %s %v: %w", name, st.Argv, err)
		}
		if got.exit != 0 {
			return seedResult{}, fmt.Errorf("seed %s: %v exited %d: %s", name, st.Argv, got.exit, got.stderr)
		}
	}
	files, err := box.collectSeed()
	if err != nil {
		return seedResult{}, err
	}
	return seedResult{Name: name, Steps: steps, Files: files}, nil
}

// --- cases -----------------------------------------------------------------

var allModes = []string{"text", "json", "yaml", "output-json", "quiet"}

func modeArgs(mode string) []string {
	switch mode {
	case "json":
		return []string{"--json"}
	case "yaml":
		return []string{"--output", "yaml"}
	case "output-json":
		return []string{"--output", "json"}
	case "quiet":
		return []string{"--quiet"}
	}
	return nil
}

// modeAccepted reports whether the pinned output-format gate lets the mode
// reach the command (errtaxgen pinned the refusal for the others).
func modeAccepted(row gateRow, mode string) bool {
	switch mode {
	case "json":
		return !row.JSONRefused
	case "yaml", "output-json":
		return !row.OutputRefused
	}
	return true
}

func runCase(goBinary string, seeds map[string]seedResult, spec caseSpec, mode string) (caseResult, error) {
	seed, ok := seeds[spec.seed]
	if !ok {
		return caseResult{}, fmt.Errorf("case %s: unknown seed %q", spec.id, spec.seed)
	}
	box, err := newSandbox(goBinary)
	if err != nil {
		return caseResult{}, err
	}
	defer box.remove()
	box.archives = spec.archives
	if err := box.materialize(seed.Files); err != nil {
		return caseResult{}, fmt.Errorf("case %s: %w", spec.id, err)
	}
	if err := box.materializeFiles(spec.files); err != nil {
		return caseResult{}, fmt.Errorf("case %s: %w", spec.id, err)
	}
	before, err := box.snapshot()
	if err != nil {
		return caseResult{}, err
	}
	argv := append(append([]string(nil), spec.argv...), modeArgs(mode)...)
	got, err := box.run(argv, spec.env, spec.stdin)
	if err != nil {
		return caseResult{}, fmt.Errorf("case %s: %w", spec.id, err)
	}
	vol := &volatile{rules: spec.rules, opaque: spec.opaque, now: time.Now()}
	stdout, err := vol.discover(box.normalize(got.stdout))
	if err != nil {
		return caseResult{}, fmt.Errorf("case %s stdout: %w", spec.id+"."+mode, err)
	}
	result := caseResult{
		ID: spec.id + "." + mode, Path: spec.path, Scenario: spec.id, Mode: mode, Desc: spec.desc,
		Seed: spec.seed, Env: spec.env, Stdin: spec.stdin, Files: spec.files, Rules: spec.rules, Opaque: spec.opaque, Archives: spec.archives,
		Argv: argv, Exit: got.exit,
		Stdout: stdout, Stderr: vol.apply(box.normalize(got.stderr)),
	}
	if !utf8.ValidString(result.Stdout) {
		result.StdoutB64 = base64.StdEncoding.EncodeToString([]byte(result.Stdout))
	}
	if !utf8.ValidString(result.Stderr) {
		result.StderrB64 = base64.StdEncoding.EncodeToString([]byte(result.Stderr))
	}
	for _, text := range []string{result.Stdout, result.Stderr} {
		if strings.Contains(text, "level=WARN") || strings.Contains(text, "level=ERROR") || wallClockLine(text) {
			return caseResult{}, fmt.Errorf("case %s: oracle emitted a wall-clock log line: %q", result.ID, text)
		}
		if strings.Contains(text, "goroutine ") {
			return caseResult{}, fmt.Errorf("case %s: oracle crashed: %q", result.ID, text)
		}
	}
	after, err := box.snapshot()
	if err != nil {
		return caseResult{}, err
	}
	if vol.has("pair-token") && vol.token == "" {
		vol.token = pairTokenFromTree(after)
	}
	result.Tree = diffTrees(before, after, vol)
	for _, post := range spec.post {
		out, err := box.run(post, nil, "")
		if err != nil {
			return caseResult{}, fmt.Errorf("case %s post %v: %w", result.ID, post, err)
		}
		result.Post = append(result.Post, step{Argv: post, Exit: out.exit, Stdout: vol.apply(box.normalize(out.stdout))})
	}
	return result, nil
}

// wallClockLine detects the timestamped lines of Go's log package and slog.
func wallClockLine(text string) bool {
	for i := 0; i+19 <= len(text); i++ {
		w := text[i : i+19]
		if len(w) == 19 && allDigits(w[0:4]) && w[4] == '/' && allDigits(w[5:7]) && w[7] == '/' &&
			allDigits(w[8:10]) && w[10] == ' ' && allDigits(w[11:13]) && w[13] == ':' {
			return true
		}
	}
	return strings.Contains(text, "time=2")
}

// --- driver ----------------------------------------------------------------

func sourceFiles(root string) ([]string, error) {
	// #nosec G204 -- fixed arguments
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--",
		"cmd/*.go", "cmd/**/*.go", "internal/cli/*.go", "internal/cli/output/*.go", "internal/errors/*.go").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" || strings.HasSuffix(name, "_test.go") || strings.Contains(name, "/testdata/") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, errors.New("no production sources found")
	}
	return files, nil
}

func loadGate(root string) ([]gateRow, string, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(gateFixture))) // #nosec G304 -- repository fixture
	if err != nil {
		return nil, "", err
	}
	var doc struct {
		Gate []gateRow `json:"gate"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "", err
	}
	// Only the gate rows matter to this fixture: digest their canonical form so
	// an unrelated edit of error-taxonomy.json does not stale this one.
	canonical, err := json.Marshal(doc.Gate)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return doc.Gate, hex.EncodeToString(sum[:]), nil
}

func acceptingRows(gate []gateRow) []gateRow {
	var rows []gateRow
	for _, row := range gate {
		if !(row.JSONRefused && row.OutputRefused) {
			rows = append(rows, row)
		}
	}
	return rows
}

func loadRecorded(root, output string) (*fixture, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(output))) // #nosec G304 -- repository fixture path
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var existing fixture
	if err := json.Unmarshal(raw, &existing); err != nil {
		return nil, err
	}
	return &existing, nil
}

func main() {
	output := flag.String("output", defaultOutput, "fixture path (relative to the repository root)")
	check := flag.Bool("check", false, "fail if the fixture differs")
	newSeeds := flag.Bool("new-seeds", false, "rebuild the frozen seed vaults with the oracle (fresh keys)")
	goBinary := flag.String("go-binary", "", "validated Go symvault binary used as the oracle")
	flag.Parse()
	if *goBinary == "" {
		fatal("--go-binary is required")
	}
	if err := validateOracle(*goBinary); err != nil {
		fatal("validate Go oracle: %v", err)
	}
	root, err := locateRoot()
	if err != nil {
		fatal("locate repository: %v", err)
	}
	sources, err := sourceFiles(root)
	if err != nil {
		fatal("list production sources: %v", err)
	}
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, pinnedOracleCommit, sources)
	if err != nil {
		fatal("verify oracle: %v", err)
	}
	generatorDigest, err := provenance.Digest(root, generatorFiles)
	if err != nil {
		fatal("hash generator: %v", err)
	}
	gate, gateDigest, err := loadGate(root)
	if err != nil {
		fatal("read gate: %v", err)
	}
	accepting := acceptingRows(gate)
	rows := map[string]gateRow{}
	for _, row := range accepting {
		rows[strings.TrimPrefix(row.Path, "symvault ")] = row
	}

	recorded, err := loadRecorded(root, *output)
	if err != nil {
		fatal("read recorded fixture: %v", err)
	}
	seedPlan := seedPlans()
	seeds := map[string]seedResult{}
	var seedList []seedResult
	switch {
	case *newSeeds || recorded == nil:
		if *check {
			fatal("--check needs a recorded fixture with frozen seeds")
		}
		for _, plan := range seedPlan {
			seed, err := buildSeed(*goBinary, plan.name, plan.steps)
			if err != nil {
				fatal("%v", err)
			}
			seeds[plan.name] = seed
			seedList = append(seedList, seed)
		}
	default:
		for _, plan := range seedPlan {
			var found *seedResult
			for i := range recorded.Seeds {
				if recorded.Seeds[i].Name == plan.name {
					found = &recorded.Seeds[i]
				}
			}
			if found == nil {
				fatal("seed %s is not frozen yet; run with --new-seeds", plan.name)
			}
			want, _ := json.Marshal(plan.steps)
			have, _ := json.Marshal(found.Steps)
			if !bytes.Equal(want, have) {
				fatal("seed %s: recorded commands differ from the generator; run with --new-seeds", plan.name)
			}
			seeds[plan.name] = *found
			seedList = append(seedList, *found)
		}
	}

	specs := allCaseSpecs()
	seenIDs := map[string]bool{}
	covered := map[string]bool{}
	var results []caseResult
	for _, spec := range specs {
		if seenIDs[spec.id] {
			fatal("duplicate scenario id %s", spec.id)
		}
		seenIDs[spec.id] = true
		row, ok := rows[spec.path]
		if !ok {
			fatal("scenario %s: path %q is not an accepting gate path", spec.id, spec.path)
		}
		covered[spec.path] = true
		modes := spec.modes
		if len(modes) == 0 {
			for _, mode := range allModes {
				if modeAccepted(row, mode) {
					modes = append(modes, mode)
				}
			}
		}
		for _, mode := range modes {
			if !modeAccepted(row, mode) {
				fatal("scenario %s: mode %s is refused by the gate for %s", spec.id, mode, spec.path)
			}
		}
		for _, mode := range modes {
			got, err := runCase(*goBinary, seeds, spec, mode)
			if err != nil {
				fatal("%v", err)
			}
			results = append(results, got)
		}
	}
	residuals := allResiduals()
	resolvedPaths := map[string]bool{}
	for _, res := range residuals {
		resolvedPaths[res.Path] = true
	}
	for _, row := range accepting {
		path := strings.TrimPrefix(row.Path, "symvault ")
		if !covered[path] {
			fatal("accepting path %q has neither a scenario nor a residual", path)
		}
	}
	for path := range resolvedPaths {
		if !covered[path] {
			fatal("residual path %q has no partial scenario", path)
		}
	}

	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: pinnedOracleCommit, CommitSHA: resolved, Release: pinnedOracleRelease,
			GoVersion: "go1.26.6", SourceFiles: sources, SourceDigest: sourceDigest,
			GeneratorFiles: generatorFiles, GeneratorDigest: generatorDigest, GateDigest: gateDigest, GOOS: runtime.GOOS,
		},
		Notes:     fixtureNotes(),
		Seeds:     seedList,
		Residuals: residuals,
		Cases:     results,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}
	summary := fmt.Sprintf("%d cases over %d command paths, %d seeds", len(results), len(covered), len(seedList))
	target := filepath.Join(root, filepath.FromSlash(*output))
	if *check {
		existing, err := os.ReadFile(target) // #nosec G304 -- repository fixture path
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; regenerate deliberately")
		}
		fmt.Printf("PASS output-mode fixture (%s)\n", summary)
		return
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%s)\n", *output, summary)
}

// normalizationRule is one entry of the numbered list in the file header.
type normalizationRule struct{ id, text string }

// normalizationRules mirrors the header list; fixtureNotes turns it into the
// notes of the fixture, and the Rust replay checks the ids and their order.
var normalizationRules = []normalizationRule{
	{"root", "sandbox root and its symlink-resolved form become $ROOT (stdout, stderr, tree paths, text files, archive members, seed text files)"},
	{"bin", "the absolute path of the executed binary becomes $BIN"},
	{"dated-id", "tok-/intake-/import-YYYYMMDD-<8 hex> with a valid date becomes <prefix>-<DATE>-<RAND>"},
	{"tmp-suffix", ".age.tmp-<digits> becomes .age.tmp-<N>"},
	{"touch-id", "the boolean after 'Touch ID available: ' and in \"touchIDAvailable\": becomes <BOOL> (sensor property); on darwin the replay also compares the live Go and Rust values"},
	{"gen-pw", "case-declared gen-pw:N: exactly one delimited run of N alphanumerics becomes <PW> (shape verified)"},
	{"pair-token", "case-declared: the 32-character base32 pairing token becomes <TOKEN>, its first six characters <TOKEN6>"},
	{"now-ts", "case-declared: RFC 3339 timestamps within one hour of the run become <NOW>; seed timestamps stay"},
	{"man-date", "case-declared: the date field of a roff .TH header ('Mon YYYY') becomes <MAN-DATE>"},
	{"opaque", "case-declared tree path prefixes are recorded by presence only (device-pair invitation file, doctor token store)"},
	{"encrypted-store", "the vault's encrypted store (entries, manifest, identity, lock, search index, .git) is not in the tree diff"},
	{"audit-fields", "audit-*.log files are recorded as decoded fields (agent, action, path, field, ok, argv_hash length, signed), not bytes"},
	{"archive-members", "case-declared archive path prefixes: every file below is recorded as decompressed .tar.gz members, sorted by name (Go writes them in map order): name, type, mode, sha256 of normalized content"},
	{"managed-fields", "inside archive members the digits of a 'managed_hash: sha256:' line become <HASH> and the stamp of a 'managed_installed_at: \"…\"' line becomes <NOW> (install-time values)"},
}

func fixtureNotes() []string {
	notes := []string{
		"Positive output matrix of the CLI-006 output-format gate: for every command path that accepts --json and/or --output, the accepted modes (text, --json, --output yaml, --output json, --quiet) are run against the pinned Go oracle. Refused modes are byte-pinned by testdata/port/cli/error-taxonomy.json and not repeated here.",
		"Every case ran in a disposable HOME/XDG/cwd sandbox seeded from a frozen vault tree (seeds[]); the seed commands are recorded and --check refuses a generator whose commands differ from the recorded ones.",
		"Sandbox environment: TZ=UTC, NO_COLOR=1, CI=1, SYMVAULT_PASSPHRASE with SYMVAULT_ALLOW_ENV_PASSPHRASE=1, stdin /dev/null unless a case supplies stdin.",
		"Normalization is the numbered list 'Normalization rule N (id): ...' below (cmd/outputmodegen/main.go header, tests/output_modes.rs header and replay agree on it; a test fails when they differ); anything not listed is compared byte for byte. Every tree entry also records the permission bits (umask 022).",
		"tree[] is the file-system diff of the sandbox root after the case, excluding the encrypted vault store (rule 11); post[] pins the resulting vault state with follow-up commands (stdout and exit only).",
		"Some commands define a local --output flag that shadows the global one (agent profile export, agent skill export, audit export, export, template generate): there `--output yaml` names an output file; the recorded tree pins that side effect.",
	}
	for index, rule := range normalizationRules {
		notes = append(notes, fmt.Sprintf("Normalization rule %d (%s): %s", index+1, rule.id, rule.text))
	}
	return notes
}

func validateGoBinary(path string) error {
	const modulePath = "github.com/danieljustus/symaira-vault"
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read build metadata: %w", err)
	}
	if info.Path != modulePath || info.Main.Path != modulePath {
		return fmt.Errorf("main module %q/%q, want %q", info.Path, info.Main.Path, modulePath)
	}
	if info.GoVersion != "go1.26.6" {
		return fmt.Errorf("GoVersion %q, want go1.26.6", info.GoVersion)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	for key, want := range map[string]string{
		"vcs.revision": pinnedOracleCommit,
		"vcs.modified": "false",
	} {
		if got := settings[key]; got != want {
			return fmt.Errorf("build setting %s=%q, want %q", key, got, want)
		}
	}
	return nil
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	exit(1)
}
