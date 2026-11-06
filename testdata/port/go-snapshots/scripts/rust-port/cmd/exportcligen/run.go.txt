package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	stepTimeout = 20 * time.Second
	// umaskValue is applied to every step through the shell wrapper so the
	// oracle and the native replay create files under the same process umask.
	umaskValue = "022"
	passphrase = "correct horse battery staple"
	rootMarker = "$ROOT"

	// Volatile-value placeholders, documented in the fixture's normalization.
	placeholderArchive = "<generated-archive>"
	placeholderTS      = "<ts>"
	placeholderKID     = "<kid>"
	placeholderHMAC    = "<hmac>"
	placeholderArgv    = "<argv_hash>"
	auditLogName       = "audit-symvault.log"
	manifestName       = "manifest.age"
	placeholderRewrite = "<rewritten>"
)

// FileSpec is one pre-existing file, directory or symlink of a scenario root.
type FileSpec struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode,omitempty"`
	Data   string `json:"data,omitempty"`
	B64    string `json:"b64,omitempty"`
	Target string `json:"target,omitempty"`
}

// Step is one invocation of the CLI inside a scenario.
type Step struct {
	Argv []string `json:"argv"`
	// Stdin is nil for a closed stdin (the null device); otherwise the exact
	// bytes piped to the process.
	Stdin *string `json:"stdin"`
}

// Result is the observation of one step.
type Result struct {
	Exit   int    `json:"exit"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// Node is one entry of the final manifest of a scenario root.
type Node struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Target     string `json:"target,omitempty"`
	Normalized string `json:"normalized,omitempty"`
}

// Member is one tar member of a produced or supplied archive.
type Member struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Mode   int64  `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ArchiveListing is the member list of one archive found in the final tree.
type ArchiveListing struct {
	Path     string   `json:"path"`
	Complete bool     `json:"complete"`
	Members  []Member `json:"members"`
}

// Case is one scenario: inputs followed by the oracle's observations.
type Case struct {
	ID    string `json:"id"`
	Desc  string `json:"desc"`
	Class string `json:"class"`
	// Seed names a frozen vault tree materialised as <root>/vault; empty means
	// no vault directory exists.
	Seed  string            `json:"seed,omitempty"`
	Pre   []FileSpec        `json:"pre,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
	Unset []string          `json:"unset,omitempty"`
	Steps []Step            `json:"steps"`
	// StderrTailFrom, when set, makes the replay compare each step's stderr only
	// up to the first occurrence of this marker (the marker must be present in
	// both). It is used where the tail is a third-party library diagnostic (age
	// decryption wording) that the Rust port words differently by design; the
	// prefix, exit status, stdout and the resulting tree stay exact.
	StderrTailFrom string `json:"stderr_tail_from,omitempty"`

	Results []Result `json:"results"`
	// Tree holds the nodes that are new or differ from the pre-run state
	// (seed, pre files and the empty home/work/tmp directories); Removed the
	// pre-run paths that no longer exist; Archives the member lists of the
	// archives among Tree.
	Tree     []Node           `json:"tree"`
	Removed  []string         `json:"removed"`
	Archives []ArchiveListing `json:"archives"`
}

type sandbox struct {
	root string
}

func newSandbox() (*sandbox, error) {
	root, err := os.MkdirTemp("", "exportcligen-")
	if err != nil {
		return nil, err
	}
	for _, dir := range []string{"home", "work", "tmp"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			_ = os.RemoveAll(root)
			return nil, err
		}
	}
	return &sandbox{root: root}, nil
}

// remove deletes the root, first making every directory traversable again
// because scenarios deliberately create unwritable trees.
func (s *sandbox) remove() {
	_ = filepath.Walk(s.root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(s.root)
}

func (s *sandbox) expand(text string) string {
	return strings.NewReplacer(
		"{ROOT}", s.root,
		"{HOME}", filepath.Join(s.root, "home"),
		"{WORK}", filepath.Join(s.root, "work"),
		"{VAULT}", filepath.Join(s.root, "vault"),
	).Replace(text)
}

func (s *sandbox) normalize(text string) string {
	roots := []string{s.root}
	if resolved, err := filepath.EvalSymlinks(s.root); err == nil && resolved != s.root {
		roots = []string{resolved, s.root}
	}
	for _, root := range roots {
		text = strings.ReplaceAll(text, root, rootMarker)
	}
	return text
}

func (s *sandbox) environment(c Case) []string {
	home := filepath.Join(s.root, "home")
	env := map[string]string{
		"PATH":            "/usr/bin:/bin",
		"HOME":            home,
		"USERPROFILE":     home,
		"XDG_CONFIG_HOME": filepath.Join(s.root, "xdg-config"),
		"XDG_DATA_HOME":   filepath.Join(s.root, "xdg-data"),
		"XDG_CACHE_HOME":  filepath.Join(s.root, "xdg-cache"),
		"TMPDIR":          filepath.Join(s.root, "tmp"),
		"NO_COLOR":        "1",
		"LC_ALL":          "C",
		"TZ":              "UTC",
		// CI and SYMVAULT_TEST_KEYRING=memory make both implementations keep the
		// audit HMAC key and the session cache in process memory, so no scenario
		// ever reaches the operator's OS keychain.
		"CI":                            "1",
		"SYMVAULT_TEST_KEYRING":         "memory",
		"SYMVAULT_VAULT":                filepath.Join(s.root, "vault"),
		"SYMVAULT_PASSPHRASE":           passphrase,
		"SYMVAULT_ALLOW_ENV_PASSPHRASE": "1",
	}
	for key, value := range c.Env {
		env[key] = s.expand(value)
	}
	for _, key := range c.Unset {
		delete(env, key)
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}

func decodeSpecData(spec FileSpec) ([]byte, error) {
	if spec.B64 != "" {
		return base64.StdEncoding.DecodeString(spec.B64)
	}
	return []byte(spec.Data), nil
}

// materialize creates specs below the sandbox root. Directories are created
// first with a writable mode and given their final mode last, deepest first.
func (s *sandbox) materialize(specs []FileSpec) error {
	type dirMode struct {
		path string
		mode os.FileMode
	}
	var dirs []dirMode
	for _, spec := range specs {
		path := filepath.Join(s.root, filepath.FromSlash(spec.Path))
		switch spec.Kind {
		case "dir":
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
			dirs = append(dirs, dirMode{path, os.FileMode(spec.Mode)})
		case "file":
			data, err := decodeSpecData(spec)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return err
			}
			if err := os.Chmod(path, os.FileMode(spec.Mode)); err != nil {
				return err
			}
		case "symlink":
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			if err := os.Symlink(s.expand(spec.Target), path); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown spec kind %q", spec.Kind)
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i].path, dirs[i].mode); err != nil {
			return err
		}
	}
	return nil
}

func isUTF8(raw []byte) bool { return utf8.Valid(raw) }

func (s *sandbox) runStep(goBinary string, c Case, step Step) (Result, error) {
	args := make([]string, 0, len(step.Argv))
	for _, arg := range step.Argv {
		args = append(args, s.expand(arg))
	}
	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()
	wrapper := append([]string{"-c", "umask " + umaskValue + `; exec "$0" "$@"`, goBinary}, args...)
	// #nosec G204 -- validateGoBinary checked the pinned, clean oracle first.
	cmd := exec.CommandContext(ctx, "/bin/sh", wrapper...)
	cmd.Dir = filepath.Join(s.root, "work")
	cmd.Env = s.environment(c)
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	if step.Stdin != nil {
		cmd.Stdin = strings.NewReader(*step.Stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return Result{}, fmt.Errorf("%v timed out", step.Argv)
	}
	result := Result{}
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return Result{}, runErr
		}
		result.Exit = exitErr.ExitCode()
	}
	for _, text := range []struct {
		raw  []byte
		dest *string
	}{{stdout.Bytes(), &result.Stdout}, {stderr.Bytes(), &result.Stderr}} {
		if !isUTF8(text.raw) {
			return Result{}, fmt.Errorf("output of %v is not valid UTF-8", step.Argv)
		}
		*text.dest = s.normalize(string(text.raw))
	}
	return result, nil
}

// isArchiveName reports whether a file is listed as an archive.
func isArchiveName(name string) bool {
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz")
}

// normalizeAuditLog applies the audit-log rule shared with the native replay:
// every line is parsed as a JSON object, the per-write values ts, kid, hmac and
// argv_hash (a digest of the argv, which holds the sandbox path) are replaced by fixed placeholders, and the object is re-serialised with
// sorted keys. Every other field (agent, action, ok, ...) is compared.
func normalizeAuditLog(content []byte) ([]byte, error) {
	var out bytes.Buffer
	for _, line := range strings.SplitAfter(string(content), "\n") {
		if line == "" {
			continue
		}
		var object map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSuffix(line, "\n")), &object); err != nil {
			return nil, fmt.Errorf("audit line %q: %w", line, err)
		}
		for key, placeholder := range map[string]string{"ts": placeholderTS, "kid": placeholderKID, "hmac": placeholderHMAC, "argv_hash": placeholderArgv} {
			if _, ok := object[key]; ok {
				object[key] = placeholder
			}
		}
		encoded, err := marshalCompact(object)
		if err != nil {
			return nil, err
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

func marshalCompact(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// snapshot records the whole sandbox root. Unreadable directories and files are
// made readable for the walk only; the recorded mode is the mode found.
//
// before is the raw content digest of every file in the pre-run snapshot (nil
// for that snapshot itself). It drives the two rules for bytes a command
// cannot reproduce: a *.tar.gz and a manifest.age whose content changed since
// the pre-run state are recorded with placeholders, unchanged ones exactly.
func (s *sandbox) snapshot(before map[string]string) ([]Node, map[string]string, error) {
	var nodes []Node
	raw := map[string]string{}
	var visit func(dir string) error
	visit = func(dir string) error {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		restore := info.Mode().Perm()
		if restore&0o500 != 0o500 {
			if err := os.Chmod(dir, 0o700); err != nil {
				return err
			}
			defer func() { _ = os.Chmod(dir, restore) }()
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			rel, err := filepath.Rel(s.root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			node := Node{Path: rel, Mode: uint32(info.Mode().Perm())}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				node.Kind, node.Mode, node.Target = "symlink", 0, s.normalize(target)
				nodes = append(nodes, node)
			case info.IsDir():
				node.Kind = "dir"
				nodes = append(nodes, node)
				if err := visit(path); err != nil {
					return err
				}
			case info.Mode().IsRegular():
				node.Kind = "file"
				readable := info.Mode().Perm()&0o400 != 0
				if !readable {
					if err := os.Chmod(path, 0o600); err != nil {
						return err
					}
				}
				content, err := os.ReadFile(path)
				if !readable {
					_ = os.Chmod(path, info.Mode().Perm())
				}
				if err != nil {
					return err
				}
				raw[rel] = digest(content)
				changed := before != nil && before[rel] != raw[rel]
				switch {
				case entry.Name() == auditLogName:
					normalized, err := normalizeAuditLog(content)
					if err != nil {
						return err
					}
					node.Size, node.SHA256, node.Normalized = int64(len(normalized)), digest(normalized), "audit-log"
				case entry.Name() == manifestName && changed:
					// age encryption is randomised: a manifest the command created
					// or rewrote has new bytes on every run, so only the fact that
					// it differs from the pre-run state is recorded.
					node.Size, node.SHA256, node.Normalized = -1, placeholderRewrite, "manifest-rewritten"
				case isArchiveName(entry.Name()) && changed:
					node.Size, node.SHA256, node.Normalized = -1, placeholderArchive, "generated-archive"
				default:
					node.Size, node.SHA256 = int64(len(content)), digest(content)
				}
				nodes = append(nodes, node)
			default:
				node.Kind = "other"
				nodes = append(nodes, node)
			}
		}
		return nil
	}
	if err := visit(s.root); err != nil {
		return nil, nil, err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Path < nodes[j].Path })
	return nodes, raw, nil
}

// delta returns the nodes of after that are new or differ from before, and the
// paths of before that no longer exist.
func delta(before, after []Node) ([]Node, []string) {
	prior := make(map[string]Node, len(before))
	for _, node := range before {
		prior[node.Path] = node
	}
	present := make(map[string]bool, len(after))
	changed := []Node{}
	for _, node := range after {
		present[node.Path] = true
		if old, ok := prior[node.Path]; !ok || old != node {
			changed = append(changed, node)
		}
	}
	removed := []string{}
	for _, node := range before {
		if !present[node.Path] {
			removed = append(removed, node.Path)
		}
	}
	return changed, removed
}

// archiveListings lists the member lists of the archives among nodes.
func (s *sandbox) archiveListings(nodes []Node) ([]ArchiveListing, error) {
	listings := []ArchiveListing{}
	for _, node := range nodes {
		if node.Kind != "file" || !isArchiveName(node.Path) {
			continue
		}
		path := filepath.Join(s.root, filepath.FromSlash(node.Path))
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0o400 == 0 {
			if err := os.Chmod(path, 0o600); err != nil {
				return nil, err
			}
			defer func(p string, mode os.FileMode) { _ = os.Chmod(p, mode) }(path, info.Mode().Perm())
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		listing, err := listArchive(content)
		if err != nil {
			return nil, err
		}
		listing.Path = node.Path
		listings = append(listings, listing)
	}
	return listings, nil
}

// listArchive reads a gzip tar member list. Complete is false when the stream
// ended in an error; the members read up to that point are still recorded.
func listArchive(content []byte) (ArchiveListing, error) {
	listing := ArchiveListing{Members: []Member{}}
	gr, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return listing, nil
	}
	tr := tar.NewReader(gr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			listing.Complete = true
			return listing, nil
		}
		if err != nil {
			return listing, nil
		}
		member := Member{Name: header.Name, Mode: header.Mode, Size: header.Size}
		switch header.Typeflag {
		case tar.TypeReg:
			member.Type = "file"
		case tar.TypeDir:
			member.Type = "dir"
		case tar.TypeSymlink:
			member.Type = "symlink"
		default:
			member.Type = fmt.Sprintf("type-%d", header.Typeflag)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return listing, nil
		}
		if path.Base(header.Name) == auditLogName {
			// The same audit-log rule as for files on disk.
			if body, err = normalizeAuditLog(body); err != nil {
				return listing, err
			}
		}
		member.Size = int64(len(body))
		member.SHA256 = digest(body)
		listing.Members = append(listing.Members, member)
	}
}

// runCase executes one scenario in a fresh sandbox and fills in observations.
func runCase(goBinary string, seeds map[string][]FileSpec, c Case) (Case, error) {
	box, err := newSandbox()
	if err != nil {
		return c, err
	}
	defer box.remove()
	if c.Seed != "" {
		seed, ok := seeds[c.Seed]
		if !ok {
			return c, fmt.Errorf("case %s: unknown seed %q", c.ID, c.Seed)
		}
		if err := box.materialize(seed); err != nil {
			return c, fmt.Errorf("case %s: seed: %w", c.ID, err)
		}
	}
	if err := box.materialize(c.Pre); err != nil {
		return c, fmt.Errorf("case %s: pre: %w", c.ID, err)
	}
	beforeNodes, beforeRaw, err := box.snapshot(nil)
	if err != nil {
		return c, fmt.Errorf("case %s: pre-run snapshot: %w", c.ID, err)
	}
	c.Results = nil
	for _, step := range c.Steps {
		result, err := box.runStep(goBinary, c, step)
		if err != nil {
			return c, fmt.Errorf("case %s: %w", c.ID, err)
		}
		c.Results = append(c.Results, result)
	}
	afterNodes, _, err := box.snapshot(beforeRaw)
	if err != nil {
		return c, fmt.Errorf("case %s: snapshot: %w", c.ID, err)
	}
	if c.StderrTailFrom != "" {
		found := false
		for _, result := range c.Results {
			found = found || strings.Contains(result.Stderr, c.StderrTailFrom)
		}
		if !found {
			return c, fmt.Errorf("case %s: stderr_tail_from %q never occurs in the oracle's stderr", c.ID, c.StderrTailFrom)
		}
	}
	c.Tree, c.Removed = delta(beforeNodes, afterNodes)
	c.Archives, err = box.archiveListings(c.Tree)
	if err != nil {
		return c, fmt.Errorf("case %s: archives: %w", c.ID, err)
	}
	return c, nil
}
