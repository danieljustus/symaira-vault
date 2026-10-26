// Command restoregen freezes the production Go backup-restore error and
// side-effect contract (IO-002) as a Go-derived corpus.
//
// Every case builds an archive, runs the real cmd/admin RestoreBackup in a
// disposable per-case root and records the exact error text plus the complete
// resulting file tree (including what an escape would have touched outside the
// destination). Rust replays the same archives through its restore path.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/danieljustus/symaira-vault/cmd/admin"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const pinnedOracleCommit = "861ad93813e3ee43c4ec989f45940d14b05b6eaf"

const fixturePath = "testdata/port/sync/restore-errors.json"

// Reasons a case is recorded Unix-only: its outcome is not what Go produces
// on Windows, so replaying it there would compare against a foreign OS.
const (
	reasonSymlink    = "seeds a POSIX symlink; Windows symlink creation needs privileges and the Windows SafeMkdirAll follows symlinks instead of rejecting them"
	reasonPermission = "depends on Unix permission bits (read-only directories and files) that Windows does not enforce the same way"
	reasonColonName  = "':' inside a member name is legal on Unix but an NTFS alternate-data-stream separator: Go on Windows creates a hidden stream or fails with an invalid-name error, neither of which this Unix recording pins"
)

type member struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Mode     int64  `json:"mode"`
	Data     string `json:"data,omitempty"`
	Size     *int64 `json:"size,omitempty"`
	Linkname string `json:"linkname,omitempty"`
}

type pre struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode,omitempty"`
	Data   string `json:"data,omitempty"`
	Target string `json:"target,omitempty"`
}

type node struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

type restoreCase struct {
	Name string `json:"name"`
	// UnixOnly marks a case whose recorded outcome cannot be reproduced on
	// Windows; UnixOnlyReason says why (required whenever UnixOnly is set).
	UnixOnly       bool   `json:"unix_only,omitempty"`
	UnixOnlyReason string `json:"unix_only_reason,omitempty"`
	Wrap           string `json:"wrap"`
	TarB64         string `json:"tar_b64"`
	Pre            []pre  `json:"pre,omitempty"`
	// Dest is the restore destination relative to the case root.
	Dest string `json:"dest"`
	// Missing leaves the archive file absent (the CLI's own stat check).
	Missing bool   `json:"missing,omitempty"`
	Error   string `json:"error"`
	// ErrorPrefix, when set, replaces exact error comparison: the text after it
	// is a decoder-internal detail Go reports and Rust cannot reproduce.
	ErrorPrefix string `json:"error_prefix,omitempty"`
	// OSError marks messages whose final ": reason" is host-OS text.
	OSError bool     `json:"os_error,omitempty"`
	Tree    []node   `json:"tree"`
	Members []member `json:"members,omitempty"`
}

var requiredMembers = []member{
	{Name: "identity.age", Type: "reg", Mode: 0o600, Data: "identity"},
	{Name: "config.yaml", Type: "reg", Mode: 0o600, Data: "vault_dir: fixture\n"},
	{Name: "entries/", Type: "dir", Mode: 0o700},
}

func with(extra ...member) []member {
	return append(append([]member{}, requiredMembers...), extra...)
}

func i64(v int64) *int64 { return &v }

func typeflag(kind string) byte {
	switch kind {
	case "reg":
		return tar.TypeReg
	case "dir":
		return tar.TypeDir
	case "symlink":
		return tar.TypeSymlink
	case "link":
		return tar.TypeLink
	case "char":
		return tar.TypeChar
	case "block":
		return tar.TypeBlock
	case "fifo":
		return tar.TypeFifo
	case "cont":
		return tar.TypeCont
	case "xglobal":
		return tar.TypeXGlobalHeader
	case "rega":
		// Legacy regular-file flag. archive/tar's writer normalizes it, so
		// members of this type are always emitted byte-for-byte.
		return 0
	}
	panic("unknown member type " + kind)
}

// buildTar serializes members. Without trailer it omits the end-of-archive marker
// and any data owed by an oversized header, producing an archive cut short.
func buildTar(members []member, format tar.Format, trailer bool) []byte {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, m := range members {
		header := &tar.Header{Name: m.Name, Mode: m.Mode, Typeflag: typeflag(m.Type), Linkname: m.Linkname, Format: format}
		if m.Type == "reg" {
			header.Size = int64(len(m.Data))
		}
		if m.Size != nil {
			header.Size = *m.Size
		}
		if m.Type == "xglobal" {
			header.PAXRecords = map[string]string{"comment": "oracle"}
		}
		if m.Type == "rega" {
			if err := writer.Flush(); err != nil {
				panic(err)
			}
			buffer.Write(rawHeader(m, int64(len(m.Data))))
			buffer.Write(rawBody(m))
			continue
		}
		if m.Size != nil {
			// The header promises more data than follows: hand-assemble it.
			if err := writer.Flush(); err != nil {
				panic(err)
			}
			buffer.Write(rawHeader(m, *m.Size))
			continue
		}
		if err := writer.WriteHeader(header); err != nil {
			// Go's own writer refuses hostile names (trailing slash runs,
			// control bytes). Emit those headers byte-for-byte instead.
			if err := writer.Flush(); err != nil {
				panic(err)
			}
			buffer.Write(rawHeader(m, header.Size))
			buffer.Write(rawBody(m))
			continue
		}
		if m.Type == "reg" && m.Size == nil {
			if _, err := writer.Write([]byte(m.Data)); err != nil {
				panic(err)
			}
		}
	}
	if trailer {
		if err := writer.Close(); err != nil {
			panic(err)
		}
		return buffer.Bytes()
	}
	if err := writer.Flush(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func gzipBytes(data []byte) []byte {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

// wrapped returns the exact bytes handed to Go and the wrap-independent tar
// payload that Rust re-wraps.
func wrapped(wrap string, tarBytes []byte) []byte {
	switch wrap {
	case "gzip":
		return gzipBytes(tarBytes)
	case "raw":
		return tarBytes
	case "gzip-cut":
		packed := gzipBytes(tarBytes)
		return packed[:len(packed)/2]
	case "gzip-corrupt":
		packed := gzipBytes(tarBytes)
		packed[len(packed)/2] ^= 0xff
		return packed
	case "empty":
		return []byte{}
	case "gzip-short-header":
		return gzipBytes(tarBytes)[:6]
	}
	panic("unknown wrap " + wrap)
}

func snapshot(root string) []node {
	var out []node
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." || rel == "input.tar.gz" {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		item := node{Path: filepath.ToSlash(rel)}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			item.Kind = "symlink"
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			item.Target = filepath.ToSlash(target)
		case info.IsDir():
			item.Kind = "dir"
			item.Mode = uint32(info.Mode().Perm())
		default:
			item.Kind = "file"
			item.Mode = uint32(info.Mode().Perm())
			data, err := os.ReadFile(path) // #nosec G304 -- walks the generator's own temporary case root
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			item.Size = int64(len(data))
			item.SHA256 = hex.EncodeToString(sum[:])
		}
		out = append(out, item)
		return nil
	})
	if err != nil {
		panic(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func seed(root string, entries []pre) {
	for _, item := range entries {
		path := filepath.Join(root, filepath.FromSlash(item.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			panic(err)
		}
		switch item.Kind {
		case "file":
			if err := os.WriteFile(path, []byte(item.Data), 0o600); err != nil {
				panic(err)
			}
			if err := os.Chmod(path, fs.FileMode(item.Mode)); err != nil {
				panic(err)
			}
		case "dir":
			if err := os.MkdirAll(path, 0o700); err != nil {
				panic(err)
			}
			if err := os.Chmod(path, fs.FileMode(item.Mode)); err != nil {
				panic(err)
			}
		case "symlink":
			if err := os.Symlink(item.Target, path); err != nil {
				panic(err)
			}
		default:
			panic("unknown pre kind " + item.Kind)
		}
	}
}

func run(name, wrap string, format tar.Format, members []member, trailer bool, setup []pre, unixReason string) restoreCase {
	return runAt(name, wrap, format, members, trailer, setup, unixReason, "vault", false, nil)
}

// runAt additionally chooses the destination and may substitute raw tar bytes.
func runAt(name, wrap string, format tar.Format, members []member, trailer bool, setup []pre, unixReason string, destRel string, missing bool, rawTar func([]byte) []byte) restoreCase {
	if unixReason != "" && runtime.GOOS == "windows" {
		panic("restoregen must run on a Unix host: " + name)
	}
	tarBytes := buildTar(members, format, trailer)
	if rawTar != nil {
		tarBytes = rawTar(tarBytes)
	}
	archive := wrapped(wrap, tarBytes)

	root, err := os.MkdirTemp("", "restoregen-")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	// Resolve /var -> /private/var style prefixes so the recorded message
	// does not depend on how the host spells its temp directory.
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		panic(err)
	}
	// Cases that seed read-only directories must still be removable.
	defer func() { makeWritable(root) }()
	dest := filepath.Join(root, filepath.FromSlash(destRel))
	if err := os.MkdirAll(filepath.Join(root, "outside"), 0o700); err != nil {
		panic(err)
	}
	seed(root, setup)
	archivePath := filepath.Join(root, "input.tar.gz")
	if !missing {
		if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
			panic(err)
		}
	}

	message := ""
	if missing {
		// RunE in cmd/admin/backup.go stats the archive before RestoreBackup
		// and wraps the os error as "archive not found: %w".
		if _, err := os.Stat(archivePath); err != nil {
			message = "archive not found: " + err.Error()
		}
	} else if err := admin.RestoreBackup(archivePath, dest); err != nil {
		// The CLI wraps every restore failure exactly once.
		message = "restore failed: " + err.Error()
	}
	message = strings.ReplaceAll(message, dest, "$DEST")
	message = strings.ReplaceAll(message, root, "$ROOT")
	prefix := ""
	if strings.Contains(message, "flate: corrupt input before offset ") {
		// Go's inflater rejects the corrupt byte itself, while a different
		// inflater may only notice at the tar layer: only the stage is pinned.
		prefix = "restore failed: read archive: "
	}
	osError := false
	for _, marker := range []string{"not a directory", "too many levels of symbolic links", "is a directory", "no such file or directory", "permission denied"} {
		if strings.HasSuffix(message, ": "+marker) {
			osError = true
		}
	}
	return restoreCase{
		Name:           name,
		UnixOnly:       unixReason != "",
		UnixOnlyReason: unixReason,
		Wrap:           wrap,
		TarB64:         base64.StdEncoding.EncodeToString(tarBytes),
		Pre:            setup,
		Dest:           destRel,
		Missing:        missing,
		Error:          message,
		ErrorPrefix:    prefix,
		OSError:        osError,
		Tree:           snapshot(root),
		Members:        members,
	}
}

// makeWritable restores owner access to every directory below root so the
// disposable case root can be deleted after a read-only-directory case.
func makeWritable(root string) {
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if entry != nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700) // #nosec G302 -- disposable generator directory
		}
		return nil
	})
}

// patchHeaderMode overwrites the mode field of the tar header at block index
// and recomputes its checksum, so only the numeric field is malformed.
func patchHeaderMode(data []byte, index int, field string) []byte {
	out := append([]byte{}, data...)
	block := out[index*512 : (index+1)*512]
	copy(block[100:108], field)
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	sum := 0
	for _, b := range block {
		sum += int(b)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return out
}

func buildCases() []restoreCase {
	var cases []restoreCase
	add := func(name string, members []member, setup ...pre) {
		reason := ""
		if hasSymlink(setup) {
			reason = reasonSymlink
		}
		cases = append(cases, run(name, "gzip", tar.FormatUnknown, members, true, setup, reason))
	}

	add("valid-modes-clamped", []member{
		{Name: "identity.age", Type: "reg", Mode: 0o777, Data: "identity"},
		{Name: "config.yaml", Type: "reg", Mode: 0o644, Data: "vault_dir: fixture\n"},
		{Name: "entries/", Type: "dir", Mode: 0o777},
		{Name: "entries/nested", Type: "dir", Mode: 0o755},
		{Name: "entries/nested/item.age", Type: "reg", Mode: 0o4755, Data: "ciphertext"},
		{Name: "..dots", Type: "reg", Mode: 0o600, Data: "not traversal"},
		{Name: "unicode-é-名前/note.txt", Type: "reg", Mode: 0o600, Data: "utf8"},
	})
	add("duplicate-member-last-wins", with(
		member{Name: "entries/a.age", Type: "reg", Mode: 0o600, Data: "first"},
		member{Name: "entries/a.age", Type: "reg", Mode: 0o600, Data: "second"},
	))
	long := strings.Repeat("segment-", 16) + "/" + strings.Repeat("leaf-", 30)
	add("long-pax-name", with(member{Name: "entries/" + long, Type: "reg", Mode: 0o600, Data: "long"}))
	add("directory-trailing-slash-only", []member{
		{Name: "identity.age", Type: "reg", Mode: 0o600, Data: "identity"},
		{Name: "config.yaml", Type: "reg", Mode: 0o600, Data: "vault_dir: fixture\n"},
		{Name: "entries", Type: "dir", Mode: 0o700},
	})
	add("empty-archive", nil)
	add("missing-identity", []member{
		{Name: "config.yaml", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "entries/", Type: "dir", Mode: 0o700},
	})
	add("missing-config", []member{
		{Name: "identity.age", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "entries/", Type: "dir", Mode: 0o700},
	})
	add("missing-entries-directory", []member{
		{Name: "identity.age", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "config.yaml", Type: "reg", Mode: 0o600, Data: "x"},
	})
	add("entries-is-a-file", []member{
		{Name: "identity.age", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "config.yaml", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "entries", Type: "reg", Mode: 0o600, Data: "file"},
	})

	for _, name := range []string{
		"../outside/escaped", "entries/../../outside/escaped", "/abs/escaped", "C:drive-relative",
		"entries\\back", "a//b", "a/./b", "./a", ".", "..", "", "a/..", "a/b/..", "entries//",
		"entries/./", "//double", "ab:c", "x:",
	} {
		label := name
		if label == "" {
			label = "empty-name"
		}
		reason := ""
		if name == "ab:c" {
			// Unix accepts the name. Go on Windows is not byte-equivalent:
			// NTFS reads "ab:c" as stream "c" of file "ab", so the open
			// creates a hidden alternate data stream (file) or fails with
			// an invalid-name error (directory).
			reason = reasonColonName
		}
		cases = append(cases, run("unsafe-name/"+label, "gzip", tar.FormatUnknown, append(with(member{Name: "entries/before", Type: "reg", Mode: 0o600, Data: "kept"}), member{Name: name, Type: "reg", Mode: 0o600, Data: "x"}, member{Name: "entries/after", Type: "reg", Mode: 0o600, Data: "not-written"}), true, nil, reason))
		cases = append(cases, run("unsafe-dir-name/"+label, "gzip", tar.FormatUnknown, append(with(), member{Name: name, Type: "dir", Mode: 0o700}, member{Name: "entries/after", Type: "reg", Mode: 0o600, Data: "not-written"}), true, nil, reason))
	}

	for _, kind := range []string{"symlink", "link", "char", "block", "fifo", "cont", "xglobal"} {
		add("unsupported-type/"+kind, append(with(member{Name: "entries/before", Type: "reg", Mode: 0o600, Data: "kept"}), member{Name: "entries/odd", Type: kind, Mode: 0o600, Linkname: "../../outside"}, member{Name: "entries/after", Type: "reg", Mode: 0o600, Data: "not-written"}))
	}

	over := int64(1<<30 + 1)
	cases = append(cases, run("oversize-member-header", "gzip", tar.FormatUnknown,
		with(member{Name: "entries/huge", Type: "reg", Mode: 0o600, Size: &over}), false, nil, ""))
	exact := int64(1 << 30)
	cases = append(cases, run("exact-limit-member-truncated", "gzip", tar.FormatUnknown,
		with(member{Name: "entries/big", Type: "reg", Mode: 0o600, Size: &exact}), false, nil, ""))
	cases = append(cases, run("truncated-member-data", "gzip", tar.FormatUnknown,
		with(member{Name: "entries/cut", Type: "reg", Mode: 0o600, Size: i64(64)}), false, nil, ""))
	cases = append(cases, run("negative-mode-file", "gzip", tar.FormatGNU,
		with(member{Name: "entries/neg", Type: "reg", Mode: -1, Data: "x"}), true, nil, ""))
	cases = append(cases, run("negative-mode-dir", "gzip", tar.FormatGNU,
		with(member{Name: "entries/negdir", Type: "dir", Mode: -1}), true, nil, ""))

	cases = append(cases, run("not-gzip", "raw", tar.FormatUnknown, with(), true, nil, ""))
	cases = append(cases, run("gzip-truncated", "gzip-cut", tar.FormatUnknown, with(member{Name: "entries/a", Type: "reg", Mode: 0o600, Data: strings.Repeat("payload-", 200)}), true, nil, ""))
	cases = append(cases, run("gzip-corrupt-body", "gzip-corrupt", tar.FormatUnknown, with(member{Name: "entries/a", Type: "reg", Mode: 0o600, Data: strings.Repeat("payload-", 200)}), true, nil, ""))
	cases = append(cases, run("tar-no-trailer", "gzip", tar.FormatUnknown, with(), false, nil, ""))

	cases = append(cases, run("empty-file", "empty", tar.FormatUnknown, with(), true, nil, ""))
	cases = append(cases, run("gzip-short-header", "gzip-short-header", tar.FormatUnknown, with(), true, nil, ""))
	cases = append(cases, runAt("gzip-of-garbage-tar", "gzip", tar.FormatUnknown, with(), true, nil, "", "vault", false,
		func([]byte) []byte { return bytes.Repeat([]byte("x"), 700) }))
	cases = append(cases, runAt("tar-cut-inside-second-header", "gzip", tar.FormatUnknown, with(), true, nil, "", "vault", false,
		func(data []byte) []byte { return data[:512+512+100] }))
	cases = append(cases, runAt("tar-cut-after-first-header", "gzip", tar.FormatUnknown, with(), true, nil, "", "vault", false,
		func(data []byte) []byte { return data[:512*2] }))
	cases = append(cases, runAt("archive-missing", "gzip", tar.FormatUnknown, with(), true, nil, "", "vault", true, nil))

	// Pre-existing destination state.
	add("existing-symlink-file-target", with(member{Name: "entries/a.age", Type: "reg", Mode: 0o600, Data: "x"}),
		pre{Path: "vault/entries/a.age", Kind: "symlink", Target: "../../outside/escaped"})
	add("existing-symlink-dir-component", with(member{Name: "entries/a.age", Type: "reg", Mode: 0o600, Data: "x"}),
		pre{Path: "vault/entries", Kind: "symlink", Target: "../outside"})
	add("existing-symlink-identity", with(),
		pre{Path: "vault/identity.age", Kind: "symlink", Target: "../outside/identity"})
	add("existing-file-where-dir-goes", with(member{Name: "nested/", Type: "dir", Mode: 0o700}),
		pre{Path: "vault/nested", Kind: "file", Mode: 0o600, Data: "file"})
	add("existing-file-as-parent", with(member{Name: "nested/inner.age", Type: "reg", Mode: 0o600, Data: "x"}),
		pre{Path: "vault/nested", Kind: "file", Mode: 0o600, Data: "file"})
	add("existing-dir-where-file-goes", with(member{Name: "entries/slot", Type: "reg", Mode: 0o600, Data: "x"}),
		pre{Path: "vault/entries/slot", Kind: "dir", Mode: 0o700})
	add("existing-files-overwritten", with(member{Name: "entries/a.age", Type: "reg", Mode: 0o600, Data: "new"}),
		pre{Path: "vault/entries/a.age", Kind: "file", Mode: 0o600, Data: "old"},
		pre{Path: "vault/unrelated.txt", Kind: "file", Mode: 0o600, Data: "stay"})
	add("existing-dangling-symlink-unrelated", with(),
		pre{Path: "vault/stale-link", Kind: "symlink", Target: "missing"})
	add("destination-is-a-file", with(),
		pre{Path: "vault", Kind: "file", Mode: 0o600, Data: "file"})
	cases = append(cases, runAt("destination-ancestor-is-symlink", "gzip", tar.FormatUnknown, with(), true,
		[]pre{{Path: "redirect", Kind: "symlink", Target: "outside"}}, reasonSymlink, "redirect/restored", false, nil))
	// No directory member precedes the file, so Go reaches SafeMkdirAll for the
	// parent of a symlinked component instead of the target-symlink check.
	add("existing-symlink-parent-of-file-member", []member{
		{Name: "identity.age", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "config.yaml", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "entries/a.age", Type: "reg", Mode: 0o600, Data: "payload"},
	}, pre{Path: "vault/entries", Kind: "symlink", Target: "../outside"})
	add("existing-symlink-grandparent-of-file-member", []member{
		{Name: "identity.age", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "config.yaml", Type: "reg", Mode: 0o600, Data: "x"},
		{Name: "entries/deep/a.age", Type: "reg", Mode: 0o600, Data: "payload"},
	}, pre{Path: "vault/entries", Kind: "symlink", Target: "../outside"})
	add("destination-is-a-symlink", with(),
		pre{Path: "vault", Kind: "symlink", Target: "outside"})

	// Read-only directories (Unix permission bits). Go creates and rewrites
	// files in place, so a writable existing file inside a 0500 directory is
	// restored while a new file cannot be created.
	addUnix := func(name string, members []member, setup ...pre) {
		cases = append(cases, run(name, "gzip", tar.FormatUnknown, members, true, setup, reasonPermission))
	}
	regm := func(name, data string) member {
		return member{Name: name, Type: "reg", Mode: 0o600, Data: data}
	}
	addUnix("new-file-in-readonly-dir", with(regm("entries/a.age", "new")),
		pre{Path: "vault/entries", Kind: "dir", Mode: 0o500})
	addUnix("existing-file-in-readonly-dir-rewritten", with(regm("entries/a.age", "new")),
		pre{Path: "vault/entries/a.age", Kind: "file", Mode: 0o600, Data: "old-longer-content"},
		pre{Path: "vault/entries", Kind: "dir", Mode: 0o500})
	addUnix("existing-readonly-file-in-readonly-dir", with(regm("entries/a.age", "new")),
		pre{Path: "vault/entries/a.age", Kind: "file", Mode: 0o400, Data: "old"},
		pre{Path: "vault/entries", Kind: "dir", Mode: 0o500})
	addUnix("existing-readonly-file-in-writable-dir", with(regm("entries/a.age", "new")),
		pre{Path: "vault/entries/a.age", Kind: "file", Mode: 0o400, Data: "old"})

	// Legacy `\0` typeflag: a trailing slash makes archive/tar report a
	// directory, otherwise a regular file. TypeReg keeps a trailing-slash name
	// a file.
	add("legacy-nul-typeflag-trailing-slash-is-dir", with(
		member{Name: "d/", Type: "rega", Mode: 0o755},
		member{Name: "d/x", Type: "reg", Mode: 0o600, Data: "inside"},
	))
	add("legacy-nul-typeflag-regular-file", with(member{Name: "entries/legacy", Type: "rega", Mode: 0o644, Data: "legacy-file"}))
	add("regular-typeflag-trailing-slash-stays-file", with(member{Name: "g/", Type: "reg", Mode: 0o600, Data: "file-named-g"}))

	// A malformed mode field is a header error inside Next(), so it wins over
	// the unsafe member name that follows the same header.
	cases = append(cases, runAt("invalid-mode-field-beats-unsafe-name", "gzip", tar.FormatUnknown,
		with(regm("../outside/escaped", "x")), true, nil, "", "vault", false,
		func(data []byte) []byte { return patchHeaderMode(data, 5, "zzzzzzz\x00") }))
	return cases
}

func hasSymlink(items []pre) bool {
	for _, item := range items {
		if item.Kind == "symlink" {
			return true
		}
	}
	return false
}

func main() {
	check := flag.Bool("check", false, "verify the committed fixture")
	flag.Parse()
	if runtime.GOOS == "windows" {
		fatal(errors.New("restoregen must run on a Unix host; its Unix-only cases pin POSIX symlink semantics"))
	}
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	fatal(err)
	root := strings.TrimSpace(string(rootBytes))
	sources := []string{"cmd/admin/backup.go", "internal/fsutil/createsensitiveoutput.go", "internal/fsutil/reexport.go", "go.mod", "go.sum"}
	_, err = provenance.Verify(root, pinnedOracleCommit, sources)
	fatal(err)
	digest, err := provenance.Digest(root, provenance.EnforcedSources(sources))
	fatal(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/restoregen/main.go"})
	fatal(err)

	writeOrCheckMultistream(root, *check, sources, digest, multistreamGeneratorDigest(root))
	cases := buildCases()
	fixture := struct {
		Commit          string        `json:"commit"`
		SourceFiles     []string      `json:"source_files"`
		SourceDigest    string        `json:"source_digest"`
		GeneratorDigest string        `json:"generator_digest"`
		Cases           []restoreCase `json:"cases"`
	}{pinnedOracleCommit, sources, digest, generatorDigest, cases}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	fatal(encoder.Encode(fixture))
	if *check {
		actual, err := os.ReadFile(filepath.Join(root, fixturePath)) // #nosec G304 -- fixed fixture path under the repository root
		fatal(err)
		if !bytes.Equal(actual, buffer.Bytes()) {
			fatal(errors.New("restore-errors fixture stale: regenerate with restoregen"))
		}
		fmt.Printf("PASS restore oracle (%d cases)\n", len(cases))
		return
	}
	fatal(os.WriteFile(filepath.Join(root, fixturePath), buffer.Bytes(), 0o600))
	fmt.Printf("wrote %s (%d cases)\n", fixturePath, len(cases))
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// rawHeader hand-assembles a ustar header that archive/tar would refuse to
// write. The checksum is computed over the final bytes so Go's reader accepts it.
func rawHeader(m member, size int64) []byte {
	block := make([]byte, 512)
	copy(block[0:100], m.Name)
	copy(block[100:108], fmt.Sprintf("%07o\x00", m.Mode))
	copy(block[108:116], "0000000\x00")
	copy(block[116:124], "0000000\x00")
	copy(block[124:136], fmt.Sprintf("%011o\x00", size))
	copy(block[136:148], "00000000000\x00")
	block[156] = typeflag(m.Type)
	copy(block[157:257], m.Linkname)
	copy(block[257:263], "ustar\x00")
	copy(block[263:265], "00")
	for i := 148; i < 156; i++ {
		block[i] = ' '
	}
	sum := 0
	for _, b := range block {
		sum += int(b)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return block
}

func rawBody(m member) []byte {
	if (m.Type != "reg" && m.Type != "rega") || m.Size != nil {
		return nil
	}
	padded := make([]byte, (len(m.Data)+511)/512*512)
	copy(padded, m.Data)
	return padded
}
