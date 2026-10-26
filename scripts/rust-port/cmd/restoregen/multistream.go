package main

// Gzip multistream corpus (IO-002, #1499).
//
// Go's gzip.Reader is multistream by default: concatenated members decode as
// one stream, and whatever follows a member is parsed as the next member
// header. This file records what production RestoreBackup does for tar
// streams split across gzip members and for bytes trailing a member. Unlike
// the main corpus, the exact Go-compressed bytes are stored (gz_b64): where a
// split or a truncation lands inside deflate data depends on the compressor,
// so re-compressing in Rust would not replay the same stream.

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const multistreamFixturePath = "testdata/port/sync/restore-gzip-multistream.json"

type multiCase struct {
	restoreCase
	// GzB64 is the exact archive handed to production Go.
	GzB64 string `json:"gz_b64"`
}

type multiSpec struct {
	name string
	// cuts split the tar payload into gzip members at these byte offsets.
	cuts []int
	// mutate damages the last member: cut, crc, isize or corrupt.
	mutate string
	// tail is appended verbatim after the last member.
	tail []byte
	// tarFn substitutes a different tar payload (nil keeps the default).
	tarFn func([]byte) []byte
	// open omits the tar end-of-archive marker, so the tar reader keeps
	// reading until the gzip layer reports the end of the stream. With the
	// marker, tar stops first and never observes bytes after it.
	open bool
}

func multistreamMembers() []member {
	return with(
		member{Name: "entries/a", Type: "reg", Mode: 0o600, Data: strings.Repeat("payload-", 200)},
		member{Name: "entries/b", Type: "reg", Mode: 0o600, Data: "second-file"},
	)
}

func tarOffset(members []member, count int) int {
	return len(buildTar(members[:count], tar.FormatUnknown, false))
}

func splitMembers(data []byte, cuts []int) [][]byte {
	var parts [][]byte
	last := 0
	for _, cut := range cuts {
		parts = append(parts, data[last:cut])
		last = cut
	}
	return append(parts, data[last:])
}

func mutateMember(packed []byte, how string) []byte {
	out := append([]byte{}, packed...)
	switch how {
	case "":
	case "cut":
		out = out[:len(out)/2]
	case "crc":
		out[len(out)-8] ^= 0xff
	case "isize":
		out[len(out)-4] ^= 0xff
	case "corrupt":
		out[len(out)/2] ^= 0xff
	default:
		panic("unknown mutation " + how)
	}
	return out
}

func multistreamArchive(tarBytes []byte, spec multiSpec) []byte {
	var out []byte
	parts := splitMembers(tarBytes, spec.cuts)
	for index, part := range parts {
		packed := gzipBytes(part)
		if index == len(parts)-1 {
			packed = mutateMember(packed, spec.mutate)
		}
		out = append(out, packed...)
	}
	return append(out, spec.tail...)
}

func describeMulti(spec multiSpec) string {
	text := fmt.Sprintf("gzip-members cuts=%v", spec.cuts)
	if spec.mutate != "" {
		text += " mutate-last=" + spec.mutate
	}
	if len(spec.tail) > 0 {
		text += " tail=" + hex.EncodeToString(spec.tail)
	}
	return text
}

func buildMultistreamCases() []multiCase {
	members := multistreamMembers()
	a, b := tarOffset(members, 3), tarOffset(members, 4)
	full := len(buildTar(members, tar.FormatUnknown, true))
	firstTar := buildTar(with(members[3]), tar.FormatUnknown, true)
	twoTars := func([]byte) []byte {
		return append(append([]byte{}, firstTar...), buildTar([]member{members[4]}, tar.FormatUnknown, true)...)
	}

	var cuts512, cuts700 []int
	for at := 512; at < full; at += 512 {
		cuts512 = append(cuts512, at)
	}
	for at := 700; at < full; at += 700 {
		cuts700 = append(cuts700, at)
	}

	zeros := func(count int) []byte { return make([]byte, count) }
	header := []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0xff}
	specs := []multiSpec{
		// One logical tar stream split across members.
		{name: "split/at-member-boundary", cuts: []int{a}},
		{name: "split/one-byte-into-header", cuts: []int{a + 1}},
		{name: "split/inside-header", cuts: []int{a + 100}},
		{name: "split/inside-first-header", cuts: []int{100}},
		{name: "split/inside-payload", cuts: []int{a + 512 + 700}},
		{name: "split/at-payload-block-boundary", cuts: []int{a + 1024}},
		{name: "split/inside-second-file-payload", cuts: []int{b + 512 + 5}},
		{name: "split/three-members", cuts: []int{a + 300, b + 200}},
		{name: "split/inside-end-marker", cuts: []int{full - 1024 + 100}},
		{name: "split/between-end-marker-blocks", cuts: []int{full - 512}},
		{name: "split/empty-middle-member", cuts: []int{a, a}},
		{name: "split/empty-first-member", cuts: []int{0}},
		{name: "split/empty-last-member", cuts: []int{full}},
		{name: "split/member-per-512-byte-block", cuts: cuts512},
		{name: "split/member-per-700-bytes", cuts: cuts700},
		// A second complete tar after the first end marker: tar stops at the
		// first marker, so the second archive is never read as members.
		{name: "split/two-complete-tars-second-ignored", cuts: []int{len(firstTar)}, tarFn: twoTars},
		// Bytes trailing the final member are parsed as the next member header.
		{name: "trailing/one-zero-byte", tail: zeros(1)},
		{name: "trailing/nine-zero-bytes", tail: zeros(9)},
		{name: "trailing/ten-zero-bytes", tail: zeros(10)},
		{name: "trailing/512-zero-bytes", tail: zeros(512)},
		{name: "trailing/one-byte-1f", tail: []byte{0x1f}},
		{name: "trailing/magic-only", tail: []byte{0x1f, 0x8b}},
		{name: "trailing/magic-and-method", tail: []byte{0x1f, 0x8b, 0x08}},
		{name: "trailing/nine-header-bytes", tail: header[:9]},
		{name: "trailing/header-without-body", tail: header},
		{name: "trailing/header-bad-method", tail: []byte{0x1f, 0x8b, 0x09, 0, 0, 0, 0, 0, 0, 0xff}},
		{name: "trailing/header-reserved-flags", tail: []byte{0x1f, 0x8b, 0x08, 0xe0, 0, 0, 0, 0, 0, 0xff}},
		{name: "trailing/ascii-garbage", tail: []byte("not a gzip member, just trailing text\n")},
		{name: "trailing/newline", tail: []byte("\n")},
		{name: "trailing/gzip-magic-then-zeros", tail: append([]byte{0x1f, 0x8b}, zeros(30)...)},
		{name: "trailing/garbage-after-split-members", cuts: []int{a + 300}, tail: []byte("trailing-garbage")},
		{name: "trailing/zeros-after-split-members", cuts: []int{a + 300}, tail: zeros(16)},
		// Damaged or truncated later members.
		{name: "damaged/truncated-second-member", cuts: []int{a}, mutate: "cut"},
		{name: "damaged/truncated-second-member-inside-payload", cuts: []int{a + 512 + 700}, mutate: "cut"},
		{name: "damaged/truncated-third-member", cuts: []int{a + 300, b + 200}, mutate: "cut"},
		{name: "damaged/crc-second-member", cuts: []int{a}, mutate: "crc"},
		{name: "damaged/isize-second-member", cuts: []int{a}, mutate: "isize"},
		{name: "damaged/corrupt-second-member", cuts: []int{a + 300}, mutate: "corrupt"},
		{name: "damaged/crc-single-member", mutate: "crc"},
		{name: "damaged/isize-single-member", mutate: "isize"},
		{name: "damaged/truncated-second-member-then-garbage", cuts: []int{a}, mutate: "cut", tail: []byte("garbage")},
	}

	// Trailing and checksum cases run twice: with the end marker (tar stops
	// before the gzip layer reaches the damage) and without it (the gzip
	// layer is read to the end of the stream).
	var expanded []multiSpec
	for _, spec := range specs {
		expanded = append(expanded, spec)
		if strings.HasPrefix(spec.name, "trailing/") || strings.Contains(spec.name, "crc-") || strings.Contains(spec.name, "isize-") {
			open := spec
			open.open = true
			open.name = "open-" + spec.name
			expanded = append(expanded, open)
		}
	}
	var cases []multiCase
	for _, spec := range expanded {
		var gz []byte
		item := runAt("multistream/"+spec.name, "raw", tar.FormatUnknown, members, !spec.open, nil, "", "vault", false,
			func(data []byte) []byte {
				if spec.tarFn != nil {
					data = spec.tarFn(data)
				}
				gz = multistreamArchive(data, spec)
				// runAt writes this verbatim ("raw"); the tar payload is
				// restored below.
				return gz
			})
		tarBytes := buildTar(members, tar.FormatUnknown, !spec.open)
		if spec.tarFn != nil {
			tarBytes = spec.tarFn(tarBytes)
		}
		item.Wrap = describeMulti(spec)
		item.TarB64 = base64.StdEncoding.EncodeToString(tarBytes)
		cases = append(cases, multiCase{restoreCase: item, GzB64: base64.StdEncoding.EncodeToString(gz)})
	}
	return cases
}

func writeOrCheckMultistream(root string, check bool, sources []string, digest, generatorDigest string) {
	cases := buildMultistreamCases()
	fixture := struct {
		Commit          string      `json:"commit"`
		SourceFiles     []string    `json:"source_files"`
		SourceDigest    string      `json:"source_digest"`
		GeneratorDigest string      `json:"generator_digest"`
		Cases           []multiCase `json:"cases"`
	}{pinnedOracleCommit, sources, digest, generatorDigest, cases}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	fatal(encoder.Encode(fixture))
	path := filepath.Join(root, multistreamFixturePath)
	if check {
		actual, err := os.ReadFile(path) // #nosec G304 -- fixed fixture path under the repository root
		fatal(err)
		if !bytes.Equal(actual, buffer.Bytes()) {
			fatal(errors.New("restore-gzip-multistream fixture stale: regenerate with restoregen"))
		}
		fmt.Printf("PASS restore multistream oracle (%d cases)\n", len(cases))
		return
	}
	fatal(os.WriteFile(path, buffer.Bytes(), 0o600))
	fmt.Printf("wrote %s (%d cases)\n", multistreamFixturePath, len(cases))
}

// multistreamGeneratorDigest covers both generator files: the case builders
// here and the shared helpers (runAt, snapshot, buildTar) in main.go.
func multistreamGeneratorDigest(root string) string {
	digest, err := provenance.Digest(root, []string{
		"scripts/rust-port/cmd/restoregen/main.go",
		"scripts/rust-port/cmd/restoregen/multistream.go",
	})
	fatal(err)
	return digest
}
