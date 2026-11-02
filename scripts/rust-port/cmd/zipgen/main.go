// Command zipgen freezes how the production Go importers react to damaged zip
// archives (IO-001 residual: every Go `archive/zip` and `compress/flate`
// error, not only `zip: not a valid zip file`).
//
// It hand-assembles zip archives byte by byte (so any header field, the
// central directory, the end record and the deflate stream can be damaged on
// purpose), then runs the REAL 1PUX and CXF importers over each archive and
// records the complete error text or the imported entries. The fixture is
// consumed by crates/symvault-sync/tests/zip_errors_contract.rs.
//
// Verification (-check) is non-writing: it rebuilds every archive, re-runs the
// importers and compares the bytes with the committed fixture. Regeneration is
// the explicit default mode.
package main

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/importer"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit = "ab1fad20166c7658e0f50bdd3b8fdc9185c1a1d4"
	fixturePath        = "testdata/port/import/zip-errors.json"
)

type entry struct {
	Path       string         `json:"path"`
	Data       map[string]any `json:"data"`
	Warnings   []string       `json:"warnings"`
	SecretType string         `json:"secret_type,omitempty"`
}

type expected struct {
	Entries []entry `json:"entries,omitempty"`
	// Error is Go's complete error text.
	Error string `json:"error,omitempty"`
}

type fixtureCase struct {
	ID       string   `json:"id"`
	Importer string   `json:"importer"`
	InputB64 string   `json:"input_b64"`
	Expected expected `json:"expected"`
}

// ---------------------------------------------------------------------------
// Raw zip assembly.

type rawEntry struct {
	name       []byte
	method     uint16
	flags      uint16
	version    uint16 // version made by: creator<<8 | spec version
	attrs      uint32
	data       []byte // bytes stored in the archive (already compressed)
	crc        uint32
	csize      uint32
	usize      uint32
	localExtra []byte
	cdExtra    []byte
	comment    []byte
	trailer    []byte // bytes after the data (data descriptor)
}

func deflateBytes(data []byte) []byte {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	must(err)
	_, err = w.Write(data)
	must(err)
	must(w.Close())
	return buf.Bytes()
}

func sum(data []byte) uint32 { return crc32.ChecksumIEEE(data) }

// newEntry builds a consistent entry: deflate compresses payload, stored keeps it.
func newEntry(name string, payload []byte, deflated bool) rawEntry {
	e := rawEntry{name: []byte(name), version: 20, crc: sum(payload), usize: uint32(len(payload))}
	if deflated {
		e.method = 8
		e.data = deflateBytes(payload)
	} else {
		e.data = payload
	}
	e.csize = uint32(len(e.data))
	return e
}

type buildOpts struct {
	prefix       []byte  // bytes before the first local header
	eocdComment  []byte  // archive comment
	gap          []byte  // bytes between the central directory and the end record
	suffix       []byte  // bytes after the end record
	records      *uint16 // overrides the record count
	cdSize       *uint32
	cdOffset     *uint32
	zip64        bool // emit a zip64 end record + locator and 0xffff markers
	zip64Records *uint64
	zip64Locator *[]byte // overrides the locator bytes
	skipEOCD     bool
}

type layout struct {
	buf      []byte
	local    []int // local header offsets
	cd       []int // central directory header offsets
	cdStart  int
	eocd     int
	zip64End int
}

func le16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }
func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }
func le64(b []byte, v uint64) []byte { return binary.LittleEndian.AppendUint64(b, v) }

func u64(v uint64) *uint64 { return &v }

func zip64Extra(usize, csize, offset *uint64) []byte {
	var body []byte
	if usize != nil {
		body = le64(body, *usize)
	}
	if csize != nil {
		body = le64(body, *csize)
	}
	if offset != nil {
		body = le64(body, *offset)
	}
	out := le16(nil, 1)
	out = le16(out, uint16(len(body)))
	return append(out, body...)
}

func build(entries []rawEntry, o buildOpts) layout {
	var l layout
	var out []byte
	out = append(out, o.prefix...)
	for _, e := range entries {
		l.local = append(l.local, len(out))
		out = le32(out, 0x04034b50)
		out = le16(out, 20)
		out = le16(out, e.flags)
		out = le16(out, e.method)
		out = le16(out, 0)
		out = le16(out, 0x21)
		out = le32(out, e.crc)
		out = le32(out, e.csize)
		out = le32(out, e.usize)
		out = le16(out, uint16(len(e.name)))
		out = le16(out, uint16(len(e.localExtra)))
		out = append(out, e.name...)
		out = append(out, e.localExtra...)
		out = append(out, e.data...)
		out = append(out, e.trailer...)
	}
	l.cdStart = len(out)
	for i, e := range entries {
		l.cd = append(l.cd, len(out))
		out = le32(out, 0x02014b50)
		out = le16(out, e.version)
		out = le16(out, 20)
		out = le16(out, e.flags)
		out = le16(out, e.method)
		out = le16(out, 0)
		out = le16(out, 0x21)
		out = le32(out, e.crc)
		out = le32(out, e.csize)
		out = le32(out, e.usize)
		out = le16(out, uint16(len(e.name)))
		out = le16(out, uint16(len(e.cdExtra)))
		out = le16(out, uint16(len(e.comment)))
		out = le16(out, 0)
		out = le16(out, 0)
		out = le32(out, e.attrs)
		out = le32(out, uint32(l.local[i]-len(o.prefix)))
		out = append(out, e.name...)
		out = append(out, e.cdExtra...)
		out = append(out, e.comment...)
	}
	cdSize := len(out) - l.cdStart
	out = append(out, o.gap...)
	records := uint16(len(entries))
	if o.records != nil {
		records = *o.records
	}
	sizeField := uint32(cdSize)
	if o.cdSize != nil {
		sizeField = *o.cdSize
	}
	offsetField := uint32(l.cdStart - len(o.prefix))
	if o.cdOffset != nil {
		offsetField = *o.cdOffset
	}
	if o.zip64 {
		l.zip64End = len(out)
		count := uint64(len(entries))
		if o.zip64Records != nil {
			count = *o.zip64Records
		}
		out = le32(out, 0x06064b50)
		out = le64(out, 44)
		out = le16(out, 45)
		out = le16(out, 45)
		out = le32(out, 0)
		out = le32(out, 0)
		out = le64(out, count)
		out = le64(out, count)
		out = le64(out, uint64(cdSize))
		out = le64(out, uint64(l.cdStart-len(o.prefix)))
		if o.zip64Locator != nil {
			out = append(out, (*o.zip64Locator)...)
		} else {
			out = le32(out, 0x07064b50)
			out = le32(out, 0)
			out = le64(out, uint64(l.zip64End-len(o.prefix)))
			out = le32(out, 1)
		}
		records, sizeField, offsetField = 0xffff, 0xffff, 0xffffffff
	}
	if !o.skipEOCD {
		l.eocd = len(out)
		out = append(out, 'P', 'K', 5, 6)
		out = le16(out, 0)
		out = le16(out, 0)
		out = le16(out, records)
		out = le16(out, records)
		out = le32(out, sizeField)
		out = le32(out, offsetField)
		out = le16(out, uint16(len(o.eocdComment)))
		out = append(out, o.eocdComment...)
	}
	out = append(out, o.suffix...)
	l.buf = out
	return l
}

func zipOf(entries []rawEntry, o buildOpts) []byte { return build(entries, o).buf }

// ---------------------------------------------------------------------------
// Deflate stream assembly.

type bitWriter struct {
	buf []byte
	acc uint32
	n   uint
}

func (w *bitWriter) bits(v uint32, n uint) {
	for i := uint(0); i < n; i++ {
		w.acc |= ((v >> i) & 1) << w.n
		w.n++
		if w.n == 8 {
			w.buf = append(w.buf, byte(w.acc))
			w.acc, w.n = 0, 0
		}
	}
}

// code writes a Huffman code most-significant bit first.
func (w *bitWriter) code(v uint32, n uint) {
	for i := int(n) - 1; i >= 0; i-- {
		w.bits((v>>uint(i))&1, 1)
	}
}

func (w *bitWriter) bytes() []byte {
	out := append([]byte(nil), w.buf...)
	if w.n > 0 {
		out = append(out, byte(w.acc))
	}
	return out
}

func (w *bitWriter) header(final bool, typ uint32) {
	if final {
		w.bits(1, 1)
	} else {
		w.bits(0, 1)
	}
	w.bits(typ, 2)
}

// fixedLit writes a literal/length symbol with the fixed Huffman code.
func (w *bitWriter) fixedSym(sym int) {
	switch {
	case sym < 144:
		w.code(uint32(0x30+sym), 8)
	case sym < 256:
		w.code(uint32(0x190+sym-144), 9)
	case sym < 280:
		w.code(uint32(sym-256), 7)
	default:
		w.code(uint32(0xc0+sym-280), 8)
	}
}

func storedBlock(final bool, data []byte, nlen uint16) []byte {
	var w bitWriter
	w.header(final, 0)
	out := w.bytes()
	out = le16(out, uint16(len(data)))
	out = le16(out, nlen)
	return append(out, data...)
}

// fixedStream is a fixed-Huffman block built from literal bytes and raw symbols.
type fixedItem struct {
	lit      int // literal byte, or -1
	sym      int // length symbol when lit < 0
	extra    uint32
	extraBit uint
	dist     int // distance code (5 bits, MSB first)
	dExtra   uint32
	dBits    uint
}

func fixedBlock(final bool, items []fixedItem, endMarker bool) []byte {
	var w bitWriter
	w.header(final, 1)
	for _, it := range items {
		if it.lit >= 0 {
			w.fixedSym(it.lit)
			continue
		}
		w.fixedSym(it.sym)
		w.bits(it.extra, it.extraBit)
		w.code(uint32(it.dist), 5)
		w.bits(it.dExtra, it.dBits)
	}
	if endMarker {
		w.fixedSym(256)
	}
	return w.bytes()
}

func lits(s string) []fixedItem {
	items := make([]fixedItem, 0, len(s))
	for _, c := range []byte(s) {
		items = append(items, fixedItem{lit: int(c)})
	}
	return items
}

// canonical assigns deflate canonical Huffman codes for the given lengths.
func canonical(lengths []int) []uint32 {
	count := map[int]int{}
	maxLen := 0
	for _, n := range lengths {
		if n > 0 {
			count[n]++
			if n > maxLen {
				maxLen = n
			}
		}
	}
	next := map[int]uint32{}
	code := uint32(0)
	for n := 1; n <= maxLen; n++ {
		code = (code + uint32(count[n-1])) << 1
		if n == 1 {
			code = 0
		}
		next[n] = code
	}
	codes := make([]uint32, len(lengths))
	for i, n := range lengths {
		if n > 0 {
			codes[i] = next[n]
			next[n]++
		}
	}
	return codes
}

// dynamicBlock writes a dynamic block header. clLens gives the code-length
// alphabet's lengths (19 entries); lens is the literal/length+distance length
// sequence given as (symbol, extra) items over that alphabet.
type clItem struct {
	sym   int
	extra uint32
}

var clOrder = []int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

func dynamicBlock(final bool, hlit, hdist, hclen int, clLens []int, items []clItem, body func(*bitWriter)) []byte {
	var w bitWriter
	w.header(final, 2)
	w.bits(uint32(hlit), 5)
	w.bits(uint32(hdist), 5)
	w.bits(uint32(hclen), 4)
	for i := 0; i < hclen+4; i++ {
		w.bits(uint32(clLens[clOrder[i]]), 3)
	}
	codes := canonical(clLens)
	for _, it := range items {
		w.code(codes[it.sym], uint(clLens[it.sym]))
		switch it.sym {
		case 16:
			w.bits(it.extra, 2)
		case 17:
			w.bits(it.extra, 3)
		case 18:
			w.bits(it.extra, 7)
		}
	}
	if body != nil {
		body(&w)
	}
	return w.bytes()
}

// ---------------------------------------------------------------------------
// Case collection.

type caseSet struct {
	cases []fixtureCase
	seen  map[string]bool
	ids   map[string]bool
}

func newCaseSet() *caseSet { return &caseSet{seen: map[string]bool{}, ids: map[string]bool{}} }

func run(imp string, input []byte) expected {
	format := importer.Format1Password
	if imp == "cxf" {
		format = importer.FormatCXF
	}
	parser, err := importer.New(format)
	must(err)
	got, err := parser.Parse(bytes.NewReader(input))
	if err != nil {
		return expected{Error: err.Error()}
	}
	out := expected{Entries: make([]entry, 0, len(got))}
	for _, item := range got {
		secret := ""
		if item.SecretMetadata != nil {
			secret = string(item.SecretMetadata.Type)
		}
		out.Entries = append(out.Entries, entry{item.Path, item.Data, item.Warnings, secret})
	}
	return out
}

func (c *caseSet) add(imp, id string, input []byte) {
	key := imp + "\x00" + string(input)
	if c.seen[key] {
		return
	}
	if c.ids[imp+id] {
		must(fmt.Errorf("duplicate case id %s", id))
	}
	c.seen[key] = true
	c.ids[imp+id] = true
	c.cases = append(c.cases, fixtureCase{
		ID:       "zip-" + imp + "-" + id,
		Importer: imp,
		InputB64: base64.StdEncoding.EncodeToString(input),
		Expected: run(imp, input),
	})
}

// both adds the same archive under both importers' ids.
func (c *caseSet) both(id string, input []byte) {
	c.add("1pux", id, input)
	c.add("cxf", id, input)
}

// ---------------------------------------------------------------------------
// Payloads.

func onePuxPayload() []byte {
	return []byte(`{"accounts":[{"vaults":[{"items":[` +
		`{"categoryUuid":"001","title":"one","details":{"loginFields":[{"designation":"username","value":"u1"},{"designation":"password","value":"p1"}]},"overview":{"urls":[{"url":"https://a.test"}],"tags":["t"]}},` +
		`{"categoryUuid":"001","title":"two","details":{"loginFields":[{"designation":"username","value":"u2"},{"designation":"password","value":"p2"}]},"overview":{"urls":[{"url":"https://b.test"}],"tags":["t"]}}` +
		`]}]}]}`)
}

func cxfPayload() []byte {
	field := func(v string) map[string]any { return map[string]any{"value": v} }
	doc := map[string]any{"accounts": []any{map[string]any{"items": []any{
		map[string]any{"id": "a", "title": "Alpha", "credentials": []any{map[string]any{"type": "basic-auth", "username": field("ua"), "password": field("pa")}}},
		map[string]any{"id": "b", "title": "Beta", "credentials": []any{map[string]any{"type": "basic-auth", "username": field("ub"), "password": field("pb")}}},
	}}}}
	out, err := json.Marshal(doc)
	must(err)
	return out
}

const emptyDoc = `{"accounts":[]}`

func memberName(imp string) string {
	if imp == "cxf" {
		return "cxf.json"
	}
	return "export.json"
}

func payloadFor(imp string) []byte {
	if imp == "cxf" {
		return cxfPayload()
	}
	return onePuxPayload()
}

// ---------------------------------------------------------------------------
// Sweeps: damage every byte of a base archive.

func (c *caseSet) sweep(imp, name string, base []byte, tags ...string) {
	for n := 0; n < len(base); n++ {
		c.add(imp, fmt.Sprintf("%s-trunc-%04d", name, n), base[:n])
	}
	for pos := range base {
		for _, mode := range []struct {
			tag string
			fn  func(byte) byte
		}{
			{"ff", func(byte) byte { return 0xff }},
			{"x01", func(b byte) byte { return b ^ 0x01 }},
			{"x80", func(b byte) byte { return b ^ 0x80 }},
		} {
			if !contains(tags, mode.tag) {
				continue
			}
			v := mode.fn(base[pos])
			if v == base[pos] {
				continue
			}
			mutated := append([]byte(nil), base...)
			mutated[pos] = v
			c.add(imp, fmt.Sprintf("%s-%s-%04d", name, mode.tag, pos), mutated)
		}
	}
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------

func buildCases() []fixtureCase {
	c := newCaseSet()
	u16p := func(v uint16) *uint16 { return &v }
	u32p := func(v uint32) *uint32 { return &v }

	for _, imp := range []string{"1pux", "cxf"} {
		name := memberName(imp)
		payload := payloadFor(imp)
		empty := []byte(emptyDoc)

		deflated := newEntry(name, payload, true)
		stored := newEntry(name, payload, false)
		// Healthy archives.
		c.add(imp, "ok-deflate", zipOf([]rawEntry{deflated}, buildOpts{}))
		c.add(imp, "ok-stored", zipOf([]rawEntry{stored}, buildOpts{}))
		c.add(imp, "ok-empty-doc", zipOf([]rawEntry{newEntry(name, empty, true)}, buildOpts{}))
		c.add(imp, "ok-eocd-comment", zipOf([]rawEntry{deflated}, buildOpts{eocdComment: []byte("hello")}))
		c.add(imp, "ok-sfx-prefix", zipOf([]rawEntry{deflated}, buildOpts{prefix: []byte("#!/bin/sh\nexit 0\n")}))
		c.add(imp, "ok-trailing-garbage-small", zipOf([]rawEntry{deflated}, buildOpts{suffix: bytes.Repeat([]byte{0}, 100)}))
		c.add(imp, "trailing-garbage-1100", zipOf([]rawEntry{deflated}, buildOpts{suffix: bytes.Repeat([]byte{0}, 1100)}))
		c.add(imp, "trailing-garbage-66000", zipOf([]rawEntry{deflated}, buildOpts{suffix: bytes.Repeat([]byte{0}, 66000)}))
		c.add(imp, "trailing-garbage-60000", zipOf([]rawEntry{deflated}, buildOpts{suffix: bytes.Repeat([]byte{0}, 60000)}))
		c.add(imp, "empty-input", nil)
		c.add(imp, "tiny-input", []byte("PK"))
		c.add(imp, "eocd-only", zipOf(nil, buildOpts{}))
		c.add(imp, "eocd-only-comment", zipOf(nil, buildOpts{eocdComment: []byte("x")}))
		eocdTruncComment := zipOf([]rawEntry{deflated}, buildOpts{eocdComment: []byte("abcdef")})
		c.add(imp, "eocd-truncated-comment", eocdTruncComment[:len(eocdTruncComment)-3])
		c.add(imp, "eocd-sig-in-comment", zipOf([]rawEntry{deflated}, buildOpts{eocdComment: []byte("PK\x05\x06xxxxxxxxxxxxxxxxxx")}))
		c.add(imp, "eocd-twice", zipOf([]rawEntry{deflated}, buildOpts{suffix: zipOf(nil, buildOpts{})}))

		// End record fields.
		c.add(imp, "records-too-few", zipOf([]rawEntry{deflated, stored}, buildOpts{records: u16p(1)}))
		c.add(imp, "records-too-many", zipOf([]rawEntry{deflated}, buildOpts{records: u16p(2)}))
		c.add(imp, "records-zero", zipOf([]rawEntry{deflated}, buildOpts{records: u16p(0)}))
		c.add(imp, "cd-offset-past-end", zipOf([]rawEntry{deflated}, buildOpts{cdOffset: u32p(100000)}))
		c.add(imp, "cd-offset-zero", zipOf([]rawEntry{deflated}, buildOpts{cdOffset: u32p(0)}))
		c.add(imp, "cd-offset-into-data", zipOf([]rawEntry{deflated}, buildOpts{cdOffset: u32p(10)}))
		c.add(imp, "cd-size-zero", zipOf([]rawEntry{deflated}, buildOpts{cdSize: u32p(0)}))
		c.add(imp, "cd-size-huge", zipOf([]rawEntry{deflated}, buildOpts{cdSize: u32p(0x7fffffff)}))
		c.add(imp, "cd-size-big-shifts-base", zipOf([]rawEntry{deflated}, buildOpts{cdSize: u32p(5), prefix: []byte("0123456789")}))
		c.add(imp, "cd-offset-ffffffff-no-zip64", zipOf([]rawEntry{deflated}, buildOpts{cdOffset: u32p(0xffffffff)}))
		c.add(imp, "gap-before-eocd", zipOf([]rawEntry{deflated}, buildOpts{gap: []byte("gap")}))
		c.add(imp, "gap-before-eocd-prefix", zipOf([]rawEntry{deflated}, buildOpts{gap: []byte("gap"), prefix: []byte("pre")}))
		c.add(imp, "prefix-without-sfx-offsets", zipOf([]rawEntry{deflated}, buildOpts{prefix: []byte("0123456789"), cdOffset: u32p(5)}))

		// Central directory damage.
		l := build([]rawEntry{deflated, stored}, buildOpts{})
		second := l.cd[1]
		// Cut the archive in the second central header, with the end record kept
		// reachable by re-appending it.
		eocd := l.buf[l.eocd:]
		for _, cut := range []int{0, 10, 46, 46 + len(name) - 3, 46 + len(name)} {
			buf := append([]byte(nil), l.buf[:second+cut]...)
			c.add(imp, fmt.Sprintf("cd-second-cut-%d-then-eocd", cut), append(buf, eocd...))
			c.add(imp, fmt.Sprintf("cd-second-cut-%d", cut), buf)
		}

		// Deflate/stored/size/CRC fields.
		with := func(f func(*rawEntry)) rawEntry {
			e := deflated
			f(&e)
			return e
		}
		withStored := func(f func(*rawEntry)) rawEntry {
			e := stored
			f(&e)
			return e
		}
		one := func(e rawEntry) []byte { return zipOf([]rawEntry{e}, buildOpts{}) }

		c.add(imp, "crc-mismatch-deflate", one(with(func(e *rawEntry) { e.crc ^= 1 })))
		c.add(imp, "crc-mismatch-stored", one(withStored(func(e *rawEntry) { e.crc ^= 1 })))
		c.add(imp, "crc-zero-skips-check", one(with(func(e *rawEntry) { e.crc = 0 })))
		c.add(imp, "crc-zero-skips-check-stored", one(withStored(func(e *rawEntry) { e.crc = 0 })))
		c.add(imp, "usize-smaller-deflate", one(with(func(e *rawEntry) { e.usize-- })))
		c.add(imp, "usize-smaller-stored", one(withStored(func(e *rawEntry) { e.usize-- })))
		c.add(imp, "usize-larger-deflate", one(with(func(e *rawEntry) { e.usize++ })))
		c.add(imp, "usize-larger-stored", one(withStored(func(e *rawEntry) { e.usize++ })))
		c.add(imp, "usize-zero", one(with(func(e *rawEntry) { e.usize = 0 })))
		c.add(imp, "usize-zero-stored", one(withStored(func(e *rawEntry) { e.usize = 0 })))
		c.add(imp, "usize-huge-declared", one(with(func(e *rawEntry) { e.usize = 200 * 1024 * 1024 })))
		c.add(imp, "usize-huge-declared-stored", one(withStored(func(e *rawEntry) { e.usize = 200 * 1024 * 1024 })))
		c.add(imp, "usize-ffffffff-no-zip64", one(with(func(e *rawEntry) { e.usize = 0xffffffff })))
		c.add(imp, "csize-smaller-deflate", one(with(func(e *rawEntry) { e.csize-- })))
		c.add(imp, "csize-smaller-stored", one(withStored(func(e *rawEntry) { e.csize-- })))
		c.add(imp, "csize-larger-deflate", one(with(func(e *rawEntry) { e.csize += 7 })))
		c.add(imp, "csize-larger-stored", one(withStored(func(e *rawEntry) { e.csize += 7 })))
		c.add(imp, "csize-past-file-end", one(with(func(e *rawEntry) { e.csize = 100000 })))
		c.add(imp, "csize-zero-deflate", one(with(func(e *rawEntry) { e.csize = 0 })))
		c.add(imp, "csize-zero-stored", one(withStored(func(e *rawEntry) { e.csize = 0 })))
		c.add(imp, "csize-ffffffff-no-zip64", one(with(func(e *rawEntry) { e.csize = 0xffffffff })))

		// Zip64 extra fields.
		c.add(imp, "zip64-extra-sizes-ok", one(with(func(e *rawEntry) {
			e.usize, e.csize = 0xffffffff, 0xffffffff
			e.cdExtra = zip64Extra(u64(uint64(len(payload))), u64(uint64(len(deflated.data))), nil)
		})))
		c.add(imp, "zip64-extra-usize-only", one(with(func(e *rawEntry) {
			e.usize = 0xffffffff
			e.cdExtra = zip64Extra(u64(uint64(len(payload))), nil, nil)
		})))
		c.add(imp, "zip64-extra-too-short", one(with(func(e *rawEntry) {
			e.usize, e.csize = 0xffffffff, 0xffffffff
			e.cdExtra = append(le16(le16(nil, 1), 8), make([]byte, 8)...)
		})))
		c.add(imp, "zip64-extra-csize-short", one(with(func(e *rawEntry) {
			e.csize = 0xffffffff
			e.cdExtra = append(le16(le16(nil, 1), 4), make([]byte, 4)...)
		})))
		c.add(imp, "zip64-extra-csize-huge", one(with(func(e *rawEntry) {
			e.csize = 0xffffffff
			e.cdExtra = zip64Extra(nil, u64(1<<63), nil)
		})))
		c.add(imp, "zip64-extra-csize-huge-stored", one(withStored(func(e *rawEntry) {
			e.csize = 0xffffffff
			e.cdExtra = zip64Extra(nil, u64(1<<63), nil)
		})))
		c.add(imp, "zip64-extra-csize-huge-stored-dd", one(withStored(func(e *rawEntry) {
			e.csize = 0xffffffff
			e.flags = 8
			e.cdExtra = zip64Extra(nil, u64(1<<63+5), nil)
		})))
		c.add(imp, "zip64-extra-csize-large-positive", one(with(func(e *rawEntry) {
			e.csize = 0xffffffff
			e.cdExtra = zip64Extra(nil, u64(1<<40), nil)
		})))
		c.add(imp, "zip64-extra-offset-negative", func() []byte {
			e := deflated
			// header offset marker
			buf := build([]rawEntry{e}, buildOpts{})
			cd := buf.cd[0]
			out := append([]byte(nil), buf.buf...)
			binary.LittleEndian.PutUint32(out[cd+42:], 0xffffffff)
			// splice the extra field in after the name
			extra := zip64Extra(nil, nil, u64(1<<63))
			head := append([]byte(nil), out[:cd+46+len(e.name)]...)
			binary.LittleEndian.PutUint16(head[cd+30:], uint16(len(extra)))
			tail := out[cd+46+len(e.name):]
			return append(append(head, extra...), tail...)
		}())
		c.add(imp, "zip64-extra-offset-no-field", func() []byte {
			buf := build([]rawEntry{deflated}, buildOpts{})
			out := append([]byte(nil), buf.buf...)
			binary.LittleEndian.PutUint32(out[buf.cd[0]+42:], 0xffffffff)
			return out
		}())
		c.add(imp, "zip64-extra-truncated-block", one(with(func(e *rawEntry) {
			e.cdExtra = []byte{1, 0, 40, 0, 1, 2, 3}
		})))
		c.add(imp, "extra-unknown-and-ntfs", one(with(func(e *rawEntry) {
			e.cdExtra = append(append(le16(le16(nil, 0x000a), 4), 0, 0, 0, 0), le16(le16(nil, 0x5455), 5)...)
			e.cdExtra = append(e.cdExtra, 1, 0, 0, 0, 0)
		})))
		c.add(imp, "extra-trailing-3-bytes", one(with(func(e *rawEntry) { e.cdExtra = []byte{1, 2, 3} })))

		// Zip64 end record.
		c.add(imp, "zip64-end-ok", zipOf([]rawEntry{deflated}, buildOpts{zip64: true}))
		c.add(imp, "zip64-end-wrong-records", zipOf([]rawEntry{deflated}, buildOpts{zip64: true, zip64Records: u64(3)}))
		badLoc := func(f func([]byte)) *[]byte {
			loc := le32(nil, 0x07064b50)
			loc = le32(loc, 0)
			loc = le64(loc, 0)
			loc = le32(loc, 1)
			f(loc)
			return &loc
		}
		c.add(imp, "zip64-locator-bad-sig", zipOf([]rawEntry{deflated}, buildOpts{zip64: true, zip64Locator: badLoc(func(b []byte) { b[0] = 'X' })}))
		c.add(imp, "zip64-locator-disk-nonzero", zipOf([]rawEntry{deflated}, buildOpts{zip64: true, zip64Locator: badLoc(func(b []byte) { b[4] = 1 })}))
		c.add(imp, "zip64-locator-disks-not-one", zipOf([]rawEntry{deflated}, buildOpts{zip64: true, zip64Locator: badLoc(func(b []byte) { b[16] = 2 })}))
		c.add(imp, "zip64-locator-offset-zero", zipOf([]rawEntry{deflated}, buildOpts{zip64: true, zip64Locator: badLoc(func(b []byte) {})}))
		c.add(imp, "zip64-locator-offset-negative", zipOf([]rawEntry{deflated}, buildOpts{zip64: true, zip64Locator: badLoc(func(b []byte) { b[15] = 0x80 })}))
		c.add(imp, "zip64-locator-offset-past-end", zipOf([]rawEntry{deflated}, buildOpts{zip64: true, zip64Locator: badLoc(func(b []byte) { b[8] = 0xff; b[9] = 0xff })}))
		// A zip64 marker with no locator in front of the end record.
		c.add(imp, "zip64-marker-no-locator", func() []byte {
			return zipOf([]rawEntry{deflated}, buildOpts{records: u16p(0xffff)})
		}())
		c.add(imp, "zip64-marker-size-ffff", zipOf([]rawEntry{deflated}, buildOpts{cdSize: u32p(0xffff)}))

		// Local header damage.
		lb := build([]rawEntry{deflated}, buildOpts{})
		patch := func(off int, v []byte) []byte {
			out := append([]byte(nil), lb.buf...)
			copy(out[off:], v)
			return out
		}
		c.add(imp, "local-sig-bad", patch(lb.local[0], []byte{'X'}))
		c.add(imp, "local-name-len-longer", patch(lb.local[0]+26, le16(nil, 200)))
		c.add(imp, "local-extra-len-longer", patch(lb.local[0]+28, le16(nil, 50)))
		c.add(imp, "local-extra-len-huge", patch(lb.local[0]+28, le16(nil, 0xffff)))
		c.add(imp, "local-offset-past-end", patch(lb.cd[0]+42, le32(nil, 100000)))
		c.add(imp, "local-offset-near-end", patch(lb.cd[0]+42, le32(nil, uint32(len(lb.buf)-10))))
		c.add(imp, "local-offset-into-cd", patch(lb.cd[0]+42, le32(nil, uint32(lb.cd[0]))))
		c.add(imp, "local-offset-ffffffff", patch(lb.cd[0]+42, le32(nil, 0xffffffff)))
		c.add(imp, "local-with-extra-data", one(with(func(e *rawEntry) { e.localExtra = []byte("0123456789") })))
		c.add(imp, "local-crc-differs-ignored", patch(lb.local[0]+14, le32(nil, 0x12345678)))
		c.add(imp, "local-method-differs-ignored", patch(lb.local[0]+8, le16(nil, 0)))
		c.add(imp, "local-flags-differs-ignored", patch(lb.local[0]+6, le16(nil, 8)))

		// Compression methods.
		for _, method := range []uint16{1, 2, 6, 9, 10, 12, 14, 93, 95, 98, 99} {
			c.add(imp, fmt.Sprintf("method-%d", method), one(with(func(e *rawEntry) { e.method = method })))
		}
		c.add(imp, "method-store-with-deflate-data", one(with(func(e *rawEntry) { e.method = 0 })))
		c.add(imp, "method-deflate-with-stored-data", one(withStored(func(e *rawEntry) { e.method = 8 })))

		// Data descriptors.
		descriptor := func(sig bool, crc uint32) []byte {
			var d []byte
			if sig {
				d = le32(d, 0x08074b50)
			}
			d = le32(d, crc)
			d = le32(d, uint32(len(deflated.data)))
			return le32(d, uint32(len(payload)))
		}
		ddEntry := func(e rawEntry, trailer []byte) rawEntry {
			e.flags = 8
			e.trailer = trailer
			return e
		}
		c.add(imp, "dd-sig-ok", one(ddEntry(deflated, descriptor(true, deflated.crc))))
		c.add(imp, "dd-nosig-ok", one(ddEntry(deflated, descriptor(false, deflated.crc))))
		c.add(imp, "dd-stored-ok", one(ddEntry(stored, descriptor(true, stored.crc))))
		c.add(imp, "dd-crc-mismatch", one(ddEntry(deflated, descriptor(true, deflated.crc^1))))
		c.add(imp, "dd-nosig-crc-mismatch", one(ddEntry(deflated, descriptor(false, deflated.crc^1))))
		c.add(imp, "dd-header-crc-zero", one(ddEntry(with(func(e *rawEntry) { e.crc = 0 }), descriptor(true, 0))))
		c.add(imp, "dd-header-crc-differs", one(ddEntry(with(func(e *rawEntry) { e.crc ^= 1 }), descriptor(true, deflated.crc))))
		c.add(imp, "dd-missing", one(ddEntry(deflated, nil)))
		c.add(imp, "dd-short-3", one(ddEntry(deflated, []byte{1, 2, 3})))
		c.add(imp, "dd-short-sig-only", one(ddEntry(deflated, le32(nil, 0x08074b50))))
		c.add(imp, "dd-short-sig-and-crc", one(ddEntry(deflated, append(le32(nil, 0x08074b50), le32(nil, deflated.crc)...))))
		c.add(imp, "dd-nosig-short-8", one(ddEntry(deflated, append(le32(nil, deflated.crc), 1, 2, 3, 4))))
		c.add(imp, "dd-usize-mismatch", one(ddEntry(with(func(e *rawEntry) { e.usize-- }), descriptor(true, deflated.crc))))
		c.add(imp, "dd-crc-zero-no-descriptor-check", one(ddEntry(with(func(e *rawEntry) { e.crc = 0 }), descriptor(true, deflated.crc))))

		// Names, directories and selection.
		c.add(imp, "name-nested", zipOf([]rawEntry{newEntry("a/b/"+name, payload, true)}, buildOpts{}))
		c.add(imp, "name-upper", zipOf([]rawEntry{newEntry(strings.ToUpper(name), payload, true)}, buildOpts{}))
		c.add(imp, "name-leading-slash", zipOf([]rawEntry{newEntry("/"+name, payload, true)}, buildOpts{}))
		c.add(imp, "name-backslash", zipOf([]rawEntry{newEntry("dir\\"+name, payload, true)}, buildOpts{}))
		c.add(imp, "name-dotdot", zipOf([]rawEntry{newEntry("../"+name, payload, true)}, buildOpts{}))
		c.add(imp, "name-suffix-only", zipOf([]rawEntry{newEntry("x"+name, payload, true)}, buildOpts{}))
		c.add(imp, "name-empty", zipOf([]rawEntry{newEntry("", payload, true)}, buildOpts{}))
		c.add(imp, "name-latin1", zipOf([]rawEntry{newEntry("caf\xe9/"+name, payload, true)}, buildOpts{}))
		c.add(imp, "name-dir-slash", zipOf([]rawEntry{newEntry(name+"/", nil, false)}, buildOpts{}))
		c.add(imp, "dir-then-file", zipOf([]rawEntry{newEntry("d/", nil, false), deflated}, buildOpts{}))
		unix := with(func(e *rawEntry) {
			e.version = 3<<8 | 20
			e.attrs = 0o040755 << 16
		})
		c.add(imp, "attr-unix-dir-named-file", one(unix))
		c.add(imp, "attr-unix-file", one(with(func(e *rawEntry) { e.version = 3<<8 | 20; e.attrs = 0o100644 << 16 })))
		c.add(imp, "attr-macosx-dir", one(with(func(e *rawEntry) { e.version = 19<<8 | 20; e.attrs = 0o040755 << 16 })))
		c.add(imp, "attr-unix-symlink", one(with(func(e *rawEntry) { e.version = 3<<8 | 20; e.attrs = 0o120777 << 16 })))
		c.add(imp, "attr-msdos-dir", one(with(func(e *rawEntry) { e.version = 0<<8 | 20; e.attrs = 0x10 })))
		c.add(imp, "attr-ntfs-dir", one(with(func(e *rawEntry) { e.version = 11<<8 | 20; e.attrs = 0x10 })))
		c.add(imp, "attr-vfat-dir", one(with(func(e *rawEntry) { e.version = 14<<8 | 20; e.attrs = 0x10 })))
		c.add(imp, "attr-other-creator-dir", one(with(func(e *rawEntry) { e.version = 7<<8 | 20; e.attrs = 0x10 | 0o040755<<16 })))
		c.add(imp, "attr-msdos-readonly", one(with(func(e *rawEntry) { e.attrs = 0x01 })))

		// Two members.
		other := newEntry("other/"+name, empty, true)
		c.add(imp, "two-first-valid", zipOf([]rawEntry{deflated, other}, buildOpts{}))
		c.add(imp, "two-first-broken", zipOf([]rawEntry{with(func(e *rawEntry) { e.crc ^= 1 }), other}, buildOpts{}))
		c.add(imp, "two-second-broken", zipOf([]rawEntry{deflated, newEntry("zz/"+name, empty, true)}, buildOpts{}))
		c.add(imp, "two-first-unsupported-method", zipOf([]rawEntry{with(func(e *rawEntry) { e.method = 12 }), other}, buildOpts{}))
		c.add(imp, "two-same-name", zipOf([]rawEntry{newEntry(name, empty, true), deflated}, buildOpts{}))
		c.add(imp, "two-unrelated-then-target", zipOf([]rawEntry{newEntry("readme.txt", []byte("hi"), false), deflated}, buildOpts{}))
	}

	// CXF selection and sizes (declared size drives the choice).
	cxfDoc := cxfPayload()
	small := newEntry("small.json", []byte(emptyDoc), true)
	big := newEntry("big.json", cxfDoc, true)
	c.add("cxf", "select-largest", zipOf([]rawEntry{small, big}, buildOpts{}))
	c.add("cxf", "select-largest-lying-usize", zipOf([]rawEntry{func() rawEntry { e := small; e.usize = 100000; return e }(), big}, buildOpts{}))
	c.add("cxf", "select-largest-tie", zipOf([]rawEntry{newEntry("a.json", []byte(emptyDoc), true), newEntry("b.json", []byte(`{"accounts":[ ]}`), true)}, buildOpts{}))
	c.add("cxf", "select-preferred-over-larger", zipOf([]rawEntry{big, newEntry("sub/Payload.JSON", []byte(emptyDoc), true)}, buildOpts{}))
	c.add("cxf", "select-preferred-broken", zipOf([]rawEntry{big, func() rawEntry {
		e := newEntry("payload.json", []byte(emptyDoc), true)
		e.crc ^= 1
		return e
	}()}, buildOpts{}))
	c.add("cxf", "select-dir-skipped", zipOf([]rawEntry{newEntry("dir.json/", nil, false), big}, buildOpts{}))
	c.add("cxf", "select-unix-dir-attr-skipped", zipOf([]rawEntry{func() rawEntry {
		e := newEntry("fake.json", cxfDoc, true)
		e.version = 3<<8 | 20
		e.attrs = 0o040755 << 16
		return e
	}(), small}, buildOpts{}))
	c.add("cxf", "select-uppercase-suffix", zipOf([]rawEntry{newEntry("DATA.JSON", cxfDoc, true)}, buildOpts{}))
	c.add("cxf", "select-json-dot-only", zipOf([]rawEntry{newEntry(".json", cxfDoc, true)}, buildOpts{}))
	c.add("cxf", "select-no-json", zipOf([]rawEntry{newEntry("readme.txt", cxfDoc, true)}, buildOpts{}))
	c.add("cxf", "select-folded-sharp-s", zipOf([]rawEntry{newEntry("cxf.js\u017fon", cxfDoc, true), small}, buildOpts{}))
	c.add("cxf", "select-first-broken-largest-fine", zipOf([]rawEntry{func() rawEntry {
		e := newEntry("a.json", cxfDoc, true)
		e.method = 12
		return e
	}(), small}, buildOpts{}))
	c.add("cxf", "name-unicode-selected", zipOf([]rawEntry{func() rawEntry {
		e := newEntry("caf\u00e9.json", cxfDoc, true)
		e.method = 12
		return e
	}()}, buildOpts{}))

	// Hand-built deflate streams.
	hand := func(id string, data []byte, usize int, plain string) {
		for _, imp := range []string{"1pux", "cxf"} {
			e := rawEntry{name: []byte(memberName(imp)), method: 8, version: 20, data: data, csize: uint32(len(data)),
				usize: uint32(usize), crc: sum([]byte(plain))}
			c.add(imp, id, zipOf([]rawEntry{e}, buildOpts{}))
		}
	}
	doc := emptyDoc
	fixedDoc := func(final bool) []byte { return fixedBlock(final, lits(doc), true) }
	hand("flate-fixed-ok", fixedDoc(true), len(doc), doc)
	hand("flate-fixed-no-final", fixedDoc(false), len(doc), doc)
	hand("flate-fixed-no-end-marker", fixedBlock(true, lits(doc), false), len(doc), doc)
	hand("flate-fixed-then-trailing", append(fixedDoc(true), 1, 2, 3), len(doc), doc)
	hand("flate-empty-input", nil, len(doc), doc)
	hand("flate-block-type-3", []byte{0x07}, len(doc), doc)
	hand("flate-stored-ok", storedBlock(true, []byte(doc), uint16(^len(doc))), len(doc), doc)
	hand("flate-stored-bad-nlen", storedBlock(true, []byte(doc), 0x1234), len(doc), doc)
	hand("flate-stored-truncated-data", storedBlock(true, []byte(doc), uint16(^len(doc)))[:10], len(doc), doc)
	hand("flate-stored-truncated-header", storedBlock(true, []byte(doc), uint16(^len(doc)))[:3], len(doc), doc)
	hand("flate-stored-zero-length-final", storedBlock(true, nil, 0xffff), len(doc), doc)
	hand("flate-stored-zero-length-then-fixed", append(storedBlock(false, nil, 0xffff), fixedDoc(true)...), len(doc), doc)
	hand("flate-two-blocks", append(fixedBlock(false, lits(doc[:5]), true), fixedBlock(true, lits(doc[5:]), true)...), len(doc), doc)
	hand("flate-dist-too-far", fixedBlock(true, append(lits("ab"), fixedItem{lit: -1, sym: 257, dist: 4, dBits: 1, dExtra: 1}), true), 6, "ab")
	hand("flate-dist-zero-history", fixedBlock(true, []fixedItem{{lit: -1, sym: 257, dist: 0}}, true), 3, "")
	hand("flate-dist-code-30", fixedBlock(true, append(lits("ab"), fixedItem{lit: -1, sym: 257, dist: 30}), true), 5, "")
	hand("flate-dist-code-31", fixedBlock(true, append(lits("ab"), fixedItem{lit: -1, sym: 257, dist: 31}), true), 5, "")
	hand("flate-len-sym-286", fixedBlock(true, append(lits("ab"), fixedItem{lit: -1, sym: 286, dist: 0}), true), 5, "")
	hand("flate-len-sym-287", fixedBlock(true, append(lits("ab"), fixedItem{lit: -1, sym: 287, dist: 0}), true), 5, "")
	hand("flate-match-ok", fixedBlock(true, append(lits("abc"), fixedItem{lit: -1, sym: 257, dist: 2}), true), 6, "abcabc")
	hand("flate-match-overlap", fixedBlock(true, append(lits("a"), fixedItem{lit: -1, sym: 258, dist: 0}), true), 5, "aaaaa")
	hand("flate-match-extra-bits-cut", func() []byte {
		b := fixedBlock(true, append(lits("a"), fixedItem{lit: -1, sym: 265, extra: 1, extraBit: 1, dist: 0}), true)
		return b[:len(b)-2]
	}(), 8, "")
	hand("flate-fixed-cut-3", fixedDoc(true)[:3], len(doc), doc)
	hand("flate-fixed-cut-half", fixedDoc(true)[:len(fixedDoc(true))/2], len(doc), doc)

	uniform := func(n int) []int {
		out := make([]int, 19)
		for i := range out {
			out[i] = n
		}
		return out
	}
	// Dynamic block headers.
	cl5 := uniform(0)
	for _, s := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18} {
		cl5[s] = 5
	}
	// 19 symbols at length 5 is an incomplete code (19 < 32).
	hand("flate-dyn-clen-incomplete", dynamicBlock(true, 0, 0, 15, cl5, nil, nil), 5, "")
	over := uniform(1)
	hand("flate-dyn-clen-oversubscribed", dynamicBlock(true, 0, 0, 15, over, nil, nil), 5, "")
	hand("flate-dyn-hlit-too-many", dynamicBlock(true, 30, 0, 0, uniform(0), nil, nil), 5, "")
	hand("flate-dyn-hdist-too-many", dynamicBlock(true, 0, 30, 0, uniform(0), nil, nil), 5, "")
	hand("flate-dyn-truncated-header", dynamicBlock(true, 0, 0, 15, cl5, nil, nil)[:3], 5, "")

	// A well-formed dynamic block: a complete code-length alphabet of 19
	// symbols cannot be built with equal lengths, so use lengths 1,2,3,... and
	// emit only symbols that exist.
	clGood := uniform(0)
	clGood[8] = 1  // length 8
	clGood[0] = 2  // length 0
	clGood[7] = 3  // length 7
	clGood[18] = 4 // long zero run
	clGood[17] = 5 // short zero run
	clGood[16] = 5 // repeat previous
	repeatFirst := []clItem{{sym: 16, extra: 0}}
	hand("flate-dyn-repeat-previous-first", dynamicBlock(true, 0, 0, 15, clGood, repeatFirst, nil), 5, "")
	overRun := []clItem{{sym: 18, extra: 127}, {sym: 18, extra: 127}, {sym: 18, extra: 127}}
	hand("flate-dyn-run-overflow", dynamicBlock(true, 0, 0, 15, clGood, overRun, nil), 5, "")
	// 258 lit/len + 1 dist code lengths: 256 lengths of 8, end-of-block 7, then 0/1 distances.
	// Fill 256 x len8, then bits[256]=7 and one more literal length, distance length 0.
	var fill []clItem
	for i := 0; i < 256; i++ {
		fill = append(fill, clItem{sym: 8})
	}
	fill = append(fill, clItem{sym: 7}) // end-of-block, 7 bits
	fill = append(fill, clItem{sym: 0}) // 257 unused
	fill = append(fill, clItem{sym: 0}) // single distance, unused
	hand("flate-dyn-incomplete-literal-code", dynamicBlock(true, 0, 0, 15, clGood, fill, nil), 5, "")
	// Complete literal code: 255 symbols x8... build: lengths 8 for 0..255 (256 codes of 8 bits) plus
	// end-of-block at 8 bits would oversubscribe; make 255 literals of 8 bits and EOB of 9 bits and 1 other 9.
	var okLen []clItem
	for i := 0; i < 255; i++ {
		okLen = append(okLen, clItem{sym: 8})
	}
	okLen = append(okLen, clItem{sym: 0}) // literal 255 unused
	okLen = append(okLen, clItem{sym: 8}) // EOB 8 bits -> 256 codes of 8: complete
	okLen = append(okLen, clItem{sym: 0}) // 257 unused
	okLen = append(okLen, clItem{sym: 0}) // single distance unused
	dynBody := func(w *bitWriter) {
		// literal codes: symbols 0..254 get canonical codes of 8 bits, EOB (256) code 255.
		lengths := make([]int, 257)
		for i := 0; i < 255; i++ {
			lengths[i] = 8
		}
		lengths[256] = 8
		codes := canonical(lengths)
		for _, ch := range []byte(doc) {
			w.code(codes[ch], 8)
		}
		w.code(codes[256], 8)
	}
	hand("flate-dyn-ok", dynamicBlock(true, 0, 0, 15, clGood, okLen, dynBody), len(doc), doc)
	hand("flate-dyn-truncated-body", dynamicBlock(true, 0, 0, 15, clGood, okLen, func(w *bitWriter) {}), len(doc), doc)
	hand("flate-dyn-unassigned-literal", dynamicBlock(true, 0, 0, 15, clGood, okLen, func(w *bitWriter) {
		lengths := make([]int, 257)
		for i := 0; i < 255; i++ {
			lengths[i] = 8
		}
		lengths[256] = 8
		codes := canonical(lengths)
		w.code(codes[256]+1, 8)
	}), 1, "")

	// Sweeps over healthy archives: truncation at every length and three byte
	// damages at every position (the deflate stream gets a second bit flip).
	body1pux := payloadFor("1pux")
	c.sweep("1pux", "sweep-deflate", zipOf([]rawEntry{newEntry("export.json", body1pux, true)}, buildOpts{}), "ff", "x01", "x80")
	c.sweep("1pux", "sweep-dd", zipOf([]rawEntry{func() rawEntry {
		e := newEntry("export.json", []byte(emptyDoc), false)
		e.flags = 8
		e.trailer = le32(le32(le32(le32(nil, 0x08074b50), e.crc), e.csize), e.usize)
		return e
	}()}, buildOpts{eocdComment: []byte("z")}), "ff", "x01")
	e64 := newEntry("export.json", []byte(emptyDoc), true)
	e64.usize, e64.csize = 0xffffffff, 0xffffffff
	e64.cdExtra = zip64Extra(u64(uint64(len(emptyDoc))), u64(uint64(len(newEntry("export.json", []byte(emptyDoc), true).data))), nil)
	c.sweep("1pux", "sweep-zip64", zipOf([]rawEntry{e64}, buildOpts{zip64: true}), "ff", "x01")
	multi := []rawEntry{
		newEntry("dir/", nil, false),
		newEntry("a.json", []byte(emptyDoc), false),
		newEntry("cxf.json", []byte(emptyDoc), true),
	}
	multi[2].comment = []byte("c")
	c.sweep("cxf", "sweep-multi", zipOf(multi, buildOpts{}), "ff", "x01")
	c.sweep("cxf", "sweep-deflate", zipOf([]rawEntry{newEntry("cxf.json", payloadFor("cxf"), true)}, buildOpts{}), "x01")

	return c.cases
}

type fixture struct {
	Commit          string        `json:"commit"`
	SourceFiles     []string      `json:"source_files"`
	SourceDigest    string        `json:"source_digest"`
	GeneratorDigest string        `json:"generator_digest"`
	Cases           []fixtureCase `json:"cases"`
}

func main() {
	check := flag.Bool("check", false, "verify the committed fixture without writing")
	flag.Parse()
	rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	must(err)
	root := strings.TrimSpace(string(rootBytes))
	sources := []string{
		"internal/importer/cxf.go",
		"internal/importer/importer.go",
		"internal/importer/onepux.go",
		"internal/importer/totp.go",
		"go.mod",
		"go.sum",
	}
	_, err = provenance.Verify(root, pinnedOracleCommit, sources)
	must(err)
	digest, err := provenance.Digest(root, provenance.EnforcedSources(sources))
	must(err)
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/zipgen/main.go"})
	must(err)

	cases := buildCases()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	must(encoder.Encode(fixture{pinnedOracleCommit, sources, digest, generatorDigest, cases}))

	writeOrCheckLimit(root, *check, sources, digest)

	path := filepath.Join(root, fixturePath)
	if *check {
		actual, err := os.ReadFile(path) // #nosec G304 -- fixed fixture path under the repository root
		must(err)
		if !bytes.Equal(actual, buffer.Bytes()) {
			must(errors.New("zip-errors fixture stale: regenerate with zipgen"))
		}
		fmt.Printf("PASS zip oracle (%d cases)\n", len(cases))
		return
	}
	must(os.WriteFile(path, buffer.Bytes(), 0o600))
	fmt.Printf("wrote %s (%d cases)\n", fixturePath, len(cases))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
