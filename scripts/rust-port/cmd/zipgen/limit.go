package main

// The 100 MiB member limit of the 1PUX and CXF importers
// (`io.ReadAll(io.LimitReader(rc, maxZipEntrySize))`).
//
// Go stops reading at exactly the limit, so a member of exactly that many
// bytes never reaches its end of stream: whether the checksum, the declared
// size or the data descriptor is ever looked at depends on how compress/flate
// hands out its last bytes (it flushes its 32 KiB window and only reports the
// end of the final block together with a non-empty remainder). These cases
// pin the three sizes around the limit through the REAL importers.
//
// Each archive is a single deflate member of zeros. Every input is described
// by a small spec and rebuilt byte for byte by the Rust replay
// (crates/symvault-sync/tests/zip_limit_contract.rs), which checks the SHA-256
// of the archive it built against the one recorded here, so the fixture holds
// no 100 MiB inputs.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	limitFixturePath = "testdata/port/import/zip-limit.json"
	entryLimit       = 100 * 1024 * 1024
)

type limitCase struct {
	ID       string `json:"id"`
	Importer string `json:"importer"`
	// Zeros is the member's uncompressed length.
	Zeros int `json:"zeros"`
	// Variant names how the headers deviate from the true CRC and length.
	Variant string `json:"variant"`
	// ArchiveSHA256 identifies the archive the importer was run on.
	ArchiveSHA256 string   `json:"archive_sha256"`
	Expected      expected `json:"expected"`
}

type limitFixture struct {
	Commit          string      `json:"commit"`
	SourceFiles     []string    `json:"source_files"`
	SourceDigest    string      `json:"source_digest"`
	GeneratorDigest string      `json:"generator_digest"`
	Limit           int         `json:"limit"`
	Cases           []limitCase `json:"cases"`
}

// limitVariants lists the header damage applied to the true CRC and sizes.
var limitVariants = []string{
	"good", "bad-crc", "crc-zero", "size-minus1", "size-plus1", "size-zero", "dd-good", "dd-bad-crc",
}

// zerosDeflate is one final fixed-Huffman block: a literal zero, matches of
// length 258 at distance 1, the remainder as literals, end of block. The
// Rust replay builds the same bytes.
func zerosDeflate(total int) []byte {
	var w bitWriter
	w.header(true, 1)
	w.fixedSym(0)
	rest := total - 1
	for i := 0; i < rest/258; i++ {
		w.fixedSym(285) // length 258
		w.code(0, 5)    // distance 1
	}
	for i := 0; i < rest%258; i++ {
		w.fixedSym(0)
	}
	w.fixedSym(256)
	return w.bytes()
}

// zerosArchive assembles the single-member archive for one variant.
func zerosArchive(imp string, total int, variant string) []byte {
	// Zeros hash to a CRC the generator computes once per size.
	crc := crc32.Update(0, crc32.IEEETable, make([]byte, total))
	data := zerosDeflate(total)
	e := rawEntry{
		name: []byte(memberName(imp)), method: 8, version: 20,
		data: data, crc: crc, csize: uint32(len(data)), usize: uint32(total),
	}
	switch variant {
	case "good":
	case "bad-crc":
		e.crc ^= 1
	case "crc-zero":
		e.crc = 0
	case "size-minus1":
		e.usize--
	case "size-plus1":
		e.usize++
	case "size-zero":
		e.usize = 0
	case "dd-good", "dd-bad-crc":
		e.flags = 8
		descriptorCRC := e.crc
		if variant == "dd-bad-crc" {
			descriptorCRC ^= 1
		}
		e.trailer = le32(le32(le32(le32(nil, 0x08074b50), descriptorCRC), e.csize), e.usize)
	default:
		must(fmt.Errorf("unknown limit variant %s", variant))
	}
	return zipOf([]rawEntry{e}, buildOpts{})
}

func buildLimitCases() []limitCase {
	var cases []limitCase
	for _, imp := range []string{"1pux", "cxf"} {
		for _, total := range []int{entryLimit - 1, entryLimit, entryLimit + 1} {
			for _, variant := range limitVariants {
				archive := zerosArchive(imp, total, variant)
				sum := sha256.Sum256(archive)
				cases = append(cases, limitCase{
					ID:            fmt.Sprintf("limit-%s-%s-%s", imp, strings.ReplaceAll(sizeLabel(total), "+", "plus"), variant),
					Importer:      imp,
					Zeros:         total,
					Variant:       variant,
					ArchiveSHA256: hex.EncodeToString(sum[:]),
					Expected:      run(imp, archive),
				})
			}
		}
	}
	return cases
}

func sizeLabel(total int) string {
	switch {
	case total < entryLimit:
		return "limit-minus1"
	case total == entryLimit:
		return "limit"
	default:
		return "limit-plus1"
	}
}

// writeOrCheckLimit regenerates or verifies the limit fixture.
func writeOrCheckLimit(root string, check bool, sources []string, sourceDigest string) {
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/zipgen/main.go", "scripts/rust-port/cmd/zipgen/limit.go"})
	must(err)
	cases := buildLimitCases()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	must(encoder.Encode(limitFixture{pinnedOracleCommit, sources, sourceDigest, generatorDigest, entryLimit, cases}))
	path := filepath.Join(root, limitFixturePath)
	if check {
		actual, err := os.ReadFile(path) // #nosec G304 -- fixed fixture path under the repository root
		must(err)
		if !bytes.Equal(actual, buffer.Bytes()) {
			must(errors.New("zip-limit fixture stale: regenerate with zipgen"))
		}
		fmt.Printf("PASS zip limit oracle (%d cases)\n", len(cases))
		return
	}
	must(os.WriteFile(path, buffer.Bytes(), 0o600))
	fmt.Printf("wrote %s (%d cases)\n", limitFixturePath, len(cases))
}
