// Command gitwinnergen freezes the GIT-003 version-winner contract from the
// pinned Go oracle.
//
// The existing sync fixture pins one conflict case with versions 1 and 2, which
// proves the conflict copy is written but says nothing about how the winner is
// chosen. WinnerByVersion has three tiers — version, then Updated, then a
// canonical-JSON tiebreak — and only the first was covered. This generator calls
// the production function directly for every tier, including the ties that only
// the last tier can decide.
//
// Two properties matter as much as the individual answers:
//
//   - The tiebreak compares the canonical JSON of the metadata, so the JSON the
//     Rust side produces has to be byte-identical or the tiebreak silently
//     diverges on equal-version, equal-timestamp pairs. The fixture therefore
//     records Go's marshaled bytes for every operand.
//   - The choice is order-independent for a non-empty path, and deliberately is
//     NOT for an empty one: `path == ""` short-circuits to the first argument.
//     Both are recorded by running each pair in both orders.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/danieljustus/symaira-vault/internal/vault"
	vaultsync "github.com/danieljustus/symaira-vault/internal/vault/sync"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "caadd5e"
	pinnedOracleRelease = "v0.22.1"
)

var productionSources = []string{
	"internal/vault/entry.go",
	"internal/vault/sync/sync.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

// winnerCase records one pair run in both argument orders.
type winnerCase struct {
	Name string `json:"name"`
	Why  string `json:"why"`
	Path string `json:"path"`
	// A and B are the operands as canonical Go JSON. The Rust side
	// deserializes these, so both implementations start from identical bytes.
	A json.RawMessage `json:"a"`
	B json.RawMessage `json:"b"`
	// ACanonical/BCanonical are the exact compact bytes json.Marshal produced.
	// The embedded A/B above are re-indented when this fixture is written, so
	// they cannot carry the byte form the third tier actually compares.
	ACanonical string `json:"a_canonical"`
	BCanonical string `json:"b_canonical"`
	// Tier names which rule decided this pair: version, updated, or tiebreak.
	Tier string `json:"tier"`
	// WinnerForward is "a" or "b" for WinnerByVersion(path, a, b).
	WinnerForward string `json:"winner_forward"`
	// WinnerSwapped is "a" or "b" for WinnerByVersion(path, b, a), still
	// named in terms of the original a/b so the two are directly comparable.
	WinnerSwapped string `json:"winner_swapped"`
	// OrderIndependent is WinnerForward == WinnerSwapped.
	OrderIndependent bool `json:"order_independent"`
	// WinnerJSON/LoserJSON are the forward-order result, verbatim.
	WinnerJSON      json.RawMessage `json:"winner_json"`
	LoserJSON       json.RawMessage `json:"loser_json"`
	WinnerCanonical string          `json:"winner_canonical"`
	LoserCanonical  string          `json:"loser_canonical"`
}

type fixture struct {
	SchemaVersion int          `json:"schema_version"`
	Oracle        oracle       `json:"oracle"`
	Cases         []winnerCase `json:"cases"`
}

// fixtureYear is fixed: nothing in this corpus depends on the year, and the
// cases vary by month/day and by sub-second precision instead.
const fixtureYear = 2026

func ts(mo time.Month, d, h, mi, s, ns int) time.Time {
	return time.Date(fixtureYear, mo, d, h, mi, s, ns, time.UTC)
}

func meta(created, updated time.Time, version int, tags []string, history []vault.WriteRecord) vault.EntryMetadata {
	return vault.EntryMetadata{
		Created: created, Updated: updated, Version: version,
		Tags: tags, WriteHistory: history,
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		fatal("marshal: %v", err)
	}
	return b
}

func buildCases() []winnerCase {
	base := ts(1, 1, 0, 0, 0, 0)
	later := ts(1, 2, 0, 0, 0, 0)
	// One nanosecond apart, to prove the comparison is not truncated to
	// seconds anywhere on either side.
	nsEarly := ts(3, 4, 5, 6, 7, 1)
	nsLate := ts(3, 4, 5, 6, 7, 2)

	type spec struct {
		name, why, path string
		tier            string
		a, b            vault.EntryMetadata
	}
	specs := []spec{
		{
			"version_higher_wins_forward", "the first tier: a larger version wins outright regardless of timestamps",
			"entries/item.age", "version",
			meta(base, later, 2, nil, nil),
			meta(base, base, 1, nil, nil),
		},
		{
			"version_higher_wins_reversed", "the same pair with the larger version second, to show the rule is not positional",
			"entries/item.age", "version",
			meta(base, base, 1, nil, nil),
			meta(base, later, 2, nil, nil),
		},
		{
			"version_beats_newer_timestamp", "an older timestamp still wins if its version is higher: version dominates Updated",
			"entries/item.age", "version",
			meta(base, base, 5, nil, nil),
			meta(base, later, 4, nil, nil),
		},
		{
			"equal_version_newer_updated_wins", "the second tier: equal versions fall through to Updated",
			"entries/item.age", "updated",
			meta(base, later, 3, nil, nil),
			meta(base, base, 3, nil, nil),
		},
		{
			"equal_version_updated_nanosecond_apart", "Updated is compared at full precision; one nanosecond decides it",
			"entries/item.age", "updated",
			meta(base, nsLate, 3, nil, nil),
			meta(base, nsEarly, 3, nil, nil),
		},
		{
			"equal_version_fractional_second_beats_whole_second",
			"Go trims trailing zeros from the fractional second, so the later instant 07.5 serializes SHORTER-prefixed than 07 and sorts EARLIER as a string ('.' is below 'Z'). A port that compares the timestamps as strings instead of instants gets this pair backwards, and only this shape catches it",
			"entries/item.age", "updated",
			meta(base, ts(3, 4, 5, 6, 7, 500000000), 3, nil, nil),
			meta(base, ts(3, 4, 5, 6, 7, 0), 3, nil, nil),
		},
		{
			"full_tie_broken_by_created", "the third tier: version and Updated are equal, so the canonical JSON decides, and Created is its first differing field",
			"entries/item.age", "tiebreak",
			meta(base, later, 1, nil, nil),
			meta(later, later, 1, nil, nil),
		},
		{
			"full_tie_broken_by_tags", "a tie decided further into the JSON: identical timestamps and version, differing tags",
			"entries/item.age", "tiebreak",
			meta(base, base, 1, []string{"alpha"}, nil),
			meta(base, base, 1, []string{"beta"}, nil),
		},
		{
			"full_tie_absent_vs_present_tags", "an omitempty field changes the JSON length, not just its content, so the tiebreak sees a shorter string",
			"entries/item.age", "tiebreak",
			meta(base, base, 1, nil, nil),
			meta(base, base, 1, []string{"alpha"}, nil),
		},
		{
			"full_tie_escaped_character_flips_the_winner",
			"json.Marshal escapes < as \\u003c, and the escape moves the byte from 0x3C (below '=') to 0x5C (above it), so the oracle picks the '=' tag. A port using serde_json's defaults compares the raw '<' and picks the OTHER entry — different sides of a sync reconciliation keeping different versions of the same path. Tags are user-controlled",
			"entries/item.age", "tiebreak",
			meta(base, base, 1, []string{"<"}, nil),
			meta(base, base, 1, []string{"="}, nil),
		},
		{
			"full_tie_ampersand_is_escaped",
			"the same shape via &, which escapes to \\u0026 and also lands above '='",
			"entries/item.age", "tiebreak",
			meta(base, base, 1, []string{"&"}, nil),
			meta(base, base, 1, []string{"="}, nil),
		},
		{
			"full_tie_broken_by_write_history", "the tiebreak reaches the last field: identical everything except one write record",
			"entries/item.age", "tiebreak",
			meta(base, base, 1, nil, []vault.WriteRecord{{Timestamp: base, Field: "a", Action: "set"}}),
			meta(base, base, 1, nil, []vault.WriteRecord{{Timestamp: base, Field: "b", Action: "set"}}),
		},
		{
			"identical_metadata_first_argument_wins", "two indistinguishable operands: the JSON compare is <=, so the first argument wins and the result is stable rather than arbitrary",
			"entries/item.age", "tiebreak",
			meta(base, base, 1, nil, nil),
			meta(base, base, 1, nil, nil),
		},
		{
			"empty_path_short_circuits_to_first_argument", "an empty path skips the JSON tiebreak entirely and returns the first argument, so this pair is deliberately order-DEPENDENT",
			"", "tiebreak",
			meta(later, base, 1, nil, nil),
			meta(base, base, 1, nil, nil),
		},
	}

	cases := make([]winnerCase, 0, len(specs))
	for _, s := range specs {
		fw, fl := vaultsync.WinnerByVersion(s.path, s.a, s.b)
		sw, _ := vaultsync.WinnerByVersion(s.path, s.b, s.a)

		aJSON := string(mustJSON(s.a))
		nameOf := func(m vault.EntryMetadata) string {
			// Operands can be byte-identical; in that case either label is
			// correct and "a" is the stable one.
			if string(mustJSON(m)) == aJSON {
				return "a"
			}
			return "b"
		}
		forward := nameOf(fw)
		swapped := nameOf(sw)

		cases = append(cases, winnerCase{
			Name: s.name, Why: s.why, Path: s.path, Tier: s.tier,
			A: mustJSON(s.a), B: mustJSON(s.b),
			ACanonical: string(mustJSON(s.a)), BCanonical: string(mustJSON(s.b)),
			WinnerForward: forward, WinnerSwapped: swapped,
			OrderIndependent: forward == swapped,
			WinnerJSON:       mustJSON(fw), LoserJSON: mustJSON(fl),
			WinnerCanonical: string(mustJSON(fw)), LoserCanonical: string(mustJSON(fl)),
		})
	}
	return cases
}

func main() {
	output := flag.String("output", "testdata/port/sync/version-winner.json", "GIT-003 winner fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	commitLabel, releaseLabel, err := resolveOracle(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle metadata: %v", err)
	}
	root, err := repositoryRoot()
	if err != nil {
		fatal("%v", err)
	}
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("%v", err)
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/gitwinnergen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}

	cases := buildCases()

	// A corpus that never exercises a tier proves nothing about it.
	seen := map[string]int{}
	for _, c := range cases {
		seen[c.Tier]++
	}
	for _, tier := range []string{"version", "updated", "tiebreak"} {
		if seen[tier] == 0 {
			fatal("no case exercises the %q tier", tier)
		}
	}

	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: commitLabel, CommitSHA: resolved, Release: releaseLabel,
			SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest,
		},
		Cases: cases,
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}

	if *check {
		existing, readErr := os.ReadFile(*output) // #nosec G304 -- explicit operator-selected fixture
		if readErr != nil {
			fatal("read fixture: %v", readErr)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; run make git-winner-fixtures-generate")
		}
		fmt.Printf("PASS GIT-003 version-winner fixture (%d cases: %d version, %d updated, %d tiebreak)\n",
			len(cases), seen["version"], seen["updated"], seen["tiebreak"])
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases)\n", *output, len(cases))
}

func resolveOracle(check bool, commit, release string) (string, string, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return "", "", fmt.Errorf("oracle commit %q is not the pinned commit %q", commit, pinnedOracleCommit)
	}
	if release != "" && release != pinnedOracleRelease {
		return "", "", fmt.Errorf("oracle release %q is not the pinned release %q", release, pinnedOracleRelease)
	}
	if check {
		return pinnedOracleCommit, pinnedOracleRelease, nil
	}
	if commit == "" || release == "" {
		return "", "", fmt.Errorf("--oracle-commit and --oracle-release are required when generating a new fixture")
	}
	return commit, release, nil
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
	os.Exit(1)
}
