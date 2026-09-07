// Command quotagen generates deterministic pure quota transition vectors from
// the production policy helper.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/danieljustus/symaira-vault/internal/policy"
)

const (
	pinnedOracleCommit  = "caadd5e"
	pinnedOracleRelease = "v0.22.1"
)

var productionSources = []string{"internal/policy/ratelimit_transition.go"}

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type quotaFixture struct {
	SchemaVersion int         `json:"schema_version"`
	Oracle        oracle      `json:"oracle"`
	Cases         []quotaCase `json:"cases"`
}

type quotaCase struct {
	Name         string            `json:"name"`
	InitialState quotaState        `json:"initial_state"`
	Limits       quotaLimits       `json:"limits"`
	Transitions  []quotaTransition `json:"transitions"`
}

type quotaState struct {
	Tokens           float64 `json:"tokens"`
	Capacity         float64 `json:"capacity"`
	RefillRate       float64 `json:"refill_rate"`
	LastRefill       int64   `json:"last_refill_unix_nanos"`
	DailyCount       int64   `json:"daily_count"`
	DailyWindowStart int64   `json:"daily_window_start_unix_nanos"`
	MaxPerDay        int64   `json:"max_per_day"`
}

type quotaLimits struct {
	MaxPerHour int `json:"max_per_hour"`
	MaxPerDay  int `json:"max_per_day"`
}

type quotaEvent struct {
	Kind        policy.RateLimitEvent `json:"kind"`
	AtUnixNanos int64                 `json:"at_unix_nanos"`
}

type quotaTransition struct {
	Event  quotaEvent             `json:"event"`
	State  quotaState             `json:"state"`
	Result policy.RateLimitResult `json:"result"`
}

func buildOracle(root, commit, release string) (oracle, error) {
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := digestFiles(root, sources)
	if err != nil {
		return oracle{}, fmt.Errorf("hash quota sources: %w", err)
	}
	generatorDigest, err := digestFiles(root, []string{"scripts/rust-port/cmd/quotagen/main.go"})
	if err != nil {
		return oracle{}, fmt.Errorf("hash quota generator: %w", err)
	}
	return oracle{Commit: commit, Release: release, SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest}, nil
}

func digestFiles(root string, files []string) (string, error) {
	hash := sha256.New()
	for _, name := range files {
		path := filepath.Join(root, name)
		content, err := os.ReadFile(path) // #nosec G304 -- fixed production/generator inputs
		if err != nil {
			return "", err
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(content)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate quota generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func resolveOracle(check bool, commit, release string) (oracle, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return oracle{}, fmt.Errorf("oracle commit %q is not the pinned commit %q", commit, pinnedOracleCommit)
	}
	if release != "" && release != pinnedOracleRelease {
		return oracle{}, fmt.Errorf("oracle release %q is not the pinned release %q", release, pinnedOracleRelease)
	}
	if check {
		return oracle{Commit: pinnedOracleCommit, Release: pinnedOracleRelease}, nil
	}
	if commit == "" || release == "" {
		return oracle{}, fmt.Errorf("--oracle-commit and --oracle-release are required when generating a new fixture")
	}
	return oracle{Commit: commit, Release: release}, nil
}

func buildFixture(meta oracle) quotaFixture {
	base := time.Unix(1_700_000_000, 0).UTC()
	return quotaFixture{
		SchemaVersion: 1,
		Oracle:        meta,
		Cases: []quotaCase{
			buildCase("refill_fractional", quotaLimits{MaxPerHour: 4}, base,
				[]quotaEvent{
					{Kind: policy.RateLimitEventSetLimits, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base.Add(30 * time.Minute))},
				}),
			buildCase("daily_rollover", quotaLimits{MaxPerHour: 10, MaxPerDay: 2}, base,
				[]quotaEvent{
					{Kind: policy.RateLimitEventSetLimits, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base.Add(24 * time.Hour))},
				}),
			buildCase("capacity_clamp", quotaLimits{MaxPerHour: 2}, base,
				[]quotaEvent{
					{Kind: policy.RateLimitEventSetLimits, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base.Add(2 * time.Hour))},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base.Add(2 * time.Hour))},
				}),
			buildCase("rejection", quotaLimits{MaxPerHour: 1, MaxPerDay: 1}, base,
				[]quotaEvent{
					{Kind: policy.RateLimitEventSetLimits, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
				}),
			buildCase("boundaries", quotaLimits{MaxPerHour: 1}, base,
				[]quotaEvent{
					{Kind: policy.RateLimitEventSetLimits, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base.Add(3599 * time.Second))},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base.Add(3600 * time.Second))},
				}),
			buildCase("negative_hour_limit", quotaLimits{MaxPerHour: -1}, base,
				[]quotaEvent{
					{Kind: policy.RateLimitEventSetLimits, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
				}),
			buildCase("negative_day_limit", quotaLimits{MaxPerHour: 1, MaxPerDay: -1}, base,
				[]quotaEvent{
					{Kind: policy.RateLimitEventSetLimits, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
					{Kind: policy.RateLimitEventAllow, AtUnixNanos: unixNanos(base)},
				}),
		},
	}
}

func buildCase(name string, limits quotaLimits, initial time.Time, events []quotaEvent) quotaCase {
	state := policy.RateLimitState{
		LastRefill:       initial,
		DailyWindowStart: initial,
	}
	transitions := make([]quotaTransition, 0, len(events))
	for _, event := range events {
		next, result := policy.TransitionRateLimit(state, policy.RateLimitLimits{
			MaxPerHour: limits.MaxPerHour,
			MaxPerDay:  limits.MaxPerDay,
		}, time.Unix(0, event.AtUnixNanos).UTC(), event.Kind)
		state = next
		transitions = append(transitions, quotaTransition{
			Event:  event,
			State:  encodeState(state),
			Result: result,
		})
	}
	return quotaCase{
		Name:         name,
		InitialState: encodeState(policy.RateLimitState{LastRefill: initial, DailyWindowStart: initial}),
		Limits:       limits,
		Transitions:  transitions,
	}
}

func encodeState(state policy.RateLimitState) quotaState {
	return quotaState{
		Tokens:           state.Tokens,
		Capacity:         state.Capacity,
		RefillRate:       state.RefillRate,
		LastRefill:       unixNanos(state.LastRefill),
		DailyCount:       int64(state.DailyCount),
		DailyWindowStart: unixNanos(state.DailyWindowStart),
		MaxPerDay:        int64(state.MaxPerDay),
	}
}

func unixNanos(value time.Time) int64 {
	return value.UnixNano()
}

func marshal(value any) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func checkFixture(path string, expected []byte) error {
	existing, err := os.ReadFile(path) // #nosec G304 -- explicit fixture path
	if err != nil {
		return fmt.Errorf("read quota fixture: %w", err)
	}
	if !bytes.Equal(existing, expected) {
		return fmt.Errorf("quota fixture is stale; run make quota-fixtures-generate")
	}
	return nil
}

func process(path string, check bool, meta oracle) {
	content, err := marshal(buildFixture(meta))
	if err != nil {
		fatal("marshal quota fixture: %v", err)
	}
	if check {
		if err := checkFixture(path, content); err != nil {
			fatal("%v", err)
		}
		fmt.Println("PASS quota fixture")
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatal("create quota fixture directory: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		fatal("write quota fixture: %v", err)
	}
	fmt.Printf("WROTE %s\n", path)
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	output := flag.String("output", "testdata/port/core/quota-contract.json", "quota fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit")
	release := flag.String("oracle-release", "", "Go oracle release")
	flag.Parse()

	meta, err := resolveOracle(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle metadata: %v", err)
	}
	if *check || *commit != "" || *release != "" {
		root, err := repositoryRoot()
		if err != nil {
			fatal("locate repository root: %v", err)
		}
		meta, err = buildOracle(root, meta.Commit, meta.Release)
		if err != nil {
			fatal("build oracle metadata: %v", err)
		}
	}
	process(*output, *check, meta)
}
