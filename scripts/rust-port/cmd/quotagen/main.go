// Command quotagen generates deterministic pure quota transition vectors from
// the production policy helper.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/danieljustus/symaira-vault/internal/policy"
)

type oracle struct {
	Commit  string `json:"commit"`
	Release string `json:"release"`
}

type header struct {
	SchemaVersion int    `json:"schema_version"`
	Oracle        oracle `json:"oracle"`
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
	DailyCount       int     `json:"daily_count"`
	DailyWindowStart int64   `json:"daily_window_start_unix_nanos"`
	MaxPerDay        int     `json:"max_per_day"`
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
		DailyCount:       state.DailyCount,
		DailyWindowStart: unixNanos(state.DailyWindowStart),
		MaxPerDay:        state.MaxPerDay,
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

func readHeader(path string) (header, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- explicit fixture path
	if err != nil {
		return header{}, err
	}
	var value header
	if err := json.Unmarshal(content, &value); err != nil {
		return header{}, err
	}
	if value.SchemaVersion != 1 {
		return header{}, fmt.Errorf("unsupported schema_version %d", value.SchemaVersion)
	}
	return value, nil
}

func process(path string, check bool, meta oracle) {
	content, err := marshal(buildFixture(meta))
	if err != nil {
		fatal("marshal quota fixture: %v", err)
	}
	if check {
		existing, err := os.ReadFile(path) // #nosec G304 -- explicit fixture path
		if err != nil {
			fatal("read quota fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("quota fixture is stale; run make quota-fixtures-generate")
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

	meta := oracle{Commit: *commit, Release: *release}
	if *check || meta.Commit == "" || meta.Release == "" {
		existing, err := readHeader(*output)
		if err == nil {
			meta = existing.Oracle
		}
	}
	if meta.Commit == "" || meta.Release == "" {
		fatal("--oracle-commit and --oracle-release are required when generating a new fixture")
	}
	process(*output, *check, meta)
}
