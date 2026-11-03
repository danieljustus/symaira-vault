// Command anomalygen records the Go MCP anomaly detector (PLATFORM-002 / ADR
// 0034 item 29) from the production code and binds the fixture to the ordered
// reference mcp-anomaly-ordered-v1 (ADR 0016).
//
// Two groups of facts are recorded:
//
//   - detector scenarios drive the real internal/anomaly.AnomalyDetector with
//     explicit event timestamps (a fixed zone, so the local hour is
//     deterministic) and record, per event, every alert the hooks saw, the one
//     Check returned and the window length;
//   - dispatch facts are read from the pinned internal/mcp/server/server_dispatch.go
//     text (audit action prefix and path, whether the audit row carries a
//     request id, which alert reaches it, the approval-cache invalidation, the
//     severity gate of the desktop notification, the empty-agent skip). The
//     server package cannot be driven from here without editing the pinned
//     server sources, so these are source-bound facts, not executed ones; the
//     Rust process tests assert the behavior they describe.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"time"

	"github.com/danieljustus/symaira-vault/internal/anomaly"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

// oracleCommit is the ordered reference mcp-anomaly-ordered-v1. Its only
// changes against the historical oracle are server.go, server_dispatch.go and
// the six anomaly dispatch regressions; internal/anomaly is byte-identical.
const oracleCommit = "24acdb08fcc7021262717aa803d72eb8d151c66a"

const generatorFile = "scripts/rust-port/cmd/anomalygen/main.go"

var sources = []string{
	"internal/anomaly/detector.go",
	"internal/anomaly/rules.go",
	"internal/mcp/server/server_dispatch.go",
}

const dispatchFile = "internal/mcp/server/server_dispatch.go"

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Contract        string   `json:"contract"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type fixture struct {
	SchemaVersion int        `json:"schema_version"`
	Oracle        oracle     `json:"oracle"`
	Dispatch      dispatch   `json:"dispatch"`
	Scenarios     []scenario `json:"scenarios"`
}

// dispatch holds facts extracted from server_dispatch.go.
type dispatch struct {
	AuditActionPrefix      string   `json:"audit_action_prefix"`
	AuditPath              string   `json:"audit_path"`
	AuditOK                bool     `json:"audit_ok"`
	AuditContextBackground bool     `json:"audit_context_background"`
	CacheInvalidatedAfter  bool     `json:"cache_invalidated_after_audit"`
	CacheInvalidationAll   bool     `json:"cache_invalidated_for_any_alert"`
	NotifyMinSeverity      string   `json:"notify_min_severity"`
	SkipsEmptyAgent        bool     `json:"skips_empty_agent"`
	ObservesFailedCalls    bool     `json:"observes_failed_calls"`
	FieldLengthTools       []string `json:"field_length_tools"`
	WarnMessage            string   `json:"warn_message"`
	WarnAttributes         []string `json:"warn_attributes"`
}

type scenario struct {
	Name   string       `json:"name"`
	Config config       `json:"config"`
	Events []eventEntry `json:"events"`
}

// config states only the options a scenario sets; nil means the default.
type config struct {
	WindowSize         *int `json:"window_size,omitempty"`
	SweepThreshold     *int `json:"sweep_threshold,omitempty"`
	SweepWindowSeconds *int `json:"sweep_window_seconds,omitempty"`
	RateLimit          *int `json:"rate_limit,omitempty"`
	RateWindowSeconds  *int `json:"rate_window_seconds,omitempty"`
	OffHoursStart      *int `json:"off_hours_start,omitempty"`
	OffHoursEnd        *int `json:"off_hours_end,omitempty"`
	ToolChainSeconds   *int `json:"tool_chain_window_seconds,omitempty"`
	ToolChainThreshold *int `json:"tool_chain_field_threshold,omitempty"`
}

type eventIn struct {
	UnixNanos        int64  `json:"unix_nanos"`
	UTCOffsetSeconds int    `json:"utc_offset_seconds"`
	Agent            string `json:"agent"`
	Tool             string `json:"tool"`
	Path             string `json:"path"`
	OK               bool   `json:"ok"`
	IsCanary         bool   `json:"is_canary,omitempty"`
	RequestID        string `json:"request_id"`
	FieldLength      int    `json:"field_length,omitempty"`
}

type alertOut struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Agent       string `json:"agent"`
	Path        string `json:"path"`
	Tool        string `json:"tool"`
	RequestID   string `json:"request_id"`
	UnixNanos   int64  `json:"unix_nanos"`
}

type eventEntry struct {
	Event eventIn `json:"event"`
	// Hooks are every alert the hooks saw, in rule order; Returned is what
	// Check returned (the first one, or null).
	Hooks     []alertOut `json:"hooks"`
	Returned  *alertOut  `json:"returned"`
	WindowLen int        `json:"window_len"`
}

func ip(n int) *int { return &n }

func options(c config) []anomaly.Option {
	var opts []anomaly.Option
	if c.WindowSize != nil {
		opts = append(opts, anomaly.WithWindowSize(*c.WindowSize))
	}
	if c.SweepThreshold != nil {
		opts = append(opts, anomaly.WithSweepThreshold(*c.SweepThreshold))
	}
	if c.SweepWindowSeconds != nil {
		opts = append(opts, anomaly.WithSweepWindow(time.Duration(*c.SweepWindowSeconds)*time.Second))
	}
	if c.RateLimit != nil {
		opts = append(opts, anomaly.WithRateLimit(*c.RateLimit))
	}
	if c.RateWindowSeconds != nil {
		opts = append(opts, anomaly.WithRateWindow(time.Duration(*c.RateWindowSeconds)*time.Second))
	}
	if c.OffHoursStart != nil {
		opts = append(opts, anomaly.WithOffHoursStart(*c.OffHoursStart))
	}
	if c.OffHoursEnd != nil {
		opts = append(opts, anomaly.WithOffHoursEnd(*c.OffHoursEnd))
	}
	if c.ToolChainSeconds != nil {
		opts = append(opts, anomaly.WithToolChainWindow(time.Duration(*c.ToolChainSeconds)*time.Second))
	}
	if c.ToolChainThreshold != nil {
		opts = append(opts, anomaly.WithToolChainFieldThreshold(*c.ToolChainThreshold))
	}
	return opts
}

func toAlert(a anomaly.AnomalyAlert) alertOut {
	return alertOut{
		Type: string(a.Type), Severity: a.Severity.String(), Description: a.Description,
		Agent: a.Agent, Path: a.Path, Tool: a.Tool, RequestID: a.RequestID,
		UnixNanos: a.Timestamp.UnixNano(),
	}
}

// run feeds the events to one real detector and records what it did.
func run(name string, c config, events []eventIn) scenario {
	var hooked []alertOut
	opts := append(options(c), anomaly.WithAlertHook(func(a anomaly.AnomalyAlert) {
		hooked = append(hooked, toAlert(a))
	}))
	detector := anomaly.New(opts...)
	out := scenario{Name: name, Config: c}
	for _, e := range events {
		hooked = nil
		zone := time.FixedZone("", e.UTCOffsetSeconds)
		returned := detector.Check(context.Background(), anomaly.ToolCallEvent{
			Timestamp: time.Unix(0, e.UnixNanos).In(zone),
			Agent:     e.Agent, Tool: e.Tool, Path: e.Path, OK: e.OK,
			IsCanary: e.IsCanary, RequestID: e.RequestID, FieldLength: e.FieldLength,
		})
		entry := eventEntry{Event: e, Hooks: append([]alertOut{}, hooked...), WindowLen: detector.WindowLen()}
		if returned != nil {
			r := toAlert(*returned)
			entry.Returned = &r
		}
		out.Events = append(out.Events, entry)
	}
	return out
}

// Base instant: 2026-11-03 12:00:00 UTC; scenarios pick the zone offset.
const baseUnix = 1_793_707_200

func ev(offsetSeconds int, agent, tool, path string) eventIn {
	return eventIn{
		UnixNanos: (baseUnix + int64(offsetSeconds)) * int64(time.Second), UTCOffsetSeconds: 3600,
		Agent: agent, Tool: tool, Path: path, OK: true,
		RequestID: fmt.Sprintf("r%04d", offsetSeconds+1000),
	}
}

// at returns an event at a local wall-clock hour (zone +01:00) of the base day.
func at(hour int, agent, tool, path string) eventIn {
	e := ev(0, agent, tool, path)
	// base is 13:00 local (+01:00); shift to the wanted local hour.
	e.UnixNanos += int64(hour-13) * int64(time.Hour)
	e.RequestID = fmt.Sprintf("h%02d", hour)
	return e
}

func withField(e eventIn, n int) eventIn { e.FieldLength = n; return e }
func canary(e eventIn) eventIn           { e.IsCanary = true; return e }

func buildScenarios() []scenario {
	var all []scenario

	// Off-hours: default window 22-06 wraps midnight; the hour is the event's
	// own zone hour, start inclusive, end exclusive.
	var hours []eventIn
	for _, h := range []int{0, 5, 6, 12, 21, 22, 23} {
		hours = append(hours, at(h, "a", "get_entry", "p"))
	}
	hours = append(hours, at(3, "a", "list_entries", ""))
	all = append(all, run("off_hours_default_wraps_midnight", config{}, hours))

	var plain []eventIn
	for _, h := range []int{0, 1, 4, 5, 6} {
		plain = append(plain, at(h, "a", "get_entry", "p"))
	}
	all = append(all, run("off_hours_plain_window_1_to_5", config{OffHoursStart: ip(1), OffHoursEnd: ip(5)}, plain))
	all = append(all, run("off_hours_empty_window_0_to_0", config{OffHoursStart: ip(0), OffHoursEnd: ip(0)},
		[]eventIn{at(0, "a", "get_entry", "p"), at(12, "a", "get_entry", "p")}))
	all = append(all, run("off_hours_all_day_0_to_24", config{OffHoursStart: ip(0), OffHoursEnd: ip(24)},
		[]eventIn{at(0, "a", "get_entry", "p"), at(13, "a", "get_entry", "p"), at(23, "a", "get_entry", "p")}))

	// Rate: strictly more than 30 events of one agent inside the 60 s window.
	day := config{OffHoursStart: ip(0), OffHoursEnd: ip(0)} // keep off-hours out of these runs
	var rate []eventIn
	for i := 0; i < 32; i++ {
		rate = append(rate, ev(i, "a", "list_entries", ""))
	}
	rate = append(rate, ev(32, "b", "list_entries", ""), ev(300, "a", "list_entries", ""))
	all = append(all, run("rate_default_31st_call_alerts", day, rate))

	rateCfg := config{OffHoursStart: ip(0), OffHoursEnd: ip(0), RateLimit: ip(2), RateWindowSeconds: ip(10)}
	all = append(all, run("rate_custom_limit_and_window_boundary", rateCfg, []eventIn{
		ev(0, "a", "x", ""), ev(1, "a", "x", ""),
		ev(10, "a", "x", ""), // the call at 0 sits exactly on the cutoff: still counted, 3 > 2
		ev(11, "a", "x", ""), // 1, 10, 11
		ev(21, "a", "x", ""), // only itself
		ev(22, "b", "x", ""), ev(23, "b", "x", ""), ev(24, "b", "x", ""), ev(25, "a", "x", ""),
	}))

	// Sweep: distinct non-empty paths of ALL agents inside the 60 s window.
	var sweep []eventIn
	for i := 0; i < 9; i++ {
		agent := "a"
		if i%2 == 1 {
			agent = "b"
		}
		sweep = append(sweep, ev(i, agent, "get_entry", fmt.Sprintf("p/%d", i)))
	}
	sweep = append(sweep, ev(9, "a", "get_entry", "p/0"), ev(10, "a", "get_entry", "p/9"),
		ev(11, "a", "list_entries", ""), ev(100, "a", "get_entry", "p/10"))
	all = append(all, run("sweep_default_ten_unique_paths", day, sweep))

	sweepCfg := config{OffHoursStart: ip(0), OffHoursEnd: ip(0), SweepThreshold: ip(3), SweepWindowSeconds: ip(5)}
	all = append(all, run("sweep_custom_threshold_and_window_boundary", sweepCfg, []eventIn{
		ev(0, "a", "get_entry", "a/0"), ev(1, "a", "get_entry", "a/1"), ev(2, "a", "get_entry", "a/2"),
		ev(5, "a", "get_entry", "a/3"), // a/0 sits exactly on the cutoff: still counted
		ev(7, "a", "get_entry", "a/4"), // a/0 and a/1 aged out
	}))

	// Canary: critical, needs a path; first-alert and hook ordering.
	all = append(all, run("canary_access", day, []eventIn{
		canary(ev(0, "a", "get_entry", "honey/pot")),
		canary(ev(1, "a", "list_entries", "")),
		ev(2, "a", "get_entry", "honey/pot"),
	}))
	allRules := config{OffHoursStart: ip(0), OffHoursEnd: ip(24), SweepThreshold: ip(1), RateLimit: ip(0), ToolChainThreshold: ip(1)}
	all = append(all, run("every_rule_on_one_event_orders_the_hooks", allRules, []eventIn{
		withField(ev(0, "a", "get_entry_value", "p/1"), 5),
		canary(ev(1, "a", "run_command", "p/2")),
	}))

	// Tool chain: read of >= 500 bytes then a command tool by the same agent
	// within 30 s.
	chain := []eventIn{
		withField(ev(0, "a", "get_entry_value", "p"), 500),
		ev(1, "b", "run_command", ""),
		ev(2, "a", "run_command", ""),
		ev(3, "a", "execute_with_secret", ""),
		ev(31, "a", "run_command", ""), // the read is 31 s old
		withField(ev(40, "a", "get_entry", "q"), 499),
		ev(41, "a", "run_command", ""),
		withField(ev(50, "a", "get_entry", "r"), 554),
		ev(80, "a", "run_command", ""), // exactly 30 s: still inside
	}
	all = append(all, run("tool_chain_default", day, chain))
	all = append(all, run("tool_chain_command_before_read_is_not_a_chain", day, []eventIn{
		ev(0, "a", "run_command", ""),
		withField(ev(1, "a", "get_entry_value", "p"), 554),
	}))
	tc := config{OffHoursStart: ip(0), OffHoursEnd: ip(0), ToolChainSeconds: ip(5), ToolChainThreshold: ip(10)}
	all = append(all, run("tool_chain_custom_window_and_threshold", tc, []eventIn{
		withField(ev(0, "a", "get_entry", "p"), 10),
		ev(5, "a", "run_command", ""),
		ev(6, "a", "run_command", ""),
	}))

	// Window bound: the oldest event is dropped once the window is full.
	small := config{OffHoursStart: ip(0), OffHoursEnd: ip(0), WindowSize: ip(3), RateLimit: ip(2)}
	var trim []eventIn
	for i := 0; i < 6; i++ {
		trim = append(trim, ev(i, "a", "x", ""))
	}
	all = append(all, run("window_is_bounded", small, trim))

	return all
}

var (
	auditRe      = regexp.MustCompile(`s\.logAudit\((context\.Background\(\)), "(anomaly_)"\+string\(alert\.Type\), (alert\.Path), (false)\)`)
	invalidateRe = regexp.MustCompile(`(?s)s\.logAudit\(context\.Background\(\), "anomaly_".*?s\.invalidateApprovalCache\(\)`)
	notifyRe     = regexp.MustCompile(`if alert\.Severity >= anomaly\.(Severity[A-Za-z]+) \{`)
	skipRe       = regexp.MustCompile(`s\.anomalyDetector == nil \|\| agentName == ""`)
	errCallRe    = regexp.MustCompile(`s\.detectAnomalyAsync\(ctx, name, entryPath, reqID, agentName, duration, false, 0\)`)
	fieldRe      = regexp.MustCompile(`name == "get_entry" \|\| name == "get_entry_value"`)
	warnRe       = regexp.MustCompile(`(?s)slog\.Default\(\)\.Warn\("(anomaly detected)",(.*?)\)\n`)
	attrRe       = regexp.MustCompile(`"([a-z_]+)", alert\.`)
	alertGuardRe = regexp.MustCompile(`if alert == nil \{\s*return\s*\}`)
)

// extractDispatch derives the dispatch facts from the pinned source text and
// refuses to record anything it cannot find.
func extractDispatch(src []byte) (dispatch, error) {
	d := dispatch{}
	m := auditRe.FindSubmatch(src)
	if m == nil {
		return d, fmt.Errorf("anomaly audit call not found in %s", dispatchFile)
	}
	d.AuditActionPrefix = string(m[2])
	d.AuditPath = string(m[3])
	d.AuditOK = string(m[4]) == "true"
	d.AuditContextBackground = string(m[1]) == "context.Background()"
	d.CacheInvalidatedAfter = invalidateRe.Match(src)
	if !alertGuardRe.Match(src) || !d.CacheInvalidatedAfter {
		return d, fmt.Errorf("cache invalidation is not unconditional after a returned alert")
	}
	d.CacheInvalidationAll = true // no severity condition between the guard and the call
	n := notifyRe.FindSubmatch(src)
	if n == nil {
		return d, fmt.Errorf("notification severity gate not found")
	}
	d.NotifyMinSeverity = string(n[1])
	d.SkipsEmptyAgent = skipRe.Match(src)
	d.ObservesFailedCalls = errCallRe.Match(src)
	if fieldRe.Match(src) {
		d.FieldLengthTools = []string{"get_entry", "get_entry_value"}
	}
	w := warnRe.FindSubmatch(src)
	if w == nil {
		return d, fmt.Errorf("dispatch warning not found")
	}
	d.WarnMessage = string(w[1])
	for _, a := range attrRe.FindAllSubmatch(w[2], -1) {
		d.WarnAttributes = append(d.WarnAttributes, string(a[1]))
	}
	if !d.AuditContextBackground || d.AuditOK || !d.SkipsEmptyAgent || !d.ObservesFailedCalls || len(d.FieldLengthTools) == 0 {
		return d, fmt.Errorf("dispatch source facts changed: %+v", d)
	}
	return d, nil
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate anomaly generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func buildOracle(root string) (oracle, error) {
	srcs := append([]string(nil), sources...)
	sort.Strings(srcs)
	sourceDigest, err := provenance.Digest(root, srcs)
	if err != nil {
		return oracle{}, fmt.Errorf("hash anomaly sources: %w", err)
	}
	// The generator can only execute the working tree. Binding it to the
	// reference commit's blobs stops the fixture claiming one revision while
	// carrying another's behavior.
	resolved, err := provenance.Verify(root, oracleCommit, srcs)
	if err != nil {
		return oracle{}, err
	}
	gens := []string{generatorFile}
	genDigest, err := provenance.Digest(root, gens)
	if err != nil {
		return oracle{}, fmt.Errorf("hash anomaly generator: %w", err)
	}
	return oracle{
		Commit: oracleCommit, CommitSHA: resolved, Contract: "mcp-anomaly-ordered-v1",
		SourceFiles: srcs, SourceDigest: sourceDigest, GeneratorFiles: gens, GeneratorDigest: genDigest,
	}, nil
}

func buildFixture(root string) (fixture, error) {
	meta, err := buildOracle(root)
	if err != nil {
		return fixture{}, err
	}
	src, err := os.ReadFile(filepath.Join(root, dispatchFile)) // #nosec G304 -- fixed pinned source
	if err != nil {
		return fixture{}, err
	}
	facts, err := extractDispatch(src)
	if err != nil {
		return fixture{}, err
	}
	return fixture{SchemaVersion: 1, Oracle: meta, Dispatch: facts, Scenarios: buildScenarios()}, nil
}

func marshal(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	output := flag.String("output", "testdata/port/mcp/anomaly-detector.json", "anomaly fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	flag.Parse()

	root, err := repositoryRoot()
	if err != nil {
		fatal("%v", err)
	}
	fx, err := buildFixture(root)
	if err != nil {
		fatal("build anomaly fixture: %v", err)
	}
	content, err := marshal(fx)
	if err != nil {
		fatal("marshal anomaly fixture: %v", err)
	}
	if *check {
		existing, err := os.ReadFile(*output) // #nosec G304 -- explicit fixture path
		if err != nil {
			fatal("read anomaly fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("anomaly fixture is stale; run make mcp-anomaly-fixtures-generate")
		}
		fmt.Println("PASS anomaly fixture")
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create anomaly fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write anomaly fixture: %v", err)
	}
	fmt.Printf("WROTE %s\n", *output)
}
