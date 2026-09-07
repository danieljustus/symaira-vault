// Command policygen freezes the pure Go policy and tier contracts for Rust.
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

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	policypkg "github.com/danieljustus/symaira-vault/internal/policy"
)

var productionSources = []string{
	"internal/config/config.go",
	"internal/config/presets.go",
	"internal/policy/engine.go",
	"internal/policy/types.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type policyFixture struct {
	SchemaVersion    int              `json:"schema_version"`
	Oracle           oracle           `json:"oracle"`
	ValidationCases  []validationCase `json:"validation_cases"`
	TimeRangeCases   []timeRangeCase  `json:"time_range_cases"`
	EvaluationPolicy fixturePolicy    `json:"evaluation_policy"`
	EvaluationCases  []evaluationCase `json:"evaluation_cases"`
	TierPresetCases  []tierPresetCase `json:"tier_preset_cases"`
	TierCopyCases    []tierCopyCase   `json:"tier_copy_cases"`
}

type validationCase struct {
	Name   string        `json:"name"`
	Policy fixturePolicy `json:"policy"`
	Valid  bool          `json:"valid"`
	Error  string        `json:"error,omitempty"`
}

type fixturePolicy struct {
	Version     string        `json:"version"`
	Description string        `json:"description,omitempty"`
	Rules       []fixtureRule `json:"rules"`
}

type fixtureRule struct {
	Name       string            `json:"name"`
	Priority   int               `json:"priority,omitempty"`
	Conditions fixtureConditions `json:"conditions"`
	Action     string            `json:"action"`
}

type fixtureConditions struct {
	AgentID      string            `json:"agent_id,omitempty"`
	Path         string            `json:"path,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	WorkingDir   string            `json:"working_dir,omitempty"`
	TimeOfDay    *fixtureTimeRange `json:"time_of_day,omitempty"`
	EnvVars      map[string]string `json:"env_vars,omitempty"`
	ActionType   string            `json:"action,omitempty"`
	AllowedTools []string          `json:"allowed_tools,omitempty"`
	MaxSecrets   int               `json:"max_secrets,omitempty"`
}

type fixtureTimeRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type timeRangeCase struct {
	Name    string           `json:"name"`
	Range   fixtureTimeRange `json:"range"`
	Now     string           `json:"now"`
	Valid   bool             `json:"valid"`
	Matches bool             `json:"matches"`
}

type evaluationCase struct {
	Name     string         `json:"name"`
	Context  fixtureContext `json:"context"`
	Expected fixtureResult  `json:"expected"`
}

type fixtureContext struct {
	AgentID         string            `json:"agent_id,omitempty"`
	Path            string            `json:"path,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	WorkingDir      string            `json:"working_dir,omitempty"`
	EnvVars         map[string]string `json:"env_vars,omitempty"`
	ActionType      string            `json:"action_type,omitempty"`
	ToolName        string            `json:"tool_name,omitempty"`
	Now             string            `json:"now"`
	SecretsAccessed int               `json:"secrets_accessed,omitempty"`
}

type fixtureResult struct {
	Action   string `json:"action"`
	RuleName string `json:"rule_name"`
	Matched  bool   `json:"matched"`
}

type profileSnapshot struct {
	Name               string   `json:"name"`
	ApprovalMode       *string  `json:"approval_mode,omitempty"`
	AllowedPaths       []string `json:"allowed_paths"`
	CanWrite           *bool    `json:"can_write,omitempty"`
	CanRunCommands     *bool    `json:"can_run_commands,omitempty"`
	CanManageConfig    *bool    `json:"can_manage_config,omitempty"`
	CanUseClipboard    *bool    `json:"can_use_clipboard,omitempty"`
	CanUseAutotype     *bool    `json:"can_use_autotype,omitempty"`
	CanReadValues      *bool    `json:"can_read_values,omitempty"`
	ExposeValueTools   *bool    `json:"expose_value_tools,omitempty"`
	AutoUnseal         *bool    `json:"auto_unseal,omitempty"`
	RequireApproval    *bool    `json:"require_approval,omitempty"`
	AllowedExecutables []string `json:"allowed_executables,omitempty"`
}

type tierPresetCase struct {
	Tier          string          `json:"tier"`
	Found         bool            `json:"found"`
	Preset        profileSnapshot `json:"preset"`
	ApplyInput    profileSnapshot `json:"apply_input"`
	ApplyExpected profileSnapshot `json:"apply_expected"`
}

type tierCopyCase struct {
	Tier            string `json:"tier"`
	MutatedCanWrite bool   `json:"mutated_can_write"`
	SecondCanWrite  bool   `json:"second_can_write"`
}

func buildPolicyFixture(commit, release string) (policyFixture, error) {
	root, err := repositoryRoot()
	if err != nil {
		return policyFixture{}, err
	}
	meta, err := buildOracle(root, commit, release)
	if err != nil {
		return policyFixture{}, err
	}

	return policyFixture{
		SchemaVersion:    1,
		Oracle:           meta,
		ValidationCases:  buildValidationCases(),
		TimeRangeCases:   buildTimeRangeCases(),
		EvaluationPolicy: evaluationPolicyFixture(),
		EvaluationCases:  buildEvaluationCases(),
		TierPresetCases:  buildTierPresetCases(),
		TierCopyCases:    buildTierCopyCases(),
	}, nil
}

func buildOracle(root, commit, release string) (oracle, error) {
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := digestFiles(root, sources)
	if err != nil {
		return oracle{}, fmt.Errorf("hash policy sources: %w", err)
	}
	generatorDigest, err := digestFiles(root, []string{"scripts/rust-port/cmd/policygen/main.go"})
	if err != nil {
		return oracle{}, fmt.Errorf("hash policy generator: %w", err)
	}
	return oracle{
		Commit:          commit,
		Release:         release,
		SourceFiles:     sources,
		SourceDigest:    sourceDigest,
		GeneratorDigest: generatorDigest,
	}, nil
}

func digestFiles(root string, files []string) (string, error) {
	hash := sha256.New()
	for _, name := range files {
		path := name
		if root != "" && !filepath.IsAbs(name) {
			path = filepath.Join(root, name)
		}
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
		return "", fmt.Errorf("locate policy generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func buildValidationCases() []validationCase {
	valid := fixturePolicy{
		Version: "1.0",
		Rules:   []fixtureRule{{Name: "allow reads", Action: "allow", Conditions: fixtureConditions{ActionType: "read"}}},
	}
	cases := []struct {
		name   string
		policy fixturePolicy
	}{
		{"valid_minimal", valid},
		{"missing_version", fixturePolicy{Rules: valid.Rules}},
		{"no_rules", fixturePolicy{Version: "1.0", Rules: []fixtureRule{}}},
		{"missing_rule_name", fixturePolicy{Version: "1.0", Rules: []fixtureRule{{Action: "allow"}}}},
		{"invalid_action", fixturePolicy{Version: "1.0", Rules: []fixtureRule{{Name: "bad action", Action: "invalid"}}}},
		{"duplicate_rule_names", fixturePolicy{Version: "1.0", Rules: []fixtureRule{{Name: "same", Action: "allow"}, {Name: "same", Action: "deny"}}}},
		{"invalid_time", fixturePolicy{Version: "1.0", Rules: []fixtureRule{{Name: "bad time", Action: "allow", Conditions: fixtureConditions{TimeOfDay: &fixtureTimeRange{Start: "25:00", End: "17:00"}}}}}},
		{"invalid_action_type", fixturePolicy{Version: "1.0", Rules: []fixtureRule{{Name: "bad type", Action: "allow", Conditions: fixtureConditions{ActionType: "execute"}}}}},
	}
	result := make([]validationCase, 0, len(cases))
	for _, item := range cases {
		policy := toGoPolicy(item.policy)
		err := policy.Validate()
		caseResult := validationCase{Name: item.name, Policy: item.policy, Valid: err == nil}
		if err != nil {
			caseResult.Error = err.Error()
		}
		result = append(result, caseResult)
	}
	return result
}

func buildTimeRangeCases() []timeRangeCase {
	inputs := []struct {
		name, start, end, now string
	}{
		{"normal_inside", "09:00", "17:00", "2024-01-01T12:00:00Z"},
		{"normal_at_start", "09:00", "17:00", "2024-01-01T09:00:00Z"},
		{"normal_at_end", "09:00", "17:00", "2024-01-01T17:00:00Z"},
		{"normal_before", "09:00", "17:00", "2024-01-01T08:59:59Z"},
		{"wrap_evening", "22:00", "06:00", "2024-01-01T23:00:00Z"},
		{"wrap_morning", "22:00", "06:00", "2024-01-01T05:59:59Z"},
		{"wrap_at_end", "22:00", "06:00", "2024-01-01T06:00:00Z"},
		{"equal_range", "12:00", "12:00", "2024-01-01T03:00:00Z"},
		{"invalid_start", "25:00", "17:00", "2024-01-01T12:00:00Z"},
		{"invalid_end", "09:00", "invalid", "2024-01-01T12:00:00Z"},
	}
	result := make([]timeRangeCase, 0, len(inputs))
	for _, item := range inputs {
		rangeValue := policypkg.TimeRange{Start: item.start, End: item.end}
		now, err := time.Parse(time.RFC3339, item.now)
		if err != nil {
			panic(err)
		}
		_, _, parseErr := rangeValue.Parse()
		result = append(result, timeRangeCase{
			Name:    item.name,
			Range:   fixtureTimeRange{Start: item.start, End: item.end},
			Now:     item.now,
			Valid:   parseErr == nil,
			Matches: rangeValue.Contains(now),
		})
	}
	return result
}

func evaluationPolicyFixture() fixturePolicy {
	return fixturePolicy{
		Version: "1.0",
		Rules: []fixtureRule{
			{Name: "allow openclaw dev", Priority: 100, Action: "allow", Conditions: fixtureConditions{AgentID: "openclaw", Tags: []string{"dev"}}},
			{Name: "allow project child", Priority: 95, Action: "allow", Conditions: fixtureConditions{Path: "/fixture/home/dev/*"}},
			{Name: "allow project recursive", Priority: 94, Action: "allow", Conditions: fixtureConditions{Path: "/fixture/home/project/**"}},
			{Name: "allow working tree", Priority: 93, Action: "allow", Conditions: fixtureConditions{WorkingDir: "/fixture/repo"}},
			{Name: "allow ci read", Priority: 92, Action: "allow", Conditions: fixtureConditions{EnvVars: map[string]string{"CI": "true"}, ActionType: "read"}},
			{Name: "allow safe tool", Priority: 91, Action: "allow", Conditions: fixtureConditions{AllowedTools: []string{"list_entries", "get_entry"}}},
			{Name: "biometry at night", Priority: 80, Action: "require_biometry", Conditions: fixtureConditions{TimeOfDay: &fixtureTimeRange{Start: "22:00", End: "06:00"}}},
			{Name: "prompt production", Priority: 70, Action: "prompt", Conditions: fixtureConditions{Tags: []string{"prod"}}},
			{Name: "allow limited secrets", Priority: 60, Action: "allow", Conditions: fixtureConditions{AgentID: "limited", MaxSecrets: 3}},
			{Name: "deny all", Priority: 0, Action: "deny", Conditions: fixtureConditions{AgentID: "*"}},
		},
	}
}

func buildEvaluationCases() []evaluationCase {
	policy := evaluationPolicyFixture()
	cases := []struct {
		name string
		ctx  fixtureContext
	}{
		{"priority_and_tags", fixtureContext{AgentID: "openclaw", Tags: []string{"dev"}, Now: "2024-01-01T12:00:00Z"}},
		{"path_single_segment", fixtureContext{Path: "/fixture/home/dev/secret", Now: "2024-01-01T12:00:00Z"}},
		{"path_single_segment_rejects_grandchild", fixtureContext{Path: "/fixture/home/dev/project/secret", Now: "2024-01-01T12:00:00Z"}},
		{"path_recursive", fixtureContext{Path: "/fixture/home/project/a/b/secret", Now: "2024-01-01T12:00:00Z"}},
		{"working_dir_prefix", fixtureContext{WorkingDir: "/fixture/repo/src", Now: "2024-01-01T12:00:00Z"}},
		{"matching_env_and_action", fixtureContext{EnvVars: map[string]string{"CI": "true"}, ActionType: "read", Now: "2024-01-01T12:00:00Z"}},
		{"wrong_env", fixtureContext{EnvVars: map[string]string{"CI": "false"}, ActionType: "read", Now: "2024-01-01T12:00:00Z"}},
		{"allowed_tool", fixtureContext{ToolName: "get_entry", Now: "2024-01-01T12:00:00Z"}},
		{"disallowed_tool", fixtureContext{ToolName: "delete_entry", Now: "2024-01-01T12:00:00Z"}},
		{"night_wrap_range", fixtureContext{Now: "2024-01-01T23:00:00Z"}},
		{"daytime_not_night", fixtureContext{Now: "2024-01-01T12:00:00Z"}},
		{"production_tag", fixtureContext{Tags: []string{"prod"}, Now: "2024-01-01T12:00:00Z"}},
		{"limited_below_secret_limit", fixtureContext{AgentID: "limited", SecretsAccessed: 2, Now: "2024-01-01T12:00:00Z"}},
		{"limited_at_secret_limit", fixtureContext{AgentID: "limited", SecretsAccessed: 3, Now: "2024-01-01T12:00:00Z"}},
		{"default_deny", fixtureContext{AgentID: "unknown", Now: "2024-01-01T12:00:00Z"}},
		{"empty_engine_shape", fixtureContext{AgentID: "unknown", Now: "2024-01-01T12:00:00Z"}},
	}
	result := make([]evaluationCase, 0, len(cases))
	goPolicy := toGoPolicy(policy)
	engine := policypkg.NewEngine([]*policypkg.Policy{goPolicy})
	for _, item := range cases {
		ctx := toGoContext(item.ctx)
		got := engine.Evaluate(ctx)
		result = append(result, evaluationCase{
			Name:     item.name,
			Context:  item.ctx,
			Expected: fixtureResult{Action: got.Action.String(), RuleName: got.RuleName, Matched: got.Matched},
		})
	}
	return result
}

func buildTierPresetCases() []tierPresetCase {
	result := make([]tierPresetCase, 0, 4)
	for _, tier := range []string{"read-only", "standard", "admin", "unknown"} {
		preset := configpkg.GetPreset(tier)
		item := tierPresetCase{
			Tier:   tier,
			Found:  preset != nil,
			Preset: snapshotProfile(configpkg.AgentProfile{}),
		}
		if preset != nil {
			item.Preset = snapshotProfile(*preset)
		}
		target := configpkg.AgentProfile{
			Name:               "fixture-agent",
			AllowedPaths:       []string{"personal/*", "work/*"},
			AllowedExecutables: []string{"custom"},
		}
		item.ApplyInput = snapshotProfile(target)
		configpkg.ApplyTierPreset(&target, tier)
		item.ApplyExpected = snapshotProfile(target)
		result = append(result, item)
	}
	return result
}

func buildTierCopyCases() []tierCopyCase {
	result := make([]tierCopyCase, 0, 2)
	for _, tier := range []string{"standard", "admin"} {
		first := configpkg.GetPreset(tier)
		second := configpkg.GetPreset(tier)
		if first == nil || second == nil {
			panic("tier fixture unexpectedly missing preset")
		}
		first.CanWrite = configpkg.BoolPtr(false)
		result = append(result, tierCopyCase{
			Tier:            tier,
			MutatedCanWrite: *first.CanWrite,
			SecondCanWrite:  *second.CanWrite,
		})
	}
	return result
}

func snapshotProfile(profile configpkg.AgentProfile) profileSnapshot {
	allowedPaths := make([]string, len(profile.AllowedPaths))
	copy(allowedPaths, profile.AllowedPaths)
	allowedExecutables := append([]string(nil), profile.AllowedExecutables...)
	return profileSnapshot{
		Name:               profile.Name,
		ApprovalMode:       profile.ApprovalMode,
		AllowedPaths:       allowedPaths,
		CanWrite:           profile.CanWrite,
		CanRunCommands:     profile.CanRunCommands,
		CanManageConfig:    profile.CanManageConfig,
		CanUseClipboard:    profile.CanUseClipboard,
		CanUseAutotype:     profile.CanUseAutotype,
		CanReadValues:      profile.CanReadValues,
		ExposeValueTools:   profile.ExposeValueTools,
		AutoUnseal:         profile.AutoUnseal,
		RequireApproval:    profile.RequireApproval,
		AllowedExecutables: allowedExecutables,
	}
}

func toGoPolicy(input fixturePolicy) *policypkg.Policy {
	policy := &policypkg.Policy{Version: input.Version, Description: input.Description}
	for _, rule := range input.Rules {
		conditions := policypkg.Conditions{
			AgentID:      rule.Conditions.AgentID,
			Path:         rule.Conditions.Path,
			Tags:         append([]string(nil), rule.Conditions.Tags...),
			WorkingDir:   rule.Conditions.WorkingDir,
			EnvVars:      cloneMap(rule.Conditions.EnvVars),
			ActionType:   rule.Conditions.ActionType,
			AllowedTools: append([]string(nil), rule.Conditions.AllowedTools...),
			MaxSecrets:   rule.Conditions.MaxSecrets,
		}
		if rule.Conditions.TimeOfDay != nil {
			conditions.TimeOfDay = &policypkg.TimeRange{Start: rule.Conditions.TimeOfDay.Start, End: rule.Conditions.TimeOfDay.End}
		}
		policy.Rules = append(policy.Rules, policypkg.Rule{
			Name:       rule.Name,
			Priority:   rule.Priority,
			Conditions: conditions,
			Action:     policypkg.Action(rule.Action),
		})
	}
	return policy
}

func toGoContext(input fixtureContext) policypkg.EvalContext {
	now, err := time.Parse(time.RFC3339, input.Now)
	if err != nil {
		panic(err)
	}
	return policypkg.EvalContext{
		AgentID:         input.AgentID,
		Path:            input.Path,
		Tags:            append([]string(nil), input.Tags...),
		WorkingDir:      input.WorkingDir,
		EnvVars:         cloneMap(input.EnvVars),
		ActionType:      input.ActionType,
		ToolName:        input.ToolName,
		Now:             now,
		SecretsAccessed: input.SecretsAccessed,
	}
}

func cloneMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func main() {
	output := flag.String("output", "testdata/port/core/policy-contract.json", "policy fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	if *check || *commit == "" || *release == "" {
		if existing, err := readFixture(*output); err == nil {
			*commit = existing.Oracle.Commit
			*release = existing.Oracle.Release
		}
	}
	if *commit == "" || *release == "" {
		fatal("--oracle-commit and --oracle-release are required when generating a new fixture")
	}
	fixture, err := buildPolicyFixture(*commit, *release)
	if err != nil {
		fatal("build policy fixture: %v", err)
	}
	content, err := marshalJSON(fixture)
	if err != nil {
		fatal("marshal policy fixture: %v", err)
	}
	if *check {
		existing, err := os.ReadFile(*output) // #nosec G304 -- explicit operator-selected fixture
		if err != nil {
			fatal("read policy fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("policy fixture (%s) is stale; run make policy-fixtures-generate", *output)
		}
		fmt.Printf("PASS policy fixture (%d validation, %d evaluation, %d tier cases)\n", len(fixture.ValidationCases), len(fixture.EvaluationCases), len(fixture.TierPresetCases))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write policy fixture: %v", err)
	}
	fmt.Printf("WROTE %s\n", *output)
}

func readFixture(path string) (policyFixture, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- explicit operator-selected fixture
	if err != nil {
		return policyFixture{}, err
	}
	var fixture policyFixture
	if err := json.Unmarshal(content, &fixture); err != nil {
		return policyFixture{}, err
	}
	if fixture.SchemaVersion != 1 {
		return policyFixture{}, fmt.Errorf("unsupported schema_version %d", fixture.SchemaVersion)
	}
	return fixture, nil
}

func marshalJSON(value any) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
