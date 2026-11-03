package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// contextOracleCommit is the commit whose policy/context sources this fixture
// freezes. context.go, engine.go, types.go and secrets/filter.go are
// byte-identical to the blobs at this commit; the generator refuses to run
// otherwise.
const contextOracleCommit = "d1cd0f97ac550bc3020bc86b0514989f8d28d95c"

var contextOracleSources = []string{
	"internal/policy/context.go",
	"internal/policy/engine.go",
	"internal/policy/types.go",
	"internal/secrets/filter.go",
}

type contextFixtureInput struct {
	Name       string   `json:"name"`
	Home       string   `json:"home"`
	HomeUnset  bool     `json:"home_unset,omitempty"`
	WorkingDir string   `json:"working_dir"`
	GitBranch  string   `json:"git_branch"`
	AgentID    string   `json:"agent_id"`
	Path       string   `json:"path"`
	ActionType string   `json:"action_type"`
	Tags       []string `json:"tags"`
}

type contextFixtureOutput struct {
	AgentID    string            `json:"agent_id"`
	Path       string            `json:"path"`
	Tags       []string          `json:"tags"`
	WorkingDir string            `json:"working_dir"`
	HomeDir    string            `json:"home_dir"`
	EnvVars    map[string]string `json:"env_vars"`
	ActionType string            `json:"action_type"`
	ToolName   string            `json:"tool_name"`
}

type contextFixtureCase struct {
	contextFixtureInput
	Context contextFixtureOutput `json:"context"`
}

type contextFixtureRule struct {
	Name       string `json:"name"`
	Priority   int    `json:"priority,omitempty"`
	Action     string `json:"action"`
	Path       string `json:"path,omitempty"`
	WorkingDir string `json:"working_dir,omitempty"`
	ActionType string `json:"action_type,omitempty"`
	// Env maps to Conditions.EnvVars.
	Env          map[string]string `json:"env,omitempty"`
	AllowedTools []string          `json:"allowed_tools,omitempty"`
}

type contextFixtureEvalCase struct {
	Name   string               `json:"name"`
	Rules  []contextFixtureRule `json:"rules"`
	Input  contextFixtureInput  `json:"input"`
	Action string               `json:"action"`
	Rule   string               `json:"rule_name"`
	Match  bool                 `json:"matched"`
}

func contextFixtureInputs() []contextFixtureInput {
	return []contextFixtureInput{
		{Name: "plain", Home: "/home/dev", WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "ssh/prod", ActionType: "get"},
		{Name: "path_cleaned", Home: "/home/dev", WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "ssh//keys/../prod/", ActionType: "run"},
		{Name: "path_empty", Home: "/home/dev", WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "", ActionType: "get"},
		{Name: "path_dot_result", Home: "/home/dev", WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "a/..", ActionType: "get"},
		{Name: "path_parent_escape", Home: "/home/dev", WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "../x/./y", ActionType: "get"},
		{Name: "working_dir_cleaned", Home: "/home/dev/", WorkingDir: "/work/./repo/src/../", GitBranch: "feature/x", AgentID: "agent", Path: "p", ActionType: "get"},
		{Name: "tags_passed_through", Home: "/home/dev", WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "p", ActionType: "get", Tags: []string{"prod", "ci"}},
		{Name: "home_unset", HomeUnset: true, WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "p", ActionType: "get"},
		{Name: "home_empty", Home: "", WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "p", ActionType: "get"},
		{Name: "home_unclean_env_raw", Home: "/home//dev/./", WorkingDir: "/work/repo", GitBranch: "main", AgentID: "agent", Path: "p", ActionType: "get"},
		// An unresolvable directory makes git fail, so the branch is deterministically "".
		{Name: "unresolvable_git_branch", Home: "/home/dev", WorkingDir: "/nonexistent-policy-fixture-dir", GitBranch: "", AgentID: "agent", Path: "p", ActionType: "get"},
		{Name: "root_working_dir", Home: "/", WorkingDir: "/", GitBranch: "main", AgentID: "agent", Path: "/abs/../etc", ActionType: "delete"},
	}
}

func buildContextForFixture(t *testing.T, in contextFixtureInput) EvalContext {
	t.Helper()
	t.Setenv("HOME", in.Home)
	if in.HomeUnset {
		if err := os.Unsetenv("HOME"); err != nil {
			t.Fatal(err)
		}
	}
	cp := NewContextProvider()
	cp.SetWorkingDir(in.WorkingDir)
	cp.SetGitBranch(in.GitBranch)
	return cp.BuildContext(in.AgentID, in.Path, in.ActionType, in.Tags)
}

func contextFixtureOutputOf(ctx EvalContext) contextFixtureOutput {
	return contextFixtureOutput{
		AgentID: ctx.AgentID, Path: ctx.Path, Tags: ctx.Tags, WorkingDir: ctx.WorkingDir,
		HomeDir: ctx.HomeDir, EnvVars: ctx.EnvVars, ActionType: ctx.ActionType, ToolName: ctx.ToolName,
	}
}

func contextFixtureEvalPolicies() []struct {
	name  string
	rules []contextFixtureRule
	input contextFixtureInput
} {
	base := contextFixtureInput{Home: "/home/dev", WorkingDir: "/work/repo", GitBranch: "feature/x", AgentID: "agent", Path: "/home/dev/vault/prod/key", ActionType: "get"}
	with := func(name string, mutate func(*contextFixtureInput)) contextFixtureInput {
		in := base
		in.Name = name
		if mutate != nil {
			mutate(&in)
		}
		return in
	}
	allowAll := contextFixtureRule{Name: "allow-all", Action: "allow"}
	return []struct {
		name  string
		rules []contextFixtureRule
		input contextFixtureInput
	}{
		{"deny_allowed_tools_applies_to_every_tool",
			[]contextFixtureRule{{Name: "deny-x", Priority: 10, Action: "deny", AllowedTools: []string{"X"}}, allowAll},
			with("deny_allowed_tools_applies_to_every_tool", nil)},
		{"allow_allowed_tools_applies_to_every_tool",
			[]contextFixtureRule{{Name: "allow-x", Action: "allow", AllowedTools: []string{"X"}}},
			with("allow_allowed_tools_applies_to_every_tool", nil)},
		{"prompt_allowed_tools_applies_to_every_tool",
			[]contextFixtureRule{{Name: "prompt-x", Priority: 10, Action: "prompt", AllowedTools: []string{"X"}}, allowAll},
			with("prompt_allowed_tools_applies_to_every_tool", nil)},
		{"biometry_allowed_tools_applies_to_every_tool",
			[]contextFixtureRule{{Name: "bio-x", Priority: 10, Action: "require_biometry", AllowedTools: []string{"X"}}, allowAll},
			with("biometry_allowed_tools_applies_to_every_tool", nil)},
		{"deny_home_relative_path_hit",
			[]contextFixtureRule{{Name: "deny-vault", Priority: 10, Action: "deny", Path: "~/vault/**"}, allowAll},
			with("deny_home_relative_path_hit", nil)},
		{"deny_home_relative_path_miss",
			[]contextFixtureRule{{Name: "deny-vault", Priority: 10, Action: "deny", Path: "~/vault/**"}, allowAll},
			with("deny_home_relative_path_miss", func(in *contextFixtureInput) { in.Path = "/home/dev/other" })},
		{"deny_home_relative_path_home_unset",
			[]contextFixtureRule{{Name: "deny-vault", Priority: 10, Action: "deny", Path: "~/vault/**"}, allowAll},
			with("deny_home_relative_path_home_unset", func(in *contextFixtureInput) { in.Home = ""; in.HomeUnset = true })},
		{"deny_working_dir_hit",
			[]contextFixtureRule{{Name: "deny-wd", Priority: 10, Action: "deny", WorkingDir: "/work/repo/**"}, allowAll},
			with("deny_working_dir_hit", func(in *contextFixtureInput) { in.WorkingDir = "/work/repo/./src/" })},
		{"deny_working_dir_miss",
			[]contextFixtureRule{{Name: "deny-wd", Priority: 10, Action: "deny", WorkingDir: "/work/repo/**"}, allowAll},
			with("deny_working_dir_miss", func(in *contextFixtureInput) { in.WorkingDir = "/elsewhere" })},
		{"deny_working_dir_home_relative",
			[]contextFixtureRule{{Name: "deny-wd", Priority: 10, Action: "deny", WorkingDir: "~/proj/**"}, allowAll},
			with("deny_working_dir_home_relative", func(in *contextFixtureInput) { in.WorkingDir = "/home/dev/proj/a" })},
		{"deny_env_git_branch_hit",
			[]contextFixtureRule{{Name: "deny-branch", Priority: 10, Action: "deny", Env: map[string]string{"GIT_BRANCH": "feature/x"}}, allowAll},
			with("deny_env_git_branch_hit", nil)},
		{"deny_env_git_branch_miss",
			[]contextFixtureRule{{Name: "deny-branch", Priority: 10, Action: "deny", Env: map[string]string{"GIT_BRANCH": "feature/x"}}, allowAll},
			with("deny_env_git_branch_miss", func(in *contextFixtureInput) { in.GitBranch = "main" })},
		{"deny_env_home_raw_value",
			[]contextFixtureRule{{Name: "deny-home", Priority: 10, Action: "deny", Env: map[string]string{"HOME": "/home/dev"}}, allowAll},
			with("deny_env_home_raw_value", nil)},
		{"deny_env_home_wildcard_present_when_unset",
			[]contextFixtureRule{{Name: "deny-home", Priority: 10, Action: "deny", Env: map[string]string{"HOME": "*"}}, allowAll},
			with("deny_env_home_wildcard_present_when_unset", func(in *contextFixtureInput) { in.Home = ""; in.HomeUnset = true })},
		{"deny_env_git_branch_wildcard_present_when_empty",
			[]contextFixtureRule{{Name: "deny-branch", Priority: 10, Action: "deny", Env: map[string]string{"GIT_BRANCH": "*"}}, allowAll},
			with("deny_env_git_branch_wildcard_present_when_empty", func(in *contextFixtureInput) { in.GitBranch = ""; in.WorkingDir = "/nonexistent-policy-fixture-dir" })},
		{"deny_env_unknown_key_never_present",
			[]contextFixtureRule{{Name: "deny-ci", Priority: 10, Action: "deny", Env: map[string]string{"CI": "*"}}, allowAll},
			with("deny_env_unknown_key_never_present", nil)},
		{"deny_action_type_with_allowed_tools",
			[]contextFixtureRule{{Name: "deny-run", Priority: 10, Action: "deny", ActionType: "run", AllowedTools: []string{"get_entry"}}, allowAll},
			with("deny_action_type_with_allowed_tools", func(in *contextFixtureInput) { in.ActionType = "run" })},
	}
}

func goFixturePolicy(rules []contextFixtureRule) *Policy {
	policy := &Policy{Version: "1.0"}
	for _, rule := range rules {
		policy.Rules = append(policy.Rules, Rule{
			Name: rule.Name, Priority: rule.Priority, Action: Action(rule.Action),
			Conditions: Conditions{
				Path: rule.Path, WorkingDir: rule.WorkingDir, ActionType: rule.ActionType,
				EnvVars: rule.Env, AllowedTools: rule.AllowedTools,
			},
		})
	}
	return policy
}

func contextFixtureDigest(t *testing.T, root string, pinned bool) string {
	t.Helper()
	h := sha256.New()
	for _, file := range contextOracleSources {
		var content []byte
		var err error
		if pinned {
			cmd := exec.Command("git", "show", contextOracleCommit+":"+file)
			cmd.Dir = root
			content, err = cmd.Output()
		} else {
			content, err = os.ReadFile(filepath.Join(root, file)) // #nosec G304 -- fixed in-repo oracle sources
		}
		if err != nil {
			t.Fatalf("read %s (pinned=%v): %v", file, pinned, err)
		}
		fmt.Fprintf(h, "%s\x00", file)
		_, _ = h.Write(content)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestGeneratePolicyBuildContextFixture freezes Go's BuildContext field
// mapping and the policy outcomes it produces, for the Rust port to replay.
// Generate: SYMAIRA_GENERATE_POLICY_CONTEXT_FIXTURE=1; verify: ..._CHECK_...=1.
func TestGeneratePolicyBuildContextFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_POLICY_CONTEXT_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_POLICY_CONTEXT_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set the policy build-context fixture generate/check flag")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	pinned := contextFixtureDigest(t, root, true)
	if working := contextFixtureDigest(t, root, false); working != pinned {
		t.Fatalf("policy context sources differ from pinned oracle: working=%s pinned=%s", working, pinned)
	}

	var cases []contextFixtureCase
	for _, in := range contextFixtureInputs() {
		ctx := buildContextForFixture(t, in)
		cases = append(cases, contextFixtureCase{contextFixtureInput: in, Context: contextFixtureOutputOf(ctx)})
	}
	var evals []contextFixtureEvalCase
	for _, scenario := range contextFixtureEvalPolicies() {
		ctx := buildContextForFixture(t, scenario.input)
		result := NewEngine([]*Policy{goFixturePolicy(scenario.rules)}).Evaluate(ctx)
		evals = append(evals, contextFixtureEvalCase{
			Name: scenario.name, Rules: scenario.rules, Input: scenario.input,
			Action: string(result.Action), Rule: result.RuleName, Match: result.Matched,
		})
	}
	fixture := struct {
		SchemaVersion int `json:"schema_version"`
		Oracle        struct {
			CommitSHA    string   `json:"commit_sha"`
			SourceFiles  []string `json:"source_files"`
			SourceDigest string   `json:"source_digest"`
		} `json:"oracle"`
		Cases     []contextFixtureCase     `json:"cases"`
		EvalCases []contextFixtureEvalCase `json:"eval_cases"`
	}{SchemaVersion: 1, Cases: cases, EvalCases: evals}
	fixture.Oracle.CommitSHA = contextOracleCommit
	fixture.Oracle.SourceFiles = contextOracleSources
	fixture.Oracle.SourceDigest = pinned
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	output := filepath.Join(root, "testdata/port/mcp/policy-build-context.json")
	if check {
		actual, err := os.ReadFile(output) // #nosec G304 -- fixed in-repo fixture path
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(data) {
			t.Fatal("policy build-context fixture is stale")
		}
		return
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
