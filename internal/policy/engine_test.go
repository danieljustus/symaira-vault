package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestActionIsValid(t *testing.T) {
	tests := []struct {
		action Action
		want   bool
	}{
		{ActionAllow, true},
		{ActionDeny, true},
		{ActionPrompt, true},
		{ActionRequireBiometry, true},
		{Action("invalid"), false},
		{Action(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTimeRangeContains(t *testing.T) {
	tests := []struct {
		name  string
		tr    TimeRange
		check time.Time
		want  bool
	}{
		{
			name:  "within range",
			tr:    TimeRange{Start: "09:00", End: "17:00"},
			check: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			want:  true,
		},
		{
			name:  "before range",
			tr:    TimeRange{Start: "09:00", End: "17:00"},
			check: time.Date(2024, 1, 1, 8, 0, 0, 0, time.UTC),
			want:  false,
		},
		{
			name:  "after range",
			tr:    TimeRange{Start: "09:00", End: "17:00"},
			check: time.Date(2024, 1, 1, 18, 0, 0, 0, time.UTC),
			want:  false,
		},
		{
			name:  "exactly at start",
			tr:    TimeRange{Start: "09:00", End: "17:00"},
			check: time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC),
			want:  true,
		},
		{
			name:  "wrap around range - night shift",
			tr:    TimeRange{Start: "22:00", End: "06:00"},
			check: time.Date(2024, 1, 1, 23, 0, 0, 0, time.UTC),
			want:  true,
		},
		{
			name:  "wrap around range - early morning",
			tr:    TimeRange{Start: "22:00", End: "06:00"},
			check: time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC),
			want:  true,
		},
		{
			name:  "wrap around range - daytime",
			tr:    TimeRange{Start: "22:00", End: "06:00"},
			check: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tr.Contains(tt.check); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTimeRangeParse(t *testing.T) {
	tests := []struct {
		name    string
		tr      TimeRange
		wantErr bool
	}{
		{"valid", TimeRange{Start: "09:00", End: "17:00"}, false},
		{"invalid start", TimeRange{Start: "25:00", End: "17:00"}, true},
		{"invalid end", TimeRange{Start: "09:00", End: "invalid"}, true},
		{"empty start", TimeRange{Start: "", End: "17:00"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := tt.tr.Parse()
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{
			name: "valid policy",
			policy: Policy{
				Version: "1.0",
				Rules: []Rule{
					{Name: "rule1", Action: ActionAllow, Conditions: Conditions{AgentID: "*"}},
				},
			},
			wantErr: false,
		},
		{
			name:    "missing version",
			policy:  Policy{Rules: []Rule{{Name: "rule1", Action: ActionAllow}}},
			wantErr: true,
		},
		{
			name:    "no rules",
			policy:  Policy{Version: "1.0"},
			wantErr: true,
		},
		{
			name: "missing rule name",
			policy: Policy{
				Version: "1.0",
				Rules:   []Rule{{Action: ActionAllow}},
			},
			wantErr: true,
		},
		{
			name: "invalid action",
			policy: Policy{
				Version: "1.0",
				Rules:   []Rule{{Name: "rule1", Action: Action("invalid")}},
			},
			wantErr: true,
		},
		{
			name: "duplicate rule names",
			policy: Policy{
				Version: "1.0",
				Rules: []Rule{
					{Name: "rule1", Action: ActionAllow},
					{Name: "rule1", Action: ActionDeny},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid time of day",
			policy: Policy{
				Version: "1.0",
				Rules: []Rule{
					{Name: "rule1", Action: ActionAllow, Conditions: Conditions{TimeOfDay: &TimeRange{Start: "25:00", End: "17:00"}}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid action type",
			policy: Policy{
				Version: "1.0",
				Rules: []Rule{
					{Name: "rule1", Action: ActionAllow, Conditions: Conditions{ActionType: "invalid"}},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEngineEvaluate(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "allow dev for openclaw",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "openclaw",
					Tags:    []string{"dev"},
				},
				Action: ActionAllow,
			},
			{
				Name:     "require biometry for prod",
				Priority: 50,
				Conditions: Conditions{
					Tags: []string{"prod"},
				},
				Action: ActionRequireBiometry,
			},
			{
				Name:     "deny during off hours",
				Priority: 75,
				Conditions: Conditions{
					TimeOfDay: &TimeRange{Start: "22:00", End: "06:00"},
				},
				Action: ActionDeny,
			},
			{
				Name:     "allow writes for admin",
				Priority: 80,
				Conditions: Conditions{
					AgentID:    "admin",
					ActionType: "write",
				},
				Action: ActionAllow,
			},
			{
				Name:     "default deny",
				Priority: 0,
				Conditions: Conditions{
					AgentID: "*",
				},
				Action: ActionDeny,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	tests := []struct {
		name string
		ctx  EvalContext
		want Action
	}{
		{
			name: "openclaw with dev tag",
			ctx:  EvalContext{AgentID: "openclaw", Tags: []string{"dev"}, Now: now},
			want: ActionAllow,
		},
		{
			name: "openclaw with prod tag",
			ctx:  EvalContext{AgentID: "openclaw", Tags: []string{"prod"}, Now: now},
			want: ActionRequireBiometry,
		},
		{
			name: "any agent with prod tag",
			ctx:  EvalContext{AgentID: "other", Tags: []string{"prod"}, Now: now},
			want: ActionRequireBiometry,
		},
		{
			name: "off hours - higher priority allow wins",
			ctx:  EvalContext{AgentID: "openclaw", Tags: []string{"dev"}, Now: time.Date(2024, 1, 1, 23, 0, 0, 0, time.UTC)},
			want: ActionAllow,
		},
		{
			name: "admin write",
			ctx:  EvalContext{AgentID: "admin", ActionType: "write", Now: now},
			want: ActionAllow,
		},
		{
			name: "admin read",
			ctx:  EvalContext{AgentID: "admin", ActionType: "read", Now: now},
			want: ActionDeny,
		},
		{
			name: "unknown agent",
			ctx:  EvalContext{AgentID: "unknown", Now: now},
			want: ActionDeny,
		},
		{
			name: "no tags",
			ctx:  EvalContext{AgentID: "openclaw", Now: now},
			want: ActionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.Evaluate(tt.ctx)
			if got.Action != tt.want {
				t.Errorf("Evaluate() = %v, want %v", got.Action, tt.want)
			}
		})
	}
}

func TestEngineEvaluatePathMatching(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "allow project a",
				Priority: 100,
				Conditions: Conditions{
					Path: "~/dev/project-a/*",
				},
				Action: ActionAllow,
			},
			{
				Name:     "allow project b recursive",
				Priority: 90,
				Conditions: Conditions{
					Path: "~/dev/project-b/**",
				},
				Action: ActionAllow,
			},
			{
				Name:     "allow exact path",
				Priority: 80,
				Conditions: Conditions{
					Path: "~/exact/path",
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})
	home, _ := os.UserHomeDir()

	tests := []struct {
		name string
		path string
		want Action
	}{
		{
			name: "match project a direct child",
			path: filepath.Join(home, "dev", "project-a", "secret"),
			want: ActionAllow,
		},
		{
			name: "no match project a grandchild",
			path: filepath.Join(home, "dev", "project-a", "sub", "secret"),
			want: ActionDeny,
		},
		{
			name: "match project b recursive",
			path: filepath.Join(home, "dev", "project-b", "sub", "secret"),
			want: ActionAllow,
		},
		{
			name: "match exact path",
			path: filepath.Join(home, "exact", "path"),
			want: ActionAllow,
		},
		{
			name: "no match",
			path: filepath.Join(home, "other", "path"),
			want: ActionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := EvalContext{Path: tt.path, Now: time.Now()}
			got := engine.Evaluate(ctx)
			if got.Action != tt.want {
				t.Errorf("Evaluate() = %v, want %v", got.Action, tt.want)
			}
		})
	}
}

func TestEngineEvaluateWorkingDir(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "allow in project dir",
				Priority: 100,
				Conditions: Conditions{
					WorkingDir: "~/dev/project-a",
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})
	home, _ := os.UserHomeDir()

	tests := []struct {
		name string
		dir  string
		want Action
	}{
		{
			name: "exact match",
			dir:  filepath.Join(home, "dev", "project-a"),
			want: ActionAllow,
		},
		{
			name: "subdirectory match",
			dir:  filepath.Join(home, "dev", "project-a", "src"),
			want: ActionAllow,
		},
		{
			name: "no match",
			dir:  filepath.Join(home, "dev", "project-b"),
			want: ActionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := EvalContext{WorkingDir: tt.dir, Now: time.Now()}
			got := engine.Evaluate(ctx)
			if got.Action != tt.want {
				t.Errorf("Evaluate() = %v, want %v", got.Action, tt.want)
			}
		})
	}
}

func TestEngineEvaluateEnvVars(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "allow in ci",
				Priority: 100,
				Conditions: Conditions{
					EnvVars: map[string]string{"CI": "true"},
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	tests := []struct {
		name    string
		envVars map[string]string
		want    Action
	}{
		{
			name:    "matching env var",
			envVars: map[string]string{"CI": "true"},
			want:    ActionAllow,
		},
		{
			name:    "non-matching env var",
			envVars: map[string]string{"CI": "false"},
			want:    ActionDeny,
		},
		{
			name:    "missing env var",
			envVars: map[string]string{},
			want:    ActionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := EvalContext{EnvVars: tt.envVars, Now: time.Now()}
			got := engine.Evaluate(ctx)
			if got.Action != tt.want {
				t.Errorf("Evaluate() = %v, want %v", got.Action, tt.want)
			}
		})
	}
}

func TestEngineEvaluatePriority(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "high priority deny",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "test",
				},
				Action: ActionDeny,
			},
			{
				Name:     "low priority allow",
				Priority: 10,
				Conditions: Conditions{
					AgentID: "test",
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})
	ctx := EvalContext{AgentID: "test", Now: time.Now()}
	got := engine.Evaluate(ctx)
	if got.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v (higher priority should win)", got.Action, ActionDeny)
	}
}

func TestEngineEvaluateMultiplePolicies(t *testing.T) {
	p1 := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "policy1 allow",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "agent1",
				},
				Action: ActionAllow,
			},
		},
	}
	p2 := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "policy2 deny",
				Priority: 50,
				Conditions: Conditions{
					AgentID: "agent1",
				},
				Action: ActionDeny,
			},
		},
	}

	engine := NewEngine([]*Policy{p1, p2})
	ctx := EvalContext{AgentID: "agent1", Now: time.Now()}
	got := engine.Evaluate(ctx)
	if got.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v", got.Action, ActionAllow)
	}
}

func TestEngineEvaluateNilEngine(t *testing.T) {
	var engine *Engine
	ctx := EvalContext{AgentID: "test", Now: time.Now()}
	got := engine.Evaluate(ctx)
	if got.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v", got.Action, ActionDeny)
	}
}

func TestEngineEvaluateEmptyRules(t *testing.T) {
	engine := NewEngine([]*Policy{})
	ctx := EvalContext{AgentID: "test", Now: time.Now()}
	got := engine.Evaluate(ctx)
	if got.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v", got.Action, ActionDeny)
	}
}

func TestMatchPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*", "anything", true},
		{"", "anything", true},
		{"exact", "exact", true},
		{"exact", "other", false},
		{"~/dev/*", filepath.Join(home, "dev", "project"), true},
		{"~/dev/*", filepath.Join(home, "dev", "project", "sub"), false},
		{"~/dev/**", filepath.Join(home, "dev", "project", "sub"), true},
		{"~/exact/path", filepath.Join(home, "exact", "path"), true},
		{"prefix/", filepath.Join("prefix", "sub"), true},
		{"prefix/*", filepath.Join("prefix", "sub"), true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.pattern, tt.path), func(t *testing.T) {
			if got := matchPath(tt.pattern, tt.path); got != tt.want {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestMatchAnyTag(t *testing.T) {
	tests := []struct {
		required []string
		actual   []string
		want     bool
	}{
		{[]string{"dev"}, []string{"dev", "personal"}, true},
		{[]string{"dev", "prod"}, []string{"prod"}, true},
		{[]string{"dev"}, []string{"prod"}, false},
		{[]string{"dev"}, []string{}, false},
		{[]string{}, []string{"dev"}, false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v_%v", tt.required, tt.actual), func(t *testing.T) {
			if got := matchAnyTag(tt.required, tt.actual); got != tt.want {
				t.Errorf("matchAnyTag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "test-policy.yaml")

	content := `
version: "1.0"
description: "Test policy"
rules:
  - name: "allow dev"
    priority: 100
    conditions:
      agent_id: "openclaw"
      tags:
        - "dev"
    action: "allow"
`
	if err := os.WriteFile(policyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	policy, err := LoadPolicy(policyFile)
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}

	if policy.Version != "1.0" {
		t.Errorf("Version = %v, want %v", policy.Version, "1.0")
	}
	if len(policy.Rules) != 1 {
		t.Fatalf("Rules length = %v, want %v", len(policy.Rules), 1)
	}
	if policy.Rules[0].Name != "allow dev" {
		t.Errorf("Rule name = %v, want %v", policy.Rules[0].Name, "allow dev")
	}
	if policy.Rules[0].Action != ActionAllow {
		t.Errorf("Rule action = %v, want %v", policy.Rules[0].Action, ActionAllow)
	}
}

func TestLoadPolicyInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "invalid-policy.yaml")

	content := `
version: "1.0"
rules:
  - name: "invalid action"
    action: "not_an_action"
`
	if err := os.WriteFile(policyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	_, err := LoadPolicy(policyFile)
	if err == nil {
		t.Fatal("LoadPolicy() expected error, got nil")
	}
}

func TestLoadPoliciesFromDir(t *testing.T) {
	tmpDir := t.TempDir()

	content1 := `
version: "1.0"
rules:
  - name: "rule1"
    action: "allow"
`
	content2 := `
version: "1.0"
rules:
  - name: "rule2"
    action: "deny"
`

	if err := os.WriteFile(filepath.Join(tmpDir, "policy1.yaml"), []byte(content1), 0o600); err != nil {
		t.Fatalf("write policy1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "policy2.yml"), []byte(content2), 0o600); err != nil {
		t.Fatalf("write policy2: %v", err)
	}
	// Non-yaml file should be ignored
	if err := os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("readme"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}

	policies, err := LoadPoliciesFromDir(tmpDir)
	if err != nil {
		t.Fatalf("LoadPoliciesFromDir() error = %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("Policies length = %v, want %v", len(policies), 2)
	}
}

func TestContextProvider(t *testing.T) {
	cp := NewContextProvider()
	cp.SetWorkingDir("/tmp/test")
	cp.SetGitBranch("main")

	ctx := cp.BuildContext("agent1", "path/to/secret", "read", []string{"dev"})

	if ctx.AgentID != "agent1" {
		t.Errorf("AgentID = %v, want %v", ctx.AgentID, "agent1")
	}
	if ctx.Path != "path/to/secret" {
		t.Errorf("Path = %v, want %v", ctx.Path, "path/to/secret")
	}
	if ctx.WorkingDir != "/tmp/test" {
		t.Errorf("WorkingDir = %v, want %v", ctx.WorkingDir, "/tmp/test")
	}
	if ctx.EnvVars["GIT_BRANCH"] != "main" {
		t.Errorf("GitBranch = %v, want %v", ctx.EnvVars["GIT_BRANCH"], "main")
	}
}

func TestDetectProjectContext(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a go.mod
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module test\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	project := DetectProjectContext(filepath.Join(tmpDir, "src", "pkg"))
	if project != filepath.Base(tmpDir) {
		t.Errorf("DetectProjectContext() = %v, want %v", project, filepath.Base(tmpDir))
	}

	// No markers
	emptyDir := t.TempDir()
	project = DetectProjectContext(emptyDir)
	if project != "" {
		t.Errorf("DetectProjectContext() = %v, want empty", project)
	}
}

func TestYAMLUnmarshal(t *testing.T) {
	content := `
version: "1.0"
description: "Test policy"
rules:
  - name: "test rule"
    priority: 50
    conditions:
      agent_id: "*"
      path: "~/dev/*"
      tags:
        - "dev"
        - "staging"
      working_dir: "~/dev"
      time_of_day:
        start: "09:00"
        end: "17:00"
      env_vars:
        CI: "true"
      action: "read"
    action: "allow"
`

	var policy Policy
	if err := yaml.Unmarshal([]byte(content), &policy); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if policy.Version != "1.0" {
		t.Errorf("Version = %v, want %v", policy.Version, "1.0")
	}
	if len(policy.Rules) != 1 {
		t.Fatalf("Rules length = %v, want %v", len(policy.Rules), 1)
	}

	rule := policy.Rules[0]
	if rule.Name != "test rule" {
		t.Errorf("Name = %v, want %v", rule.Name, "test rule")
	}
	if rule.Priority != 50 {
		t.Errorf("Priority = %v, want %v", rule.Priority, 50)
	}
	if rule.Conditions.AgentID != "*" {
		t.Errorf("AgentID = %v, want %v", rule.Conditions.AgentID, "*")
	}
	if len(rule.Conditions.Tags) != 2 {
		t.Errorf("Tags length = %v, want %v", len(rule.Conditions.Tags), 2)
	}
	if rule.Conditions.TimeOfDay == nil {
		t.Fatal("TimeOfDay is nil")
	}
	if rule.Conditions.TimeOfDay.Start != "09:00" {
		t.Errorf("TimeOfDay.Start = %v, want %v", rule.Conditions.TimeOfDay.Start, "09:00")
	}
	if len(rule.Conditions.EnvVars) != 1 {
		t.Errorf("EnvVars length = %v, want %v", len(rule.Conditions.EnvVars), 1)
	}
	if rule.Conditions.ActionType != "read" {
		t.Errorf("ActionType = %v, want %v", rule.Conditions.ActionType, "read")
	}
}

func TestEngineEvaluateAllowedTools(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "allow list_entries only",
				Priority: 100,
				Conditions: Conditions{
					AgentID:      "restricted-agent",
					AllowedTools: []string{"list_entries", "get_entry"},
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	tests := []struct {
		name     string
		toolName string
		want     Action
	}{
		{
			name:     "allowed tool",
			toolName: "list_entries",
			want:     ActionAllow,
		},
		{
			name:     "another allowed tool",
			toolName: "get_entry",
			want:     ActionAllow,
		},
		{
			name:     "disallowed tool",
			toolName: "delete_entry",
			want:     ActionDeny,
		},
		{
			name:     "empty tool name",
			toolName: "",
			want:     ActionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := EvalContext{AgentID: "restricted-agent", ToolName: tt.toolName, Now: time.Now()}
			got := engine.Evaluate(ctx)
			if got.Action != tt.want {
				t.Errorf("Evaluate() = %v, want %v", got.Action, tt.want)
			}
		})
	}
}

func TestEngineEvaluateAllowedToolsEmpty(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "no tool restriction",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "any-agent",
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})
	ctx := EvalContext{AgentID: "any-agent", ToolName: "any_tool", Now: time.Now()}
	got := engine.Evaluate(ctx)
	if got.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v (no tool restriction should match any tool)", got.Action, ActionAllow)
	}
}

func TestEngineEvaluateRateLimitWithinLimits(t *testing.T) {
	rl := NewAgentRateLimiter()
	defer rl.Cleanup()

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "rate limited rule",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "agent1",
					RateLimit: &RateLimitCondition{
						MaxReadsPerHour: 10,
						MaxReadsPerDay:  50,
					},
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	ctx := EvalContext{AgentID: "agent1", Now: time.Now(), RateLimiter: rl}
	got := engine.Evaluate(ctx)
	if got.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v (within rate limit)", got.Action, ActionAllow)
	}
}

func TestEngineEvaluateRateLimitExceeded(t *testing.T) {
	rl := NewAgentRateLimiter()
	defer rl.Cleanup()

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "rate limited rule",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "agent1",
					RateLimit: &RateLimitCondition{
						MaxReadsPerHour: 1,
						MaxReadsPerDay:  5,
					},
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	// First call should succeed (rate limit = 1 per hour)
	ctx1 := EvalContext{AgentID: "agent1", Now: time.Now(), RateLimiter: rl}
	got1 := engine.Evaluate(ctx1)
	if got1.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v (first call within limit)", got1.Action, ActionAllow)
	}

	// Second call should be denied (exceeded hourly limit)
	ctx2 := EvalContext{AgentID: "agent1", Now: time.Now(), RateLimiter: rl}
	got2 := engine.Evaluate(ctx2)
	if got2.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v (rate limit exceeded)", got2.Action, ActionDeny)
	}
}

func TestEngineEvaluateRateLimitNoLimiter(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "rate limited rule",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "agent1",
					RateLimit: &RateLimitCondition{
						MaxReadsPerHour: 10,
					},
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	ctx := EvalContext{AgentID: "agent1", Now: time.Now()}
	got := engine.Evaluate(ctx)
	if got.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v (no rate limiter should deny)", got.Action, ActionDeny)
	}
}

func TestEngineEvaluateRateLimitDifferentAgents(t *testing.T) {
	rl := NewAgentRateLimiter()
	defer rl.Cleanup()

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "rate limited rule",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "*",
					RateLimit: &RateLimitCondition{
						MaxReadsPerHour: 2,
						MaxReadsPerDay:  10,
					},
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	// Agent A uses 2 calls (hits limit)
	for i := 0; i < 2; i++ {
		ctx := EvalContext{AgentID: "agent-a", Now: time.Now(), RateLimiter: rl}
		got := engine.Evaluate(ctx)
		if got.Action != ActionAllow {
			t.Errorf("agent-a call %d: Evaluate() = %v, want %v", i+1, got.Action, ActionAllow)
		}
	}

	// Agent A's third call should be denied
	ctxA := EvalContext{AgentID: "agent-a", Now: time.Now(), RateLimiter: rl}
	gotA := engine.Evaluate(ctxA)
	if gotA.Action != ActionDeny {
		t.Errorf("agent-a exceeded: Evaluate() = %v, want %v", gotA.Action, ActionDeny)
	}

	// Agent B should still be allowed (separate bucket)
	ctxB := EvalContext{AgentID: "agent-b", Now: time.Now(), RateLimiter: rl}
	gotB := engine.Evaluate(ctxB)
	if gotB.Action != ActionAllow {
		t.Errorf("agent-b: Evaluate() = %v, want %v", gotB.Action, ActionAllow)
	}
}

func TestEngineEvaluateMaxSecretsWithinLimit(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "max secrets rule",
				Priority: 100,
				Conditions: Conditions{
					AgentID:    "agent1",
					MaxSecrets: 3,
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	ctx := EvalContext{AgentID: "agent1", Now: time.Now(), SecretsAccessed: 0}
	got := engine.Evaluate(ctx)
	if got.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v (0 < 3, within limit)", got.Action, ActionAllow)
	}

	ctx2 := EvalContext{AgentID: "agent1", Now: time.Now(), SecretsAccessed: 2}
	got2 := engine.Evaluate(ctx2)
	if got2.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v (2 < 3, within limit)", got2.Action, ActionAllow)
	}
}

func TestEngineEvaluateMaxSecretsExceeded(t *testing.T) {
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "max secrets rule",
				Priority: 100,
				Conditions: Conditions{
					AgentID:    "agent1",
					MaxSecrets: 3,
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	ctx := EvalContext{AgentID: "agent1", Now: time.Now(), SecretsAccessed: 3}
	got := engine.Evaluate(ctx)
	if got.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v (3 >= 3, exceeded)", got.Action, ActionDeny)
	}

	ctx2 := EvalContext{AgentID: "agent1", Now: time.Now(), SecretsAccessed: 5}
	got2 := engine.Evaluate(ctx2)
	if got2.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v (5 >= 3, exceeded)", got2.Action, ActionDeny)
	}
}

func TestEngineEvaluateMaxSecretsZero(t *testing.T) {
	// MaxSecrets = 0 means no limit
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "no max secrets",
				Priority: 100,
				Conditions: Conditions{
					AgentID:    "agent1",
					MaxSecrets: 0,
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	ctx := EvalContext{AgentID: "agent1", Now: time.Now(), SecretsAccessed: 100}
	got := engine.Evaluate(ctx)
	if got.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v (0 means unlimited)", got.Action, ActionAllow)
	}
}

func TestEngineEvaluateMaxSecretsDefaultDeny(t *testing.T) {
	// Default deny rule should still work when max secrets is set
	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "allow agent1 up to 5 secrets",
				Priority: 100,
				Conditions: Conditions{
					AgentID:    "agent1",
					MaxSecrets: 5,
				},
				Action: ActionAllow,
			},
			{
				Name:     "default deny",
				Priority: 0,
				Conditions: Conditions{
					AgentID: "*",
				},
				Action: ActionDeny,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	// agent1 within limit
	ctx := EvalContext{AgentID: "agent1", Now: time.Now(), SecretsAccessed: 3}
	got := engine.Evaluate(ctx)
	if got.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v", got.Action, ActionAllow)
	}

	// agent1 exceeded limit
	ctx2 := EvalContext{AgentID: "agent1", Now: time.Now(), SecretsAccessed: 5}
	got2 := engine.Evaluate(ctx2)
	if got2.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v (exceeded max secrets, fallthrough to default)", got2.Action, ActionDeny)
	}

	// other agent denied by default
	ctx3 := EvalContext{AgentID: "agent2", Now: time.Now()}
	got3 := engine.Evaluate(ctx3)
	if got3.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v (unknown agent)", got3.Action, ActionDeny)
	}
}

func TestYAMLUnmarshalExtendedConditions(t *testing.T) {
	content := `
version: "1.0"
description: "Test policy with extended conditions"
rules:
  - name: "extended rule"
    priority: 50
    conditions:
      agent_id: "*"
      allowed_tools:
        - "list_entries"
        - "get_entry"
      rate_limit:
        max_reads_per_hour: 60
        max_reads_per_day: 500
      max_secrets: 10
    action: "allow"
`

	var policy Policy
	if err := yaml.Unmarshal([]byte(content), &policy); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if len(policy.Rules) != 1 {
		t.Fatalf("Rules length = %v, want %v", len(policy.Rules), 1)
	}

	rule := policy.Rules[0]
	if len(rule.Conditions.AllowedTools) != 2 {
		t.Errorf("AllowedTools length = %v, want %v", len(rule.Conditions.AllowedTools), 2)
	}
	if rule.Conditions.AllowedTools[0] != "list_entries" {
		t.Errorf("AllowedTools[0] = %v, want %v", rule.Conditions.AllowedTools[0], "list_entries")
	}
	if rule.Conditions.AllowedTools[1] != "get_entry" {
		t.Errorf("AllowedTools[1] = %v, want %v", rule.Conditions.AllowedTools[1], "get_entry")
	}
	if rule.Conditions.RateLimit == nil {
		t.Fatal("RateLimit is nil")
	}
	if rule.Conditions.RateLimit.MaxReadsPerHour != 60 {
		t.Errorf("RateLimit.MaxReadsPerHour = %v, want %v", rule.Conditions.RateLimit.MaxReadsPerHour, 60)
	}
	if rule.Conditions.RateLimit.MaxReadsPerDay != 500 {
		t.Errorf("RateLimit.MaxReadsPerDay = %v, want %v", rule.Conditions.RateLimit.MaxReadsPerDay, 500)
	}
	if rule.Conditions.MaxSecrets != 10 {
		t.Errorf("MaxSecrets = %v, want %v", rule.Conditions.MaxSecrets, 10)
	}
}

func TestMatchAllowedTool(t *testing.T) {
	tests := []struct {
		allowed  []string
		toolName string
		want     bool
	}{
		{[]string{"list_entries", "get_entry"}, "list_entries", true},
		{[]string{"list_entries", "get_entry"}, "get_entry", true},
		{[]string{"list_entries"}, "get_entry", false},
		{[]string{}, "any_tool", true},
		{[]string{"list_entries"}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			if got := matchAllowedTool(tt.allowed, tt.toolName); got != tt.want {
				t.Errorf("matchAllowedTool(%v, %q) = %v, want %v", tt.allowed, tt.toolName, got, tt.want)
			}
		})
	}
}

func TestEnginePerformance(t *testing.T) {
	rules := make([]Rule, 0, 100)
	for i := 0; i < 100; i++ {
		rules = append(rules, Rule{
			Name:       fmt.Sprintf("rule-%d", i),
			Priority:   100 - i,
			Conditions: Conditions{AgentID: fmt.Sprintf("agent-%d", i)},
			Action:     ActionAllow,
		})
	}

	policy := &Policy{Version: "1.0", Rules: rules}
	engine := NewEngine([]*Policy{policy})

	ctx := EvalContext{AgentID: "agent-99", Now: time.Now()}

	start := time.Now()
	iterations := 10000
	for i := 0; i < iterations; i++ {
		engine.Evaluate(ctx)
	}
	elapsed := time.Since(start)
	avg := elapsed / time.Duration(iterations)

	t.Logf("Average evaluation time: %v (total: %v for %d iterations)", avg, elapsed, iterations)

	// Should be well under 1ms per evaluation
	if avg > 1*time.Millisecond {
		t.Errorf("Average evaluation time %v exceeds 1ms threshold", avg)
	}
}

func TestEngineEvaluateAuditLogDenyRule(t *testing.T) {
	var loggedAction Action
	var loggedRule string

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "deny all",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "*",
				},
				Action: ActionDeny,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})
	ctx := EvalContext{
		AgentID: "agent1",
		Now:     time.Now(),
		AuditLogFunc: func(action Action, ruleName, reason string) {
			loggedAction = action
			loggedRule = ruleName
		},
	}
	got := engine.Evaluate(ctx)

	if got.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v", got.Action, ActionDeny)
	}
	if loggedAction != ActionDeny {
		t.Errorf("logged action = %v, want %v", loggedAction, ActionDeny)
	}
	if loggedRule != "deny all" {
		t.Errorf("logged rule = %v, want %v", loggedRule, "deny all")
	}
}

func TestEngineEvaluateAuditLogDefaultDeny(t *testing.T) {
	var logged bool

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "allow specific",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "specific-agent",
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})
	ctx := EvalContext{
		AgentID: "unknown-agent",
		Now:     time.Now(),
		AuditLogFunc: func(action Action, ruleName, reason string) {
			logged = true
			if action != ActionDeny {
				t.Errorf("logged action = %v, want %v", action, ActionDeny)
			}
			if reason != "no matching rule found, default deny" {
				t.Errorf("logged reason = %q, want %q", reason, "no matching rule found, default deny")
			}
		},
	}
	got := engine.Evaluate(ctx)

	if got.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v", got.Action, ActionDeny)
	}
	if !logged {
		t.Error("AuditLogFunc was not called for default deny")
	}
}

func TestEngineEvaluateAuditLogRateLimit(t *testing.T) {
	rl := NewAgentRateLimiter()
	defer rl.Cleanup()

	type auditCall struct {
		action   Action
		ruleName string
		reason   string
	}
	var calls []auditCall

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "rate limited",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "agent1",
					RateLimit: &RateLimitCondition{
						MaxReadsPerHour: 1,
						MaxReadsPerDay:  5,
					},
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	// First call should succeed (consume the only token)
	ctx1 := EvalContext{AgentID: "agent1", Now: time.Now(), RateLimiter: rl}
	got1 := engine.Evaluate(ctx1)
	if got1.Action != ActionAllow {
		t.Errorf("first call: Evaluate() = %v, want %v", got1.Action, ActionAllow)
	}

	// Second call should be rate limited and trigger audit log
	ctx2 := EvalContext{
		AgentID:     "agent1",
		Now:         time.Now(),
		RateLimiter: rl,
		AuditLogFunc: func(action Action, ruleName, reason string) {
			calls = append(calls, auditCall{action, ruleName, reason})
		},
	}
	got2 := engine.Evaluate(ctx2)
	if got2.Action != ActionDeny {
		t.Errorf("second call: Evaluate() = %v, want %v", got2.Action, ActionDeny)
	}
	if len(calls) == 0 {
		t.Fatal("AuditLogFunc was not called for rate limit")
	}
	// First call should be the rate limit rejection from matches()
	if calls[0].action != ActionDeny {
		t.Errorf("first audit call action = %v, want %v", calls[0].action, ActionDeny)
	}
	if calls[0].reason != "rate limit exceeded" {
		t.Errorf("first audit call reason = %q, want %q", calls[0].reason, "rate limit exceeded")
	}
	if calls[0].ruleName != "rate limited" {
		t.Errorf("first audit call rule = %v, want %v", calls[0].ruleName, "rate limited")
	}
	// Second call should be the default deny from Evaluate()
	if len(calls) > 1 {
		if calls[1].reason != "no matching rule found, default deny" {
			t.Errorf("second audit call reason = %q, want %q", calls[1].reason, "no matching rule found, default deny")
		}
	}
}

func TestEngineEvaluateAuditLogMaxSecrets(t *testing.T) {
	type auditCall struct {
		action   Action
		ruleName string
		reason   string
	}
	var calls []auditCall

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "max secrets",
				Priority: 100,
				Conditions: Conditions{
					AgentID:    "agent1",
					MaxSecrets: 5,
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})

	ctx := EvalContext{
		AgentID:         "agent1",
		Now:             time.Now(),
		SecretsAccessed: 5,
		AuditLogFunc: func(action Action, ruleName, reason string) {
			calls = append(calls, auditCall{action, ruleName, reason})
		},
	}
	got := engine.Evaluate(ctx)
	if got.Action != ActionDeny {
		t.Errorf("Evaluate() = %v, want %v", got.Action, ActionDeny)
	}
	if len(calls) == 0 {
		t.Fatal("AuditLogFunc was not called for max secrets")
	}
	// First call should be the max secrets rejection from matches()
	if calls[0].action != ActionDeny {
		t.Errorf("first audit call action = %v, want %v", calls[0].action, ActionDeny)
	}
	if calls[0].reason != "max secrets exceeded: 5 >= 5" {
		t.Errorf("first audit call reason = %q, want %q", calls[0].reason, "max secrets exceeded: 5 >= 5")
	}
	if calls[0].ruleName != "max secrets" {
		t.Errorf("first audit call rule = %v, want %v", calls[0].ruleName, "max secrets")
	}
}

func TestEngineEvaluateAuditLogAllowNoLog(t *testing.T) {
	var logged bool

	policy := &Policy{
		Version: "1.0",
		Rules: []Rule{
			{
				Name:     "allow all",
				Priority: 100,
				Conditions: Conditions{
					AgentID: "*",
				},
				Action: ActionAllow,
			},
		},
	}

	engine := NewEngine([]*Policy{policy})
	ctx := EvalContext{
		AgentID: "agent1",
		Now:     time.Now(),
		AuditLogFunc: func(action Action, ruleName, reason string) {
			logged = true
		},
	}
	got := engine.Evaluate(ctx)
	if got.Action != ActionAllow {
		t.Errorf("Evaluate() = %v, want %v", got.Action, ActionAllow)
	}
	if logged {
		t.Error("AuditLogFunc should not be called for allow actions")
	}
}

func TestDefaultPolicyDir(t *testing.T) {
	dir := DefaultPolicyDir()
	if dir == "" {
		t.Skip("no home directory available")
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("DefaultPolicyDir() = %q, want absolute path", dir)
	}
}
