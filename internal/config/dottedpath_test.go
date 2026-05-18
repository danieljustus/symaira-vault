package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadConfigNode_ValidFile(t *testing.T) {
	content := []byte("vaultDir: /test\nagents:\n  test:\n    canWrite: true\n")
	path := writeTempFile(t, content)

	root, err := LoadConfigNode(path)
	if err != nil {
		t.Fatalf("LoadConfigNode() error = %v", err)
	}
	if root == nil {
		t.Fatal("LoadConfigNode() returned nil")
	}
}

func TestLoadConfigNode_MissingFile(t *testing.T) {
	_, err := LoadConfigNode(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("LoadConfigNode() expected error for missing file")
	}
}

func TestLoadConfigNode_InvalidYAML(t *testing.T) {
	path := writeTempFile(t, []byte("vaultDir: [unterminated\n"))
	_, err := LoadConfigNode(path)
	if err == nil {
		t.Fatal("LoadConfigNode() expected error for invalid YAML")
	}
}

func TestSaveConfigNode_RoundTrip(t *testing.T) {
	original := []byte("vaultDir: ~/.openpass\nagents:\n  default:\n    canWrite: false\n")
	srcPath := writeTempFile(t, original)
	destPath := filepath.Join(t.TempDir(), "config.yaml")

	root, err := LoadConfigNode(srcPath)
	if err != nil {
		t.Fatalf("LoadConfigNode() error = %v", err)
	}

	if err := SaveConfigNode(destPath, root); err != nil {
		t.Fatalf("SaveConfigNode() error = %v", err)
	}

	loaded, err := LoadConfigNode(destPath)
	if err != nil {
		t.Fatalf("LoadConfigNode() after save error = %v", err)
	}

	v, err := GetConfigValue(loaded, "vaultDir")
	if err != nil {
		t.Fatalf("GetConfigValue(vaultDir) error = %v", err)
	}
	if v.Value != "~/.openpass" {
		t.Errorf("vaultDir = %q, want ~/.openpass", v.Value)
	}
}

func TestGetConfigValue_TopLevel(t *testing.T) {
	root := mustParseYAML(t, "vaultDir: /my/vault\n")
	v, err := GetConfigValue(root, "vaultDir")
	if err != nil {
		t.Fatalf("GetConfigValue() error = %v", err)
	}
	if v.Value != "/my/vault" {
		t.Errorf("vaultDir = %q, want /my/vault", v.Value)
	}
}

func TestGetConfigValue_Nested(t *testing.T) {
	root := mustParseYAML(t, "agents:\n  claude:\n    canWrite: true\n")

	v, err := GetConfigValue(root, "agents.claude.canWrite")
	if err != nil {
		t.Fatalf("GetConfigValue() error = %v", err)
	}
	if v.Value != "true" {
		t.Errorf("canWrite = %q, want true", v.Value)
	}
}

func TestGetConfigValue_NotFound(t *testing.T) {
	root := mustParseYAML(t, "vaultDir: /test\n")
	_, err := GetConfigValue(root, "nonexistent.key")
	if err == nil {
		t.Fatal("GetConfigValue() expected error for missing key")
	}
}

func TestGetConfigValue_DeepNested(t *testing.T) {
	root := mustParseYAML(t, "agents:\n  codex:\n    approvalMode: deny\n    allowedPaths:\n      - work/\n")

	v, err := GetConfigValue(root, "agents.codex.approvalMode")
	if err != nil {
		t.Fatalf("GetConfigValue(agents.codex.approvalMode) error = %v", err)
	}
	if v.Value != "deny" {
		t.Errorf("approvalMode = %q, want deny", v.Value)
	}

	v2, err := GetConfigValue(root, "agents.codex.allowedPaths")
	if err != nil {
		t.Fatalf("GetConfigValue(agents.codex.allowedPaths) error = %v", err)
	}
	if v2.Kind != yaml.SequenceNode {
		t.Errorf("allowedPaths kind = %d, want SequenceNode", v2.Kind)
	}
}

func TestSetConfigValue_CreateNew(t *testing.T) {
	root := mustParseYAML(t, "vaultDir: /old\n")

	if err := SetConfigValue(root, "vaultDir", "/new"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "vaultDir")
	if v.Value != "/new" {
		t.Errorf("vaultDir = %q, want /new", v.Value)
	}
}

func TestSetConfigValue_CreateNewKey(t *testing.T) {
	root := mustParseYAML(t, "vaultDir: /test\n")

	if err := SetConfigValue(root, "sessionTimeout", "30m"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "sessionTimeout")
	if v.Value != "30m" {
		t.Errorf("sessionTimeout = %q, want 30m", v.Value)
	}
}

func TestSetConfigValue_CreateNested(t *testing.T) {
	root := mustParseYAML(t, "{}\n")

	if err := SetConfigValue(root, "agents.claude.canWrite", "true"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "agents.claude.canWrite")
	if v.Value != "true" {
		t.Errorf("canWrite = %q, want true", v.Value)
	}
}

func TestSetConfigValue_BoolValue(t *testing.T) {
	root := mustParseYAML(t, "agents:\n  test:\n    canWrite: false\n")

	if err := SetConfigValue(root, "agents.test.canWrite", "true"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "agents.test.canWrite")
	if v.Tag != "!!bool" {
		t.Errorf("tag = %q, want !!bool", v.Tag)
	}
	if v.Value != "true" {
		t.Errorf("Value = %q, want true", v.Value)
	}
}

func TestSetConfigValue_IntValue(t *testing.T) {
	root := mustParseYAML(t, "mcp:\n  port: 8080\n")

	if err := SetConfigValue(root, "mcp.port", "9090"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "mcp.port")
	if v.Tag != "!!int" {
		t.Errorf("tag = %q, want !!int", v.Tag)
	}
	if v.Value != "9090" {
		t.Errorf("Value = %q, want 9090", v.Value)
	}
}

func TestSetConfigValue_ListValue(t *testing.T) {
	root := mustParseYAML(t, "agents:\n  test:\n    allowedPaths: []\n")

	if err := SetConfigValue(root, "agents.test.allowedPaths", "[work/]"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "agents.test.allowedPaths")
	if v.Kind != yaml.SequenceNode {
		t.Errorf("kind = %d, want SequenceNode (%d)", v.Kind, yaml.SequenceNode)
	}
	if len(v.Content) != 1 {
		t.Errorf("Content len = %d, want 1", len(v.Content))
	}
}

func TestSetConfigValue_OverwriteWithDifferentType(t *testing.T) {
	root := mustParseYAML(t, "agents:\n  test:\n    canWrite: true\n")

	if err := SetConfigValue(root, "agents.test.canWrite", "false"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "agents.test.canWrite")
	if v.Value != "false" {
		t.Errorf("canWrite = %q, want false", v.Value)
	}
}

func TestSetConfigValue_StringValue(t *testing.T) {
	root := mustParseYAML(t, "{}\n")

	if err := SetConfigValue(root, "defaultAgent", "my-agent"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "defaultAgent")
	if v.Tag != "!!str" {
		t.Errorf("tag = %q, want !!str", v.Tag)
	}
	if v.Value != "my-agent" {
		t.Errorf("Value = %q, want my-agent", v.Value)
	}
}

func TestSetConfigValue_DottedValue(t *testing.T) {
	root := mustParseYAML(t, "{}\n")

	if err := SetConfigValue(root, "agents.claude.code.canWrite", "true"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "agents.claude.code.canWrite")
	if v.Value != "true" || v.Tag != "!!bool" {
		t.Errorf("got tag=%q value=%q, want !!bool true", v.Tag, v.Value)
	}
}

func TestConfigTreeKeys(t *testing.T) {
	root := mustParseYAML(t, "vaultDir: /test\nagents:\n  a:\n    canWrite: true\n  b:\n    tier: basic\n")

	keys := ConfigTreeKeys(root)
	expected := []string{"vaultDir", "agents.a.canWrite", "agents.b.tier"}
	for _, exp := range expected {
		found := false
		for _, k := range keys {
			if k == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing key %q in tree keys: %v", exp, keys)
		}
	}
}

func TestConfigTreeKeys_Empty(t *testing.T) {
	keys := ConfigTreeKeys(nil)
	if keys != nil && len(keys) != 0 {
		t.Errorf("expected empty keys, got %v", keys)
	}

	root := mustParseYAML(t, "{}\n")
	keys = ConfigTreeKeys(root)
	if len(keys) != 0 {
		t.Errorf("expected no keys for empty config, got %v", keys)
	}
}

func TestNodeToString_Scalar(t *testing.T) {
	root := mustParseYAML(t, "key: hello\n")
	v, _ := GetConfigValue(root, "key")
	s := NodeToString(v)
	if s != "hello" {
		t.Errorf("NodeToString = %q, want hello", s)
	}
}

func TestNodeToString_Mapping(t *testing.T) {
	root := mustParseYAML(t, "outer:\n  inner: value\n")
	v, _ := GetConfigValue(root, "outer")
	s := NodeToString(v)
	if !strings.Contains(s, "inner:") || !strings.Contains(s, "value") {
		t.Errorf("NodeToString mapping = %q, should contain inner and value", s)
	}
}

func TestNodeToString_Sequence(t *testing.T) {
	root := mustParseYAML(t, "list: [a, b]\n")
	v, _ := GetConfigValue(root, "list")
	s := NodeToString(v)
	if s != "a" && s != "b" && !strings.Contains(s, "a") && !strings.Contains(s, "[a, b]") {
		t.Errorf("NodeToString sequence = %q, should contain the elements a, b", s)
	}
}

func TestKnownConfigKeys_NotEmpty(t *testing.T) {
	keys := KnownConfigKeys()
	if len(keys) == 0 {
		t.Fatal("KnownConfigKeys() returned empty slice")
	}
	if keys[0] != "vaultDir" {
		t.Errorf("first key = %q, want vaultDir", keys[0])
	}
}

func TestDefaultConfigFilePath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir")
	}

	path, err := DefaultConfigFilePath()
	if err != nil {
		t.Fatalf("DefaultConfigFilePath() error = %v", err)
	}
	if !strings.HasPrefix(path, home) {
		t.Errorf("path = %q, should start with home %q", path, home)
	}
	if !strings.HasSuffix(path, "/.openpass/config.yaml") && !strings.HasSuffix(path, "\\.openpass\\config.yaml") {
		t.Errorf("path = %q, should end with .openpass/config.yaml", path)
	}
}

func TestSetConfigValue_DeepNestedOverride(t *testing.T) {
	root := mustParseYAML(t, "agents:\n  test:\n    sub:\n      key: old\n")

	if err := SetConfigValue(root, "agents.test.sub.key", "new"); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "agents.test.sub.key")
	if v.Value != "new" {
		t.Errorf("got %q, want new", v.Value)
	}
}

func TestSetConfigValue_InferTypeEmptyString(t *testing.T) {
	root := mustParseYAML(t, "{}\n")

	if err := SetConfigValue(root, "vaultDir", ""); err != nil {
		t.Fatalf("SetConfigValue() error = %v", err)
	}

	v, _ := GetConfigValue(root, "vaultDir")
	if v.Tag != "!!str" || v.Value != "" {
		t.Errorf("got tag=%q value=%q, want !!str empty", v.Tag, v.Value)
	}
}

func mustParseYAML(t *testing.T, yamlContent string) *yaml.Node {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(yamlContent), &root); err != nil {
		t.Fatalf("yaml.Unmarshal error: %v", err)
	}
	return &root
}
