package mcp

import (
	"strings"
	"testing"
)

func TestPromptDefinitions_StableInvariants(t *testing.T) {
	defs := promptDefinitions()
	if len(defs) == 0 {
		t.Fatal("promptDefinitions() returned no prompts")
	}
	seen := map[string]bool{}
	for _, def := range defs {
		if def.Name == "" {
			t.Error("prompt with empty name")
		}
		if def.Description == "" {
			t.Errorf("prompt %q has empty description", def.Name)
		}
		if def.Builder == nil {
			t.Errorf("prompt %q has nil Builder", def.Name)
		}
		if seen[def.Name] {
			t.Errorf("duplicate prompt name %q", def.Name)
		}
		seen[def.Name] = true

		msgs := def.Builder(map[string]string{})
		if len(msgs) == 0 {
			t.Errorf("prompt %q builder produced no messages", def.Name)
		}
		for i, m := range msgs {
			if m.Role != "user" && m.Role != "assistant" {
				t.Errorf("prompt %q msg[%d] has invalid role %q", def.Name, i, m.Role)
			}
			if strings.TrimSpace(m.Text) == "" {
				t.Errorf("prompt %q msg[%d] has empty text", def.Name, i)
			}
		}
	}

	expected := []string{"add-credential", "rotate-credential", "find-and-use", "share-credential"}
	for _, name := range expected {
		if !seen[name] {
			t.Errorf("missing expected prompt %q", name)
		}
	}
}

func TestFindPromptDefinition(t *testing.T) {
	if _, ok := findPromptDefinition("add-credential"); !ok {
		t.Error("findPromptDefinition(add-credential) should succeed")
	}
	if _, ok := findPromptDefinition("does-not-exist"); ok {
		t.Error("findPromptDefinition for unknown name should fail")
	}
}

func TestPromptsListPayload(t *testing.T) {
	list := promptsListPayload()
	if len(list) == 0 {
		t.Fatal("promptsListPayload returned empty list")
	}
	for _, p := range list {
		if _, ok := p["name"].(string); !ok {
			t.Errorf("prompt missing name string: %+v", p)
		}
		if _, ok := p["description"].(string); !ok {
			t.Errorf("prompt missing description string: %+v", p)
		}
		if _, ok := p["arguments"].([]map[string]any); !ok {
			t.Errorf("prompt missing arguments slice: %+v", p)
		}
	}
}

func TestPromptGetPayload_AddCredentialSubstitutesService(t *testing.T) {
	def, ok := findPromptDefinition("add-credential")
	if !ok {
		t.Fatal("add-credential prompt missing")
	}
	out := promptGetPayload(def, map[string]string{"service_name": "GitHub API"})
	msgs, _ := out["messages"].([]map[string]any)
	if len(msgs) == 0 {
		t.Fatal("no messages rendered")
	}
	text, _ := msgs[0]["content"].(map[string]any)["text"].(string)
	if !strings.Contains(text, "GitHub API") {
		t.Errorf("rendered text should include service_name: %s", text)
	}
	if !strings.Contains(text, "github-api") {
		t.Errorf("rendered text should include slugified path 'github-api': %s", text)
	}
	if !strings.Contains(text, "request_credential") {
		t.Errorf("add-credential prompt must instruct the agent to use request_credential: %s", text)
	}
}

func TestPromptGetPayload_RotateUsesPath(t *testing.T) {
	def, _ := findPromptDefinition("rotate-credential")
	out := promptGetPayload(def, map[string]string{"path": "aws/prod", "length": "48"})
	msgs, _ := out["messages"].([]map[string]any)
	text, _ := msgs[0]["content"].(map[string]any)["text"].(string)
	for _, want := range []string{"aws/prod", "48", "generate_password", "set_entry_field"} {
		if !strings.Contains(text, want) {
			t.Errorf("rotate prompt missing %q in:\n%s", want, text)
		}
	}
}

func TestPromptGetPayload_ShareIncludesGrantFlow(t *testing.T) {
	def, _ := findPromptDefinition("share-credential")
	out := promptGetPayload(def, map[string]string{"path": "p", "to_agent": "hermes"})
	msgs, _ := out["messages"].([]map[string]any)
	text, _ := msgs[0]["content"].(map[string]any)["text"].(string)
	for _, want := range []string{"request_share", "approve_share", "revoke_share", "PENDING"} {
		if !strings.Contains(text, want) {
			t.Errorf("share prompt missing %q in:\n%s", want, text)
		}
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"GitHub":        "github",
		"AWS prod-east": "aws-prod-east",
		"  spaced  ":    "spaced",
		"":              "",
		"Foo / Bar":     "foo-bar",
		"---hi---":      "hi",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, want %q", in, got, want)
		}
	}
}
