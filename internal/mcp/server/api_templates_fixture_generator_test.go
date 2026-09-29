package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/mcp/apitemplates"
)

func TestGenerateAPITemplatesFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_API_TEMPLATES_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_API_TEMPLATES_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_API_TEMPLATES_FIXTURE=1 or SYMAIRA_CHECK_API_TEMPLATES_FIXTURE=1")
	}
	root := executeAPIRequestRepoRoot(t)
	files := []string{"internal/mcp/apitemplates/template.go", "internal/mcp/apitemplates/auth.go"}
	assets, err := filepath.Glob(filepath.Join(root, "internal/mcp/apitemplates/builtin/*.yaml"))
	if err != nil || len(assets) == 0 {
		t.Fatalf("locate built-in assets: %v", err)
	}
	type templateCase struct {
		Name       string                    `json:"name"`
		Template   string                    `json:"template"`
		Directory  bool                      `json:"directory"`
		Override   *string                   `json:"override,omitempty"`
		Definition *apitemplates.APITemplate `json:"definition,omitempty"`
		Error      string                    `json:"error,omitempty"`
	}
	var cases []templateCase
	for _, asset := range assets {
		relative, err := filepath.Rel(root, asset)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, filepath.ToSlash(relative))
		name := strings.TrimSuffix(filepath.Base(asset), ".yaml")
		cases = append(cases, templateCase{Name: "builtin_" + name, Template: name})
	}
	sourceDigest := executeAPIRequestGitDigest(t, root, executeAPIRequestOracleCommit, files)
	if got := executeAPIRequestWorkingDigest(t, root, files); got != sourceDigest {
		t.Fatalf("template sources differ from pinned Go oracle: working=%s pinned=%s", got, sourceDigest)
	}
	custom := "base_url: https://override.example.test\nauth_type: bearer\nentry_ref: fixture-custom\nallowed_endpoints: [/custom]\nallowed_methods: [GET]\n"
	malformed := "base_url: [\n"
	cases = append(cases,
		templateCase{Name: "missing_custom_file", Template: "github", Directory: true},
		templateCase{Name: "custom_overrides_builtin", Template: "github", Directory: true, Override: &custom},
		templateCase{Name: "malformed_override_no_fallback", Template: "github", Directory: true, Override: &malformed},
		templateCase{Name: "unknown", Template: "absent-fixture"},
		templateCase{Name: "empty", Template: ""},
		templateCase{Name: "traversal", Template: "../github"},
		templateCase{Name: "backslash", Template: `folder\github`},
	)
	for i := range cases {
		c := &cases[i]
		vault := t.TempDir()
		if c.Directory {
			if err := os.Mkdir(filepath.Join(vault, "templates"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if c.Override != nil {
			if err := os.WriteFile(filepath.Join(vault, "templates", c.Template+".yaml"), []byte(*c.Override), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		c.Definition, err = apitemplates.Load(c.Template, vault)
		if err != nil {
			c.Error = err.Error()
		}
	}
	generators := []string{"internal/mcp/server/api_templates_fixture_generator_test.go", "internal/mcp/server/mcp_execute_api_request_fixture_generator_test.go"}
	fixture := struct {
		SchemaVersion int                          `json:"schema_version"`
		Oracle        executeAPIRequestFixtureRefs `json:"oracle"`
		Cases         []templateCase               `json:"cases"`
	}{1, executeAPIRequestFixtureRefs{
		Commit: executeAPIRequestOracleCommit, CommitSHA: executeAPIRequestOracleCommit,
		SourceFiles: files, SourceDigest: sourceDigest, GeneratorFiles: generators,
		GeneratorHash: executeAPIRequestWorkingDigest(t, root, generators),
	}, cases}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(root, "testdata/port/mcp/api-templates.json")
	if check {
		actual, err := os.ReadFile(path)
		if err != nil || string(actual) != string(data) {
			t.Fatalf("API template fixture is stale or unreadable: %v", err)
		}
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
