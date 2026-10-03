package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateMCPExecuteAPIPolicyFixture(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_EXECUTE_API_POLICY_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_EXECUTE_API_POLICY_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set the API policy fixture generate/check flag")
	}
	root := executeAPIRequestRepoRoot(t)
	files := append([]string(nil), executeAPIRequestSourceFiles...)
	sourceDigest := executeAPIRequestGitDigest(t, root, executeAPIRequestOracleCommit, files)
	if working := executeAPIRequestWorkingDigest(t, root, files); working != sourceDigest {
		t.Fatalf("API policy sources differ from pinned oracle: working=%s pinned=%s", working, sourceDigest)
	}
	generatorFiles := []string{
		"internal/mcp/server/mcp_execute_api_policy_fixture_generator_test.go",
		"internal/mcp/server/mcp_execute_api_request_fixture_generator_test.go",
		"internal/mcp/server/tools_execute_api_policy_test.go",
		"internal/mcp/server/tools_execute_api_request_test.go",
		"internal/mcp/server/tools_test_helpers.go",
	}
	fixture := struct {
		SchemaVersion int                          `json:"schema_version"`
		GoVersion     string                       `json:"go_version"`
		Oracle        executeAPIRequestFixtureRefs `json:"oracle"`
		Cases         []apiEntryPolicyObservation  `json:"cases"`
	}{SchemaVersion: 1, GoVersion: runtime.Version(), Oracle: executeAPIRequestFixtureRefs{
		Commit: executeAPIRequestOracleCommit, CommitSHA: executeAPIRequestOracleCommit,
		SourceFiles: files, SourceDigest: sourceDigest, GeneratorFiles: generatorFiles,
		GeneratorHash: executeAPIRequestWorkingDigest(t, root, generatorFiles),
	}}
	for _, input := range apiEntryPolicyCases() {
		fixture.Cases = append(fixture.Cases, observeAPIEntryPolicy(t, input))
	}
	if t.Failed() {
		t.Fatal("refusing to freeze failed handler observations")
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	output := filepath.Join(root, "testdata/port/mcp/execute-api-policy.json")
	if check {
		actual, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(data) {
			t.Fatal("API entry policy fixture is stale")
		}
		return
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
