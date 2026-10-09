package server

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"testing"
	"time"
)

const localMCPOracleGoVersion = "go1.26.6"
const localMCPOracleCorekitVersion = "v0.17.1-0.20260904101640-f3d3eb79b9b1"

func localMCPOracleSourceFiles(files []string) []string {
	return slices.DeleteFunc(slices.Clone(files), func(name string) bool {
		return name == "go.mod" || name == "go.sum"
	})
}

// Only the local clipboard/input corpora separate a production-code pin from
// build manifests. Their full source hash still includes go.mod AND go.sum;
// unrelated generators and their stricter input closures remain unchanged.
func localMCPOracleSourcePin(t *testing.T, root, commit string, files []string) string {
	t.Helper()
	if runtime.Version() != localMCPOracleGoVersion {
		t.Fatalf("local MCP oracle requires %s, got %s", localMCPOracleGoVersion, runtime.Version())
	}
	if os.Getenv("GOWORK") != "off" {
		t.Fatal("local MCP oracle requires GOWORK=off")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-json", "github.com/danieljustus/symaira-corekit")
	cmd.Dir = root
	data, err := cmd.Output()
	if err != nil {
		t.Fatalf("read selected CoreKit module: %v", err)
	}
	var module struct {
		Version string
		Replace *json.RawMessage
	}
	if err := json.Unmarshal(data, &module); err != nil {
		t.Fatalf("decode selected CoreKit module: %v", err)
	}
	if module.Version != localMCPOracleCorekitVersion || module.Replace != nil {
		t.Fatal("local MCP oracle requires the exact CoreKit module without replacement")
	}
	pinned := localMCPOracleSourceFiles(files)
	digest := executeAPIRequestGitDigest(t, root, commit, pinned)
	if current := executeAPIRequestWorkingDigest(t, root, pinned); current != digest {
		t.Fatalf("Go production sources differ from pinned oracle %s: got %s, want %s", commit, current, digest)
	}
	t.Logf("local MCP oracle: %s/%s; full build manifests remain source-hashed", runtime.Version(), runtime.GOOS)
	return digest
}

func TestLocalMCPOracleSourcePinScope(t *testing.T) {
	files := []string{"go.mod", "internal/vault/entry.go", "go.sum", "internal/mcp/server/server.go"}
	got := localMCPOracleSourceFiles(files)
	if !slices.Equal(got, []string{"internal/vault/entry.go", "internal/mcp/server/server.go"}) {
		t.Fatalf("production pin lost behavior inputs: %v", got)
	}
	if len(files) != 4 || files[0] != "go.mod" || files[2] != "go.sum" {
		t.Fatal("full capture inventory lost its module files")
	}
}
