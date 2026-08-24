package crud

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	cli "github.com/danieljustus/symaira-vault/internal/cli"
)

func TestGetCommand_ExactPath(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	cmd := newGetCmd()
	cmd.SetArgs([]string{"github"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestGetCommand_Field(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	cmd := newGetCmd()
	cmd.SetArgs([]string{"github.username"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestGetCommand_NotFound(t *testing.T) {
	setupTestVault(t)

	cmd := newGetCmd()
	cmd.SetArgs([]string{"missing"})
	cmd.SetOut(&strings.Builder{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute() = nil, want not-found error")
	}
	if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "not exist") {
		t.Errorf("error = %q, want not-found message", err)
	}
}

func TestGetCommand_JSONOutput(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	setJSONOutput(t)
	cmd := newGetCmd()
	GetPrint = true
	t.Cleanup(func() { GetPrint = false })
	cmd.SetArgs([]string{"github"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})
	if !strings.Contains(out, `"Path"`) {
		t.Errorf("JSON output = %q, want path field", out)
	}
}

func TestGetCommand_JSONFlag(t *testing.T) {
	setupTestVault(t)
	addTestEntry(t, "github", map[string]any{"username": "octocat", "password": "s3cret"})

	cmd := newGetCmd()
	GetPrint = true
	t.Cleanup(func() { GetPrint = false })
	cmd.SetArgs([]string{"github"})
	var out strings.Builder
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestNewGetCmd_Flags(t *testing.T) {
	cmd := newGetCmd()
	if cmd.Flags().Lookup("print") == nil {
		t.Error("--print flag missing")
	}
	if cmd.Flags().Lookup("length") == nil {
		t.Error("--length flag missing")
	}
	if cmd.Flags().Lookup("digest") == nil {
		t.Error("--digest flag missing")
	}
	if cmd.Flags().Lookup("metadata") == nil {
		t.Error("--metadata flag missing")
	}
	if cmd.GroupID != cli.GroupIDEssentials {
		t.Errorf("GroupID = %q, want %q", cmd.GroupID, cli.GroupIDEssentials)
	}
}

func resetGetCmdFlags(t *testing.T) {
	t.Helper()
	origPrint := GetPrint
	origLength := GetLength
	origDigest := GetDigest
	origMetadata := GetMetadata
	t.Cleanup(func() {
		GetPrint = origPrint
		GetLength = origLength
		GetDigest = origDigest
		GetMetadata = origMetadata
	})
}

func TestGetCommand_Length(t *testing.T) {
	setupTestVault(t)
	resetGetCmdFlags(t)
	secret := "supersecretvalue123"
	addTestEntry(t, "service/api", map[string]any{"token": secret})

	cmd := newGetCmd()
	cmd.SetArgs([]string{"service/api.token", "--length"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})

	want := "19\n"
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
	if strings.Contains(out, secret) {
		t.Errorf("plaintext secret leaked in output: %q", out)
	}
}

func TestGetCommand_Digest(t *testing.T) {
	setupTestVault(t)
	resetGetCmdFlags(t)
	secret := "supersecretvalue123"
	addTestEntry(t, "service/api", map[string]any{"token": secret})

	h := sha256.Sum256([]byte(secret))
	expectedDigest := fmt.Sprintf("sha256:%s\n", hex.EncodeToString(h[:])[:12])

	cmd := newGetCmd()
	cmd.SetArgs([]string{"service/api.token", "--digest"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})

	if out != expectedDigest {
		t.Errorf("output = %q, want %q", out, expectedDigest)
	}
	if strings.Contains(out, secret) {
		t.Errorf("plaintext secret leaked in output: %q", out)
	}
}

func TestGetCommand_Metadata(t *testing.T) {
	setupTestVault(t)
	resetGetCmdFlags(t)
	secret := "supersecretvalue123"
	addTestEntry(t, "service/api", map[string]any{"token": secret})

	h := sha256.Sum256([]byte(secret))
	expectedSHA := hex.EncodeToString(h[:])[:12]

	cmd := newGetCmd()
	cmd.SetArgs([]string{"service/api.token", "--metadata"})
	out := captureStdout(t, func() {
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	})

	var parsed struct {
		Length   int    `json:"length"`
		SHA25612 string `json:"sha256_12"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		t.Fatalf("unmarshal metadata json %q: %v", out, err)
	}
	if parsed.Length != 19 || parsed.SHA25612 != expectedSHA {
		t.Errorf("metadata = %+v, want length=19, sha256_12=%s", parsed, expectedSHA)
	}
	if strings.Contains(out, secret) {
		t.Errorf("plaintext secret leaked in output: %q", out)
	}
}

func TestGetCommand_MutualExclusion(t *testing.T) {
	setupTestVault(t)
	resetGetCmdFlags(t)
	addTestEntry(t, "service/api", map[string]any{"token": "secret"})

	cases := [][]string{
		{"service/api.token", "--length", "--print"},
		{"service/api.token", "--digest", "--print"},
		{"service/api.token", "--metadata", "--print"},
		{"service/api.token", "--length", "--digest"},
		{"service/api.token", "--length", "--metadata"},
		{"service/api.token", "--digest", "--metadata"},
	}

	for _, args := range cases {
		cmd := newGetCmd()
		cmd.SetArgs(args)
		cmd.SetOut(&strings.Builder{})
		err := cmd.Execute()
		if err == nil {
			t.Errorf("Execute(%v) = nil, want error for mutually exclusive flags", args)
		}
	}
}

func TestGetCommand_MetadataFlags_RequireField(t *testing.T) {
	setupTestVault(t)
	resetGetCmdFlags(t)
	addTestEntry(t, "service/api", map[string]any{"token": "secret"})

	for _, flag := range []string{"--length", "--digest", "--metadata"} {
		cmd := newGetCmd()
		cmd.SetArgs([]string{"service/api", flag})
		cmd.SetOut(&strings.Builder{})
		err := cmd.Execute()
		if err == nil {
			t.Errorf("Execute(service/api %s) = nil, want error requiring field", flag)
		}
	}
}
