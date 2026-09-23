package pairing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const deviceSessionOracleCommit = "27da9111e64ab2aa6cacb0f35e921077f3be30ee"

var deviceSessionOracleFiles = []string{
	"internal/pairing/devicesession.go",
	"internal/mcp/auth/token.go",
}

type deviceSessionOracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	GoVersion       string   `json:"go_version"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type deviceSessionCase struct {
	Name      string `json:"name"`
	Token     string `json:"token"`
	Input     string `json:"input"`
	Valid     bool   `json:"valid"`
	DeviceID  string `json:"device_id"`
	After     string `json:"after"`
	RawAbsent bool   `json:"raw_absent"`
	Cleanup   bool   `json:"cleanup"`
	LoadError bool   `json:"load_error,omitempty"`
}

type deviceSessionFixture struct {
	SchemaVersion int                 `json:"schema_version"`
	Oracle        deviceSessionOracle `json:"oracle"`
	Cases         []deviceSessionCase `json:"cases"`
}

func TestDeviceSessionFixture(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	content := buildDeviceSessionFixture(t, root)
	path := filepath.Join(root, "testdata/port/device_sessions/contract.json")
	if os.Getenv("UPDATE_DEVICE_SESSION_FIXTURE") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("device session fixture is stale; run UPDATE_DEVICE_SESSION_FIXTURE=1 go test ./internal/pairing -run '^TestDeviceSessionFixture$' -count=1")
	}
}

func buildDeviceSessionFixture(t *testing.T, root string) []byte {
	t.Helper()
	if runtime.Version() != "go1.26.6" {
		t.Fatalf("fixture requires pinned Go 1.26.6, got %s", runtime.Version())
	}
	parts := make([][]byte, 0, len(deviceSessionOracleFiles))
	for _, name := range deviceSessionOracleFiles {
		cmd := exec.Command("git", "show", deviceSessionOracleCommit+":"+name)
		cmd.Dir = root
		pinned, err := cmd.Output()
		if err != nil {
			t.Fatalf("read pinned source %s: %v", name, err)
		}
		working, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pinned, working) {
			t.Fatalf("oracle source %s differs from pinned commit %s", name, deviceSessionOracleCommit)
		}
		parts = append(parts, append(append([]byte(name+"\x00"), pinned...), 0))
	}
	sourceDigest := sha256.Sum256(bytes.Join(parts, nil))
	_, generatorPath, _, _ := runtime.Caller(0)
	generator, err := os.ReadFile(generatorPath)
	if err != nil {
		t.Fatal(err)
	}
	generatorDigest := sha256.Sum256(generator)
	fixture := deviceSessionFixture{
		SchemaVersion: 1,
		Oracle: deviceSessionOracle{
			Commit: "origin/main", CommitSHA: deviceSessionOracleCommit, GoVersion: runtime.Version(),
			SourceFiles: deviceSessionOracleFiles, SourceDigest: hex.EncodeToString(sourceDigest[:]),
			GeneratorDigest: hex.EncodeToString(generatorDigest[:]),
		},
	}
	cases := []struct {
		name, token, device string
		revoked             bool
		expires             time.Time
		legacy              bool
		cleanup             bool
	}{
		{"active", "0123456789ABCDEFGHIJKLMNOPQRSTUV", "device-active", false, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), false, false},
		{"revoked", "1123456789ABCDEFGHIJKLMNOPQRSTUV", "device-revoked", true, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), false, false},
		{"expired_and_cleaned", "2123456789ABCDEFGHIJKLMNOPQRSTUV", "device-expired", false, time.Date(2000, 1, 2, 3, 4, 5, 0, time.UTC), false, true},
		{"legacy_raw_key", "3123456789ABCDEFGHIJKLMNOPQRSTUV", "device-legacy", false, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), true, false},
	}
	for _, input := range cases {
		value := map[string]any{
			"prefix": tokenPrefix(input.token), "device_id": input.device, "public_key": "fixture-public-key",
			"created_at": time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), "expires_at": input.expires,
			"revoked": input.revoked,
		}
		key := hashToken(input.token)
		if input.legacy {
			value["token"] = input.token
			key = input.token
		}
		encoded, err := json.MarshalIndent(map[string]any{key: value}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := filepath.Join(dir, ".symvault/device-sessions.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := NewDeviceSessionStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		deviceID, valid := store.Validate(input.token)
		if input.cleanup {
			store.CleanupExpired()
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fixture.Cases = append(fixture.Cases, deviceSessionCase{
			Name: input.name, Token: input.token, Input: string(encoded), Valid: valid, DeviceID: deviceID,
			After: string(after), RawAbsent: !strings.Contains(string(after), input.token), Cleanup: input.cleanup,
		})
	}
	for _, input := range []struct{ name, expires string }{
		{"lowercase_zone", "2030-01-02T03:04:05z"},
		{"leap_second", "2030-01-02T03:04:60Z"},
	} {
		value := map[string]any{
			"prefix": "test", "device_id": "device-invalid", "public_key": "fixture-public-key",
			"created_at": "2025-01-02T03:04:05Z", "expires_at": input.expires, "revoked": false,
		}
		encoded, err := json.MarshalIndent(map[string]any{hashToken(input.name): value}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		path := filepath.Join(dir, ".symvault/device-sessions.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDeviceSessionStore(dir); err == nil {
			t.Fatalf("Go accepted %s timestamp", input.name)
		}
		fixture.Cases = append(fixture.Cases, deviceSessionCase{Name: input.name, Input: string(encoded), LoadError: true})
	}
	content, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(content, '\n')
}
