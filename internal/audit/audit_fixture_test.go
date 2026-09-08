package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// This fixture is intentionally generated inside the production audit package:
// it calls canonicalJSON and computeHMAC directly, rather than copying the
// algorithm into a migration-only command. The key bytes and paths are test
// values only; they are never used by a production logger.
const auditFixturePath = "testdata/port/audit/audit.json"

var auditOracleSources = []string{
	"internal/audit/audit.go",
	"internal/audit/export.go",
	"internal/audit/keystore.go",
	"internal/audit/keystore_fallback.go",
	"internal/audit/keystore_os.go",
}

var auditGeneratorSources = []string{"internal/audit/audit_fixture_test.go"}

const auditOracleCommit = "a57f565a"

type auditFixture struct {
	SchemaVersion int                  `json:"schema_version"`
	Oracle        auditOracleMeta      `json:"oracle"`
	Keys          []auditFixtureKey    `json:"keys"`
	Entries       []json.RawMessage    `json:"entries"`
	Legacy        json.RawMessage      `json:"legacy"`
	Negatives     []auditNegativeCase  `json:"negative_cases"`
	Export        auditExportFixture   `json:"export"`
	Rotation      auditRotationFixture `json:"rotation"`
}

type auditOracleMeta struct {
	Commit          string   `json:"commit"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
	GeneratorDigest string   `json:"generator_digest"`
}

type auditFixtureKey struct {
	Name string `json:"name"`
	Hex  string `json:"key_hex"`
	Kid  string `json:"kid"`
}

type auditNegativeCase struct {
	Name          string            `json:"name"`
	Lines         []json.RawMessage `json:"lines"`
	Valid         bool              `json:"valid"`
	Total         int               `json:"total"`
	Verified      int               `json:"verified"`
	Legacy        int               `json:"legacy"`
	Tampered      int               `json:"tampered"`
	Unverifiable  int               `json:"unverifiable"`
	FirstBadIndex int               `json:"first_bad_index"`
}

type auditExportFixture struct {
	Action       string `json:"action"`
	FailedOnly   bool   `json:"failed_only"`
	RedactedPath string `json:"redacted_path"`
	Total        int    `json:"total"`
}

type auditRotationFixture struct {
	ArchivePrefix string `json:"archive_prefix"`
	ArchiveKid    string `json:"archive_kid"`
	Bootstrap     bool   `json:"bootstrap"`
}

func auditRepoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate audit fixture generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func auditDigestFiles(root string, revision string, names []string) (string, error) {
	ordered := append([]string(nil), names...)
	sort.Strings(ordered)
	h := sha256.New()
	for _, name := range ordered {
		var data []byte
		var err error
		if revision == "" {
			data, err = os.ReadFile(filepath.Join(root, name))
		} else {
			data, err = exec.Command("git", "-C", root, "show", revision+":"+name).Output() // #nosec G204 -- fixed generator inputs
		}
		if err != nil {
			return "", err
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func auditOracleForRoot(root string) (auditOracleMeta, error) {
	sourceDigest, err := auditDigestFiles(root, auditOracleCommit, auditOracleSources)
	if err != nil {
		return auditOracleMeta{}, err
	}
	generatorDigest, err := auditDigestFiles(root, "", auditGeneratorSources)
	if err != nil {
		return auditOracleMeta{}, err
	}
	return auditOracleMeta{
		Commit:          auditOracleCommit,
		SourceFiles:     append([]string(nil), auditOracleSources...),
		SourceDigest:    sourceDigest,
		GeneratorFiles:  append([]string(nil), auditGeneratorSources...),
		GeneratorDigest: generatorDigest,
	}, nil
}

func auditEntryLine(entry LogEntry) json.RawMessage {
	data, err := json.Marshal(entry)
	if err != nil {
		panic(err)
	}
	return data
}

func auditSignedEntry(key []byte, previous []byte, entry LogEntry) (json.RawMessage, []byte) {
	entry.Kid = KeyFingerprint(key)
	entry.HMAC = computeHMAC(key, previous, entry)
	hmacBytes, err := hex.DecodeString(entry.HMAC)
	if err != nil {
		panic(err)
	}
	return auditEntryLine(entry), hmacBytes
}

func buildAuditFixture(root string) (auditFixture, error) {
	oracle, err := auditOracleForRoot(root)
	if err != nil {
		return auditFixture{}, err
	}
	oldKey := []byte("audit-fixture-old-key-0000000000")
	newKey := []byte("audit-fixture-new-key-0000000000")
	if len(oldKey) != 32 || len(newKey) != 32 {
		return auditFixture{}, errors.New("fixture keys must be exactly 32 bytes")
	}
	keys := []auditFixtureKey{
		{Name: "old", Hex: hex.EncodeToString(oldKey), Kid: KeyFingerprint(oldKey)},
		{Name: "new", Hex: hex.EncodeToString(newKey), Kid: KeyFingerprint(newKey)},
	}

	legacy := auditEntryLine(LogEntry{Timestamp: "2026-01-01T00:00:00Z", Agent: "fixture-agent", Action: "legacy", Path: "before-chain", OK: true})
	entries := make([]json.RawMessage, 0, 4)
	var previous []byte
	for _, item := range []struct {
		key    []byte
		action string
		path   string
		ok     bool
		argv   string
	}{
		{oldKey, "get", "safe/password", true, ""},
		{oldKey, "set", "safe/password", false, ""},
		{newKey, "list", "safe/", true, "deadbeef"},
		{newKey, "delete", "safe/password", true, ""},
	} {
		line, next := auditSignedEntry(item.key, previous, LogEntry{
			Timestamp: "2026-01-01T00:00:0" + string(rune('1'+len(entries))) + "Z",
			Agent:     "fixture-agent",
			Action:    item.action,
			Path:      item.path,
			Reason:    map[bool]string{false: "write_denied", true: ""}[item.ok],
			OK:        item.ok,
			ArgvHash:  item.argv,
		})
		entries = append(entries, line)
		previous = next
	}

	makeCase := func(name string, lines []json.RawMessage) auditNegativeCase {
		result := VerifyLogBytesForFixture(lines, map[string][]byte{"old": oldKey, "new": newKey}, KeyFingerprint(newKey))
		return auditNegativeCase{Name: name, Lines: lines, Valid: result.Valid, Total: result.Total, Verified: result.Verified, Legacy: result.Legacy, Tampered: result.Tampered, Unverifiable: result.Unverifiable, FirstBadIndex: result.FirstBadIdx}
	}
	mutated := append([]json.RawMessage(nil), entries...)
	var mutation map[string]any
	_ = json.Unmarshal(mutated[1], &mutation)
	mutation["action"] = "tampered"
	mutated[1] = auditEntryLineFromMap(mutation)
	reordered := append([]json.RawMessage(nil), entries...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	truncatedHMAC := append([]json.RawMessage(nil), entries...)
	var truncated map[string]any
	_ = json.Unmarshal(truncatedHMAC[2], &truncated)
	truncated["hmac"] = truncated["hmac"].(string)[:63]
	truncatedHMAC[2] = auditEntryLineFromMap(truncated)
	inserted := append([]json.RawMessage{entries[0], auditEntryLine(LogEntry{Timestamp: "2026-01-01T00:00:01Z", Agent: "fixture-agent", Action: "inserted", OK: true})}, entries[1:]...)
	wrongKey := VerifyLogBytesWithKids(entries, map[string][]byte{KeyFingerprint(oldKey): []byte("audit-fixture-bad-key-0000000000"), KeyFingerprint(newKey): newKey}, KeyFingerprint(newKey))
	negatives := []auditNegativeCase{makeCase("mutation", mutated), makeCase("reorder", reordered), makeCase("truncated_hmac", truncatedHMAC), makeCase("insertion", inserted), makeCase("reset_after_chain", append(append(append([]json.RawMessage(nil), entries[:2]...), legacy), entries[2:]...)), {Name: "key_mismatch", Lines: entries, Valid: wrongKey.Valid, Total: wrongKey.Total, Verified: wrongKey.Verified, Legacy: wrongKey.Legacy, Tampered: wrongKey.Tampered, Unverifiable: wrongKey.Unverifiable, FirstBadIndex: wrongKey.FirstBadIdx}}
	endTruncated := append([]json.RawMessage(nil), entries[:len(entries)-1]...)
	negatives = append(negatives, makeCase("end_truncation_is_undetectable", endTruncated))
	return auditFixture{SchemaVersion: 1, Oracle: oracle, Keys: keys, Entries: entries, Legacy: legacy, Negatives: negatives, Export: auditExportFixture{Action: "set", FailedOnly: true, RedactedPath: RedactPath("safe/password"), Total: 1}, Rotation: auditRotationFixture{ArchivePrefix: "audit-hmac-key.rotated.", ArchiveKid: KeyFingerprint(oldKey), Bootstrap: true}}, nil
}

func auditEntryLineFromMap(value map[string]any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

// fixtureVerification is intentionally tiny and only bridges generated JSONL
// into the production verifier without exposing its implementation.
type fixtureVerification struct {
	Valid                                                        bool
	Total, Verified, Legacy, Tampered, Unverifiable, FirstBadIdx int
}

func VerifyLogBytesWithKids(lines []json.RawMessage, keys map[string][]byte, currentKid string) fixtureVerification {
	var data []byte
	for _, line := range lines {
		data = append(data, line...)
		data = append(data, '\n')
	}
	result, err := verifyLogData(data, keys, currentKid)
	if err != nil {
		panic(err)
	}
	return fixtureVerification{result.Valid, result.Total, result.Verified, result.Legacy, result.Tampered, result.Unverifiable, result.FirstBadIdx}
}

func VerifyLogBytesForFixture(lines []json.RawMessage, keys map[string][]byte, currentKid string) fixtureVerification {
	var data []byte
	for _, line := range lines {
		data = append(data, line...)
		data = append(data, '\n')
	}
	keySet := make(map[string][]byte, len(keys))
	for _, key := range keys {
		keySet[KeyFingerprint(key)] = key
	}
	result, err := verifyLogData(data, keySet, currentKid)
	if err != nil {
		panic(err)
	}
	return fixtureVerification{result.Valid, result.Total, result.Verified, result.Legacy, result.Tampered, result.Unverifiable, result.FirstBadIdx}
}

func verifyLogData(data []byte, keys map[string][]byte, currentKid string) (*VerifyResult, error) {
	// Keep the fixture's oracle call on the exact production entry point.
	path := filepath.Join(os.TempDir(), "symvault-audit-fixture-oracle.log")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(path)
	return VerifyLogAgainstKeys(path, keys, currentKid)
}

func TestAuditFixture(t *testing.T) {
	root := auditRepoRoot()
	fixturePath := filepath.Join(root, auditFixturePath)
	fixture, err := buildAuditFixture(root)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_AUDIT_FIXTURE") == "1" {
		data, marshalErr := json.MarshalIndent(fixture, "", "  ")
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		data = append(data, '\n')
		if writeErr := os.MkdirAll(filepath.Dir(fixturePath), 0o750); writeErr != nil {
			t.Fatal(writeErr)
		}
		if writeErr := os.WriteFile(fixturePath, data, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
		t.Logf("wrote %s", auditFixturePath)
		return
	}
	got, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if string(got) != string(want) {
		t.Fatalf("audit fixture drift; run UPDATE_AUDIT_FIXTURE=1 go test ./internal/audit -run TestAuditFixture")
	}

	var parsed auditFixture
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Oracle.Commit != auditOracleCommit || parsed.Oracle.SourceDigest != fixture.Oracle.SourceDigest || parsed.Oracle.GeneratorDigest != fixture.Oracle.GeneratorDigest {
		t.Fatal("audit fixture provenance drift")
	}
	if len(parsed.Entries) != 4 || len(parsed.Negatives) != 7 {
		t.Fatal("audit fixture cardinality drift")
	}
	for _, negative := range parsed.Negatives {
		if negative.Name == "end_truncation_is_undetectable" {
			if !negative.Valid {
				t.Fatal("Go truncation contract changed")
			}
			continue
		}
		if negative.Valid || negative.Tampered == 0 {
			t.Fatalf("negative case %q is not rejected", negative.Name)
		}
	}
	if !strings.HasPrefix(parsed.Rotation.ArchivePrefix, "audit-hmac-key.rotated.") {
		t.Fatal("rotation archive contract drift")
	}
}
