package vault

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	vaultconfig "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/testutil"
)

func TestEntryJSONSerialization(t *testing.T) {
	created := time.Date(2026, 3, 30, 10, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 3, 30, 10, 5, 0, 0, time.UTC)
	entry := Entry{
		Data: map[string]any{
			"username": "alice",
			"nested":   map[string]any{"token": "abc"},
		},
		Metadata: EntryMetadata{Created: created, Updated: updated, Version: 7},
	}

	raw, err := entry.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}

	var got Entry
	if err := got.UnmarshalJSON(raw); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}

	if !reflect.DeepEqual(got, entry) {
		t.Fatalf("roundtrip mismatch:\n got: %#v\nwant: %#v", got, entry)
	}
}

func TestWriteAndReadEntryRoundTrip(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	entry := &Entry{
		Data: map[string]any{
			"username": "alice",
			"password": "s3cr3t",
		},
	}

	if err := WriteEntry(vaultDir, "github.com/user", entry, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	path := filepath.Join(vaultDir, "entries", "github.com", "user.age")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected entry file at %s: %v", path, err)
	}

	got, err := ReadEntry(vaultDir, "github.com/user", id)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}

	if !reflect.DeepEqual(got.Data, entry.Data) {
		t.Fatalf("data mismatch: got %#v want %#v", got.Data, entry.Data)
	}
	if got.Metadata.Version != 1 {
		t.Fatalf("version = %d, want 1", got.Metadata.Version)
	}
	if got.Metadata.Created.IsZero() || got.Metadata.Updated.IsZero() {
		t.Fatal("metadata timestamps must be set")
	}
	if got.Metadata.Updated.Before(got.Metadata.Created) {
		t.Fatal("updated must not be before created")
	}
}

func TestDeleteEntryRemovesFile(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	if err := WriteEntry(vaultDir, "github.com/user", &Entry{Data: map[string]any{"x": 1}}, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if err := DeleteEntry(vaultDir, "github.com/user", id); err != nil {
		t.Fatalf("delete entry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "entries", "github.com", "user.age")); !os.IsNotExist(err) {
		t.Fatalf("expected file deleted, got err=%v", err)
	}
}

func TestMergeEntryPreservesUnknownFieldsAndIncrementsVersion(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	original := &Entry{
		Data: map[string]any{
			"username": "alice",
			"password": "old",
			"notes":    "keep-me",
		},
	}
	if err := WriteEntry(vaultDir, "github.com/user", original, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	merged, err := MergeEntry(vaultDir, "github.com/user", map[string]any{"password": "new"}, id)
	if err != nil {
		t.Fatalf("merge entry: %v", err)
	}

	if merged.Metadata.Version != 2 {
		t.Fatalf("version = %d, want 2", merged.Metadata.Version)
	}
	if merged.Data["username"] != "alice" {
		t.Fatalf("username = %#v, want %q", merged.Data["username"], "alice")
	}
	if merged.Data["password"] != "new" {
		t.Fatalf("password = %#v, want %q", merged.Data["password"], "new")
	}
	if merged.Data["notes"] != "keep-me" {
		t.Fatalf("notes = %#v, want %q", merged.Data["notes"], "keep-me")
	}
	if merged.Metadata.Updated.Before(merged.Metadata.Created) {
		t.Fatal("updated must not be before created")
	}
}

func TestEntryFileNamingUsesPathParts(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	if err := WriteEntry(vaultDir, "github.com/user", &Entry{Data: map[string]any{"x": 1}}, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	want := filepath.Join(vaultDir, "entries", "github.com", "user.age")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected file at %s: %v", want, err)
	}
}

func TestEntryFileNamingUsesEntriesRootForTopLevelPath(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	if err := WriteEntry(vaultDir, "github", &Entry{Data: map[string]any{"x": 1}}, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	want := filepath.Join(vaultDir, "entries", "github.age")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected file at %s: %v", want, err)
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "github.age")); !os.IsNotExist(err) {
		t.Fatalf("expected no root-level entry file, got err=%v", err)
	}
}

func TestValidateEntryPathRejectsTraversal(t *testing.T) {
	vaultDir := t.TempDir()

	tests := []string{
		"../etc/passwd",
		"entries/../identity",
		"./github",
		"github/./user",
		"github/../identity",
		`github\..\identity`,
		`github\.\user`,
		"/absolute/path",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			err := validateEntryPath(vaultDir, path)
			if err == nil {
				t.Fatal("expected error for invalid path")
			}
		})
	}
}

func TestDeleteEntryRejectsTraversal(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	err := DeleteEntry(vaultDir, "../etc/passwd", nil)
	if err == nil {
		t.Fatal("expected error for path traversal")
	}

	// Also test with WriteEntry path traversal
	err = WriteEntry(vaultDir, "../../../tmp/evil", &Entry{Data: map[string]any{"x": 1}}, id)
	if err == nil {
		t.Fatal("expected error for path traversal in WriteEntry")
	}
}

func TestLegacyFallbackDoesNotTouchIdentity(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)
	identityPath := filepath.Join(vaultDir, "identity.age")
	if err := os.WriteFile(identityPath, []byte("identity"), 0o600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}

	_, err := ReadEntry(vaultDir, "identity", id)
	if !os.IsNotExist(err) {
		t.Fatalf("ReadEntry(identity) error = %v, want IsNotExist", err)
	}

	if err := DeleteEntry(vaultDir, "identity", id); !os.IsNotExist(err) {
		t.Fatalf("DeleteEntry(identity) error = %v, want IsNotExist", err)
	}
	if _, err := os.Stat(identityPath); err != nil {
		t.Fatalf("identity file should remain: %v", err)
	}
}

func TestReadEntryFileNotFound(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	_, err := ReadEntry(vaultDir, "nonexistent/entry", id)
	if err == nil {
		t.Fatal("expected error for nonexistent entry")
	}
}

func TestReadEntry_RejectsTraversal(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"parent directory traversal", "../identity"},
		{"deep traversal", "../../etc/passwd"},
		{"alternating traversal", "a/../../b"},
		{"dot segment start", "./.."},
		{"encoded traversal", "..%2Fidentity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vaultDir := t.TempDir()
			id := testutil.TempIdentity(t)

			_, err := ReadEntry(vaultDir, tt.path, id)
			if err == nil {
				t.Fatal("expected error for path traversal")
			}
		})
	}
}

func TestReadEntryFallsBackToLegacyRootPath(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	if err := WriteEntry(vaultDir, "legacy/nested", &Entry{Data: map[string]any{"username": "alice"}}, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	newPath := filepath.Join(vaultDir, "entries", "legacy", "nested.age")
	legacyPath := filepath.Join(vaultDir, "legacy", "nested.age")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatalf("create legacy dir: %v", err)
	}
	if err := os.Rename(newPath, legacyPath); err != nil {
		t.Fatalf("move entry to legacy path: %v", err)
	}

	//nolint:errcheck // type assertion in test code
	got, err := ReadEntry(vaultDir, "legacy/nested", id)
	if err != nil {
		t.Fatalf("read legacy entry: %v", err)
		//nolint:errcheck // type assertion in test code
	}
	if got.Data["username"] != "alice" {
		t.Fatalf("username = %#v, want alice", got.Data["username"])
	}
}

func TestCloneEntryWithNilData(t *testing.T) {
	entry := &Entry{
		Data:     nil,
		Metadata: EntryMetadata{Version: 5},
	}
	clone := cloneEntry(entry)
	if clone == nil {
		t.Fatal("clone should not be nil")
	}
	if clone.Data != nil {
		t.Error("clone.Data should be nil")
	}
}

func TestDeepCloneValueWithSlice(t *testing.T) {
	original := []any{"a", "b", map[string]any{"nested": "value"}}
	//nolint:errcheck // type assertion in test code
	clone := deepCloneValue(original).([]any)
	if len(clone) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(clone))
	}

	// Modify original to ensure deep clone
	//nolint:errcheck // type assertion in test code
	original[0] = "modified"
	if clone[0] == "modified" {
		t.Error("clone should be independent of original")
	}

	// Check nested map is also deep cloned
	//nolint:errcheck // type assertion in test code
	nested := clone[2].(map[string]any)
	nested["nested"] = "changed"
	//nolint:errcheck // type assertion in test code
	origNested := original[2].(map[string]any)
	//nolint:errcheck // type assertion in test code
	if origNested["nested"] == "changed" {
		t.Error("nested map should be deep cloned")
	}
}

func TestMergeEntryRecursiveMerge(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	original := &Entry{
		Data: map[string]any{
			"config": map[string]any{
				"host": "localhost",
				"port": 8080,
			},
		},
	}
	if err := WriteEntry(vaultDir, "app/config", original, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	merged, err := MergeEntry(vaultDir, "app/config", map[string]any{
		"config": map[string]any{
			"port": 9090,
			"tls":  true,
		},
	}, id)
	if err != nil {
		t.Fatalf("merge entry: %v", err)
	}

	//nolint:errcheck // type assertion in test code
	config := merged.Data["config"].(map[string]any)
	if config["host"] != "localhost" {
		t.Error("existing nested field should be preserved")
	}
	if config["port"] != float64(9090) {
		t.Error("nested field should be updated")
	}
	if config["tls"] != true {
		t.Error("new nested field should be added")
	}
}

func TestGetEntryMetadataReturnsMetadataWithoutFullDecryption(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	entry := &Entry{
		Data: map[string]any{
			"username": "alice",
			"password": "s3cr3t",
		},
	}

	if err := WriteEntry(vaultDir, "github.com/user", entry, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	meta, err := GetEntryMetadata(vaultDir, "github.com/user", id)
	if err != nil {
		t.Fatalf("get entry metadata: %v", err)
	}

	if meta.Version != 1 {
		t.Fatalf("version = %d, want 1", meta.Version)
	}
	if meta.Created.IsZero() || meta.Updated.IsZero() {
		t.Fatal("metadata timestamps must be set")
	}
	if meta.Updated.Before(meta.Created) {
		t.Fatal("updated must not be before created")
	}
}

func TestGetEntryMetadataReturnsErrorForNonexistentEntry(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	_, err := GetEntryMetadata(vaultDir, "nonexistent/entry", id)
	if err == nil {
		t.Fatal("expected error for nonexistent entry")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected IsNotExist error, got: %v", err)
	}
}

func TestGetEntryMetadataReturnsUpdatedMetadataAfterMerge(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	original := &Entry{
		Data: map[string]any{
			"username": "alice",
			"password": "old",
		},
	}
	if err := WriteEntry(vaultDir, "github.com/user", original, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	// Get initial metadata
	meta1, err := GetEntryMetadata(vaultDir, "github.com/user", id)
	if err != nil {
		t.Fatalf("get initial metadata: %v", err)
	}
	if meta1.Version != 1 {
		t.Fatalf("initial version = %d, want 1", meta1.Version)
	}

	// Merge to update entry
	if _, mergeErr := MergeEntry(vaultDir, "github.com/user", map[string]any{"password": "new"}, id); mergeErr != nil {
		t.Fatalf("merge entry: %v", mergeErr)
	}

	// Get updated metadata
	meta2, err := GetEntryMetadata(vaultDir, "github.com/user", id)
	if err != nil {
		t.Fatalf("get updated metadata: %v", err)
	}
	if meta2.Version != 2 {
		t.Fatalf("updated version = %d, want 2", meta2.Version)
	}
	if !meta2.Updated.After(meta1.Updated) {
		t.Fatal("updated timestamp should be later after merge")
	}
}

func TestExtractTOTP(t *testing.T) {
	tests := []struct {
		name        string
		data        map[string]any
		wantSecret  string
		wantAlgo    string
		wantDigits  int
		wantPeriod  int
		wantHasTOTP bool
	}{
		{
			name: "valid totp with all fields",
			data: map[string]any{
				"totp": map[string]any{
					"secret":    "JBSWY3DPEHPK3PXP",
					"algorithm": "SHA256",
					"digits":    float64(8),
					"period":    float64(60),
				},
			},
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantAlgo:    "SHA256",
			wantDigits:  8,
			wantPeriod:  60,
			wantHasTOTP: true,
		},
		{
			name: "valid totp with defaults",
			data: map[string]any{
				"totp": map[string]any{
					"secret": "JBSWY3DPEHPK3PXP",
				},
			},
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantAlgo:    "SHA1",
			wantDigits:  6,
			wantPeriod:  30,
			wantHasTOTP: true,
		},
		{
			name:        "missing totp key",
			data:        map[string]any{"username": "alice"},
			wantHasTOTP: false,
		},
		{
			name:        "nil data",
			data:        nil,
			wantHasTOTP: false,
		},
		{
			name: "totp not a map",
			data: map[string]any{
				"totp": "not-a-map",
			},
			wantHasTOTP: false,
		},
		{
			name: "totp missing secret",
			data: map[string]any{
				"totp": map[string]any{
					"algorithm": "SHA1",
				},
			},
			wantHasTOTP: false,
		},
		{
			name: "totp empty secret",
			data: map[string]any{
				"totp": map[string]any{
					"secret": "",
				},
			},
			wantHasTOTP: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSecret, gotAlgo, gotDigits, gotPeriod, gotHasTOTP := ExtractTOTP(tt.data)
			if gotHasTOTP != tt.wantHasTOTP {
				t.Errorf("hasTOTP = %v, want %v", gotHasTOTP, tt.wantHasTOTP)
			}
			if gotSecret != tt.wantSecret {
				t.Errorf("secret = %q, want %q", gotSecret, tt.wantSecret)
			}
			if gotAlgo != tt.wantAlgo {
				t.Errorf("algorithm = %q, want %q", gotAlgo, tt.wantAlgo)
			}
			if gotDigits != tt.wantDigits {
				t.Errorf("digits = %d, want %d", gotDigits, tt.wantDigits)
			}
			if gotPeriod != tt.wantPeriod {
				t.Errorf("period = %d, want %d", gotPeriod, tt.wantPeriod)
			}
		})
	}
}

func TestEntryGetField(t *testing.T) {
	tests := []struct {
		name    string
		entry   *Entry
		key     string
		wantVal any
		wantOk  bool
	}{
		{
			name:    "existing field",
			entry:   &Entry{Data: map[string]any{"username": "alice"}},
			key:     "username",
			wantVal: "alice",
			wantOk:  true,
		},
		{
			name:    "missing field",
			entry:   &Entry{Data: map[string]any{"username": "alice"}},
			key:     "password",
			wantVal: nil,
			wantOk:  false,
		},
		{
			name:    "nil data",
			entry:   &Entry{Data: nil},
			key:     "username",
			wantVal: nil,
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotOk := tt.entry.GetField(tt.key)
			if gotOk != tt.wantOk {
				t.Errorf("ok = %v, want %v", gotOk, tt.wantOk)
			}
			if gotVal != tt.wantVal {
				t.Errorf("value = %#v, want %#v", gotVal, tt.wantVal)
			}
		})
	}
}

func TestEntrySetField(t *testing.T) {
	t.Run("set on nil data initializes map", func(t *testing.T) {
		entry := &Entry{Data: nil}
		entry.SetField("username", "alice")
		if entry.Data == nil {
			t.Fatal("Data should be initialized")
		}
		if entry.Data["username"] != "alice" {
			t.Errorf("username = %v, want alice", entry.Data["username"])
		}
	})

	t.Run("overwrite existing field", func(t *testing.T) {
		entry := &Entry{Data: map[string]any{"username": "old"}}
		entry.SetField("username", "new")
		if entry.Data["username"] != "new" {
			t.Errorf("username = %v, want new", entry.Data["username"])
		}
	})

	t.Run("add new field", func(t *testing.T) {
		entry := &Entry{Data: map[string]any{"username": "alice"}}
		entry.SetField("password", "s3cr3t")
		if entry.Data["password"] != "s3cr3t" {
			t.Errorf("password = %v, want s3cr3t", entry.Data["password"])
		}
		if entry.Data["username"] != "alice" {
			t.Error("existing field should be preserved")
		}
	})
}

func TestEntryHasField(t *testing.T) {
	tests := []struct {
		name  string
		entry *Entry
		key   string
		want  bool
	}{
		{
			name:  "existing field",
			entry: &Entry{Data: map[string]any{"username": "alice"}},
			key:   "username",
			want:  true,
		},
		{
			name:  "missing field",
			entry: &Entry{Data: map[string]any{"username": "alice"}},
			key:   "password",
			want:  false,
		},
		{
			name:  "nil data",
			entry: &Entry{Data: nil},
			key:   "username",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.entry.HasField(tt.key)
			if got != tt.want {
				t.Errorf("HasField(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestGetEntryMetadataRejectsNilIdentity(t *testing.T) {
	vaultDir := t.TempDir()

	_, err := GetEntryMetadata(vaultDir, "test/entry", nil)
	if err == nil {
		t.Fatal("expected error for nil identity")
	}
}

func TestGetEntryMetadataRejectsPathTraversal(t *testing.T) {
	vaultDir := t.TempDir()
	_ = testutil.TempIdentity(t)

	err := validateEntryPath(vaultDir, "../etc/passwd")
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
}

func TestPseudonymizePathDeterminism(t *testing.T) {
	id := testutil.TempIdentity(t)
	key := derivePseudonymizationKey(id)

	h1 := pseudonymizePath("github.com/user", key)
	h2 := pseudonymizePath("github.com/user", key)
	h3 := pseudonymizePath("github.com/other", key)

	if h1 != h2 {
		t.Fatalf("same path should produce same hash: %q vs %q", h1, h2)
	}
	if h1 == h3 {
		t.Fatal("different paths should produce different hashes")
	}
	if len(h1) != 64 {
		t.Fatalf("hash length should be 64 (SHA256 hex), got %d", len(h1))
	}
}

func TestDerivePseudonymizationKeyDeterminism(t *testing.T) {
	id := testutil.TempIdentity(t)
	k1 := derivePseudonymizationKey(id)
	k2 := derivePseudonymizationKey(id)

	if string(k1) != string(k2) {
		t.Fatal("same identity should produce same key")
	}
	if len(k1) != 32 {
		t.Fatalf("key length should be 32 (SHA256), got %d", len(k1))
	}
}

func TestWriteAndReadEntryWithPseudonymization(t *testing.T) {
	vaultDir := t.TempDir()

	writePseudonymizeConfig(t, vaultDir)

	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	entry := &Entry{
		Data: map[string]any{
			"username": "alice",
			"password": "s3cr3t",
		},
	}

	if err := WriteEntry(vaultDir, "github.com/user", entry, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	key := derivePseudonymizationKey(id)
	hash := pseudonymizePath("github.com/user", key)
	wantPath := filepath.Join(vaultDir, "entries", hash[:2], hash+".age")
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("expected pseudonymized file at %s: %v", wantPath, err)
	}

	plainPath := filepath.Join(vaultDir, "entries", "github.com", "user.age")
	if _, err := os.Stat(plainPath); !os.IsNotExist(err) {
		t.Fatalf("plaintext path file should not exist: %v", err)
	}

	got, err := ReadEntry(vaultDir, "github.com/user", id)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}

	if got.Path != "github.com/user" {
		t.Fatalf("entry.Path = %q, want %q", got.Path, "github.com/user")
	}
	if got.Data["username"] != "alice" {
		t.Fatalf("username = %v, want alice", got.Data["username"])
	}
	if got.Data["password"] != "s3cr3t" {
		t.Fatalf("password = %v, want s3cr3t", got.Data["password"])
	}
}

func TestDeleteEntryWithPseudonymization(t *testing.T) {
	vaultDir := t.TempDir()

	writePseudonymizeConfig(t, vaultDir)

	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	entry := &Entry{Data: map[string]any{"x": 1}}
	if err := WriteEntry(vaultDir, "github.com/user", entry, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	key := derivePseudonymizationKey(id)
	hash := pseudonymizePath("github.com/user", key)
	pseudPath := filepath.Join(vaultDir, "entries", hash[:2], hash+".age")
	if _, err := os.Stat(pseudPath); err != nil {
		t.Fatalf("expected file at %s: %v", pseudPath, err)
	}

	if err := DeleteEntry(vaultDir, "github.com/user", id); err != nil {
		t.Fatalf("delete entry: %v", err)
	}

	if _, err := os.Stat(pseudPath); !os.IsNotExist(err) {
		t.Fatalf("expected file deleted, got err=%v", err)
	}
}

func TestListWithPseudonymizedEntries(t *testing.T) {
	vaultDir := t.TempDir()

	writePseudonymizeConfig(t, vaultDir)

	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "github.com/work", map[string]interface{}{"username": "bob"})
	mustWriteEntry(t, vaultDir, id, "personal/email", map[string]interface{}{"username": "carol"})

	got, err := List(vaultDir, "")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	want := []string{"github.com/user", "github.com/work", "personal/email"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List() = %#v, want %#v", got, want)
	}
}

func TestListWithPseudonymizedEntriesAndPrefix(t *testing.T) {
	vaultDir := t.TempDir()

	writePseudonymizeConfig(t, vaultDir)

	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	mustWriteEntry(t, vaultDir, id, "github.com/user", map[string]interface{}{"username": "alice"})
	mustWriteEntry(t, vaultDir, id, "github.com/work", map[string]interface{}{"username": "bob"})
	mustWriteEntry(t, vaultDir, id, "personal/email", map[string]interface{}{"username": "carol"})

	got, err := List(vaultDir, "github.com")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	want := []string{"github.com/user", "github.com/work"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List() = %#v, want %#v", got, want)
	}
}

func TestEntryStoragePathWithoutPseudonymization(t *testing.T) {
	vaultDir := t.TempDir()
	id := testutil.TempIdentity(t)

	got := entryStoragePath(vaultDir, "github.com/user", id, nil)
	want := filepath.Join(vaultDir, "entries", "github.com", "user.age")
	if got != want {
		t.Fatalf("entryStoragePath = %q, want %q", got, want)
	}
}

func TestEntryStoragePathWithNilIdentity(t *testing.T) {
	vaultDir := t.TempDir()

	got := entryStoragePath(vaultDir, "github.com/user", nil, nil)
	want := filepath.Join(vaultDir, "entries", "github.com", "user.age")
	if got != want {
		t.Fatalf("entryStoragePath with nil identity = %q, want %q", got, want)
	}
}

func TestGetEntryMetadataWithPseudonymization(t *testing.T) {
	vaultDir := t.TempDir()

	writePseudonymizeConfig(t, vaultDir)

	id := testutil.TempIdentity(t)
	rememberSearchIdentity(id)

	entry := &Entry{
		Data: map[string]any{"username": "alice", "password": "s3cr3t"},
	}
	if err := WriteEntry(vaultDir, "github.com/user", entry, id); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	meta, err := GetEntryMetadata(vaultDir, "github.com/user", id)
	if err != nil {
		t.Fatalf("get entry metadata: %v", err)
	}

	if meta.Version != 1 {
		t.Fatalf("version = %d, want 1", meta.Version)
	}
}

func TestIsPseudonymizeEnabledDefault(t *testing.T) {
	vaultDir := t.TempDir()
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatalf("create vault dir: %v", err)
	}

	cfg := vaultconfig.Default()
	cfg.VaultDir = vaultDir
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config: %v", err)
	}

	loaded, err := vaultconfig.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if isPseudonymizeEnabled(loaded) {
		t.Fatal("pseudonymization should be disabled by default")
	}

	if isPseudonymizeEnabled(cfg) {
		t.Fatal("pseudonymization should be disabled by default")
	}
}

func writePseudonymizeConfig(t *testing.T, vaultDir string) {
	t.Helper()
	cfg := vaultconfig.Default()
	cfg.VaultDir = vaultDir
	cfg.Vault = &vaultconfig.VaultConfig{PseudonymizePaths: true}
	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		t.Fatalf("save config: %v", err)
	}
}

func TestFieldUntrusted_ReturnsUntrusted(t *testing.T) {
	e := &Entry{
		Path: "test/entry",
		Data: map[string]any{
			"password": "my-secret",
			"username": "alice",
		},
	}

	u, ok := e.FieldUntrusted("password")
	if !ok {
		t.Fatal("FieldUntrusted should return true for existing field")
	}
	prov := u.Provenance()
	if prov.Source != "vault.field" {
		t.Fatalf("Source = %q, want %q", prov.Source, "vault.field")
	}
	if prov.EntryPath != "test/entry" {
		t.Fatalf("EntryPath = %q, want %q", prov.EntryPath, "test/entry")
	}
	if prov.FieldName != "password" {
		t.Fatalf("FieldName = %q, want %q", prov.FieldName, "password")
	}
	raw := u.UnsafeRawForStorage()
	if raw != "my-secret" {
		t.Fatalf("raw value = %q, want %q", raw, "my-secret")
	}
}

func TestFieldUntrusted_NotFound(t *testing.T) {
	e := &Entry{
		Path: "test",
		Data: map[string]any{"existing": "value"},
	}
	_, ok := e.FieldUntrusted("nonexistent")
	if ok {
		t.Fatal("FieldUntrusted should return false for missing field")
	}
}

func TestFieldUntrusted_NilData(t *testing.T) {
	e := &Entry{Path: "test"}
	_, ok := e.FieldUntrusted("anything")
	if ok {
		t.Fatal("FieldUntrusted should return false for nil Data")
	}
}

func TestFieldUntrusted_NonStringValue(t *testing.T) {
	e := &Entry{
		Path: "test",
		Data: map[string]any{
			"count": 42,
			"ratio": 3.14,
			"tags":  []string{"a", "b"},
		},
	}
	u, ok := e.FieldUntrusted("count")
	if !ok {
		t.Fatal("should find 'count'")
	}
	if u.UnsafeRawForStorage() != "42" {
		t.Fatalf("expected '42', got %q", u.UnsafeRawForStorage())
	}
}

func TestTagsUntrusted_ReturnsUntrusted(t *testing.T) {
	e := &Entry{
		Path: "test/entry",
		Metadata: EntryMetadata{
			Tags: []string{"database", "production"},
		},
	}
	tags := e.TagsUntrusted()
	if len(tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(tags))
	}
	for i, tag := range tags {
		prov := tag.Provenance()
		if prov.Source != "vault.tag" {
			t.Fatalf("tag[%d] Source = %q, want %q", i, prov.Source, "vault.tag")
		}
		if prov.EntryPath != "test/entry" {
			t.Fatalf("tag[%d] EntryPath = %q, want %q", i, prov.EntryPath, "test/entry")
		}
		if tag.UnsafeRawForStorage() != e.Metadata.Tags[i] {
			t.Fatalf("tag[%d] value mismatch", i)
		}
	}
}

func TestTagsUntrusted_Empty(t *testing.T) {
	e := &Entry{Path: "test"}
	tags := e.TagsUntrusted()
	if tags == nil {
		t.Fatal("TagsUntrusted should return empty slice, not nil")
	}
	if len(tags) != 0 {
		t.Fatalf("expected 0 tags, got %d", len(tags))
	}
}

func TestUsageHintUntrusted_ReturnsUntrusted(t *testing.T) {
	e := &Entry{
		Path: "test/entry",
		SecretMetadata: SecretMetadata{
			UsageHint: "use this for AWS CLI authentication",
		},
	}
	u := e.UsageHintUntrusted()
	prov := u.Provenance()
	if prov.Source != "vault.usage_hint" {
		t.Fatalf("Source = %q, want %q", prov.Source, "vault.usage_hint")
	}
	if prov.EntryPath != "test/entry" {
		t.Fatalf("EntryPath = %q, want %q", prov.EntryPath, "test/entry")
	}
	if u.UnsafeRawForStorage() != "use this for AWS CLI authentication" {
		t.Fatalf("raw = %q", u.UnsafeRawForStorage())
	}
}

func TestUsageHintUntrusted_Empty(t *testing.T) {
	e := &Entry{Path: "test"}
	u := e.UsageHintUntrusted()
	if u.UnsafeRawForStorage() != "" {
		t.Fatal("empty UsageHint should produce empty Untrusted")
	}
}

func TestHandles_ReturnsHandles(t *testing.T) {
	e := &Entry{
		Path: "work/aws",
		Data: map[string]any{
			"password": "secret",
			"username": "alice",
		},
	}
	handles := e.Handles(e.Path)
	if len(handles) != 2 {
		t.Fatalf("expected 2 handles, got %d", len(handles))
	}
	found := map[string]bool{}
	for _, h := range handles {
		if h.Path != "work/aws" {
			t.Fatalf("Path = %q, want %q", h.Path, "work/aws")
		}
		found[h.Field] = true
	}
	if !found["password"] {
		t.Fatal("missing handle for 'password'")
	}
	if !found["username"] {
		t.Fatal("missing handle for 'username'")
	}
}

func TestHandles_EmptyData(t *testing.T) {
	e := &Entry{Path: "test"}
	handles := e.Handles(e.Path)
	if handles != nil {
		t.Fatal("Handles should return nil for empty Data")
	}
}

func TestHandles_ExplicitPath(t *testing.T) {
	e := &Entry{
		Path: "actual/path",
		Data: map[string]any{"key": "val"},
	}
	handles := e.Handles("custom/path")
	if len(handles) != 1 {
		t.Fatalf("expected 1 handle, got %d", len(handles))
	}
	if handles[0].Path != "custom/path" {
		t.Fatalf("Path = %q, want %q", handles[0].Path, "custom/path")
	}
}
