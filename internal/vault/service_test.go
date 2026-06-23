package vault

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// --- helpers ---

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	cfg.Git = &config.GitConfig{AutoPush: false}

	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	v, err := Open(vaultDir, identity)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return v
}

// writeTestEntry writes an entry to the vault using the package-level WriteEntry.
func writeTestEntry(t *testing.T, v *Vault, path string, data map[string]any) {
	t.Helper()
	if err := WriteEntry(v.Dir, path, &Entry{Data: data}, v.Identity); err != nil {
		t.Fatalf("WriteEntry(%q) error = %v", path, err)
	}
}

// --- NewVaultService ---

func TestNewVaultService_NilOps(t *testing.T) {
	v := newTestVault(t)
	svc := NewVaultService(v, nil)
	if svc == nil {
		t.Fatal("NewVaultService returned nil")
	}
	if svc.Vault != v {
		t.Error("Vault not set correctly")
	}
	// Verify the ops is DefaultOperationService
	if _, ok := svc.Ops.(DefaultOperationService); !ok {
		t.Errorf("expected DefaultOperationService, got %T", svc.Ops)
	}
}

func TestNewVaultService_CustomOps(t *testing.T) {
	v := newTestVault(t)
	custom := &fakeOperationService{}
	svc := NewVaultService(v, custom)
	if svc.Ops != custom {
		t.Error("custom ops not preserved")
	}
}

// fakeOperationService implements OperationService for NewVaultService tests.
type fakeOperationService struct{}

func (f *fakeOperationService) GetField(_ *Vault, _, _ string) (any, error) { return nil, nil }
func (f *fakeOperationService) UpsertEntry(_ *Vault, _ string, _ map[string]any, _ string, _ *WriteRecord) error {
	return nil
}
func (f *fakeOperationService) GetEntry(_ *Vault, _ string) (*Entry, error) { return nil, nil }
func (f *fakeOperationService) WriteEntry(_ *Vault, _ string, _ *Entry) error {
	return nil
}
func (f *fakeOperationService) DeleteEntry(_ *Vault, _ string) error { return nil }
func (f *fakeOperationService) ListEntries(_ *Vault, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeOperationService) ListEntryInfos(_ *Vault, _ string, _ int) ([]ListEntryInfo, error) {
	return nil, nil
}
func (f *fakeOperationService) FindEntries(_ *Vault, _ string, _ FindOptions) ([]Match, error) {
	return nil, nil
}
func (f *fakeOperationService) VaultDir(_ *Vault) string                   { return "" }
func (f *fakeOperationService) VaultIdentity(_ *Vault) *age.X25519Identity { return nil }

// --- ValidateFieldLengths ---

func TestValidateFieldLengths_NormalData(t *testing.T) {
	data := map[string]any{
		"username": "alice",
		"password": "secret123",
	}
	if err := ValidateFieldLengths(data); err != nil {
		t.Errorf("ValidateFieldLengths() error = %v, want nil", err)
	}
}

func TestValidateFieldLengths_EmptyData(t *testing.T) {
	if err := ValidateFieldLengths(map[string]any{}); err != nil {
		t.Errorf("ValidateFieldLengths() error = %v, want nil", err)
	}
}

func TestValidateFieldLengths_ExceedsMaxLength(t *testing.T) {
	longValue := strings.Repeat("a", MaxFieldLength+1)
	data := map[string]any{"field": longValue}
	err := ValidateFieldLengths(data)
	if err == nil {
		t.Fatal("ValidateFieldLengths() error = nil, want error for oversized field")
	}
	if !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Errorf("error = %v, want 'exceeds maximum length'", err)
	}
}

func TestValidateFieldLengths_ExactMaxLength(t *testing.T) {
	exactValue := strings.Repeat("a", MaxFieldLength)
	data := map[string]any{"field": exactValue}
	if err := ValidateFieldLengths(data); err != nil {
		t.Errorf("ValidateFieldLengths() error = %v, want nil for exact length", err)
	}
}

func TestValidateFieldLengths_NestedExceedsMaxLength(t *testing.T) {
	longValue := strings.Repeat("b", MaxFieldLength+1)
	data := map[string]any{
		"outer": map[string]any{
			"inner": longValue,
		},
	}
	err := ValidateFieldLengths(data)
	if err == nil {
		t.Fatal("ValidateFieldLengths() error = nil, want error for nested oversized field")
	}
}

func TestValidateFieldLengths_NonStringValuesIgnored(t *testing.T) {
	data := map[string]any{
		"count": 42,
		"flag":  true,
		"items": []any{"a", "b"},
	}
	if err := ValidateFieldLengths(data); err != nil {
		t.Errorf("ValidateFieldLengths() error = %v, want nil for non-string values", err)
	}
}

func TestValidateFieldLengths_NestedNormal(t *testing.T) {
	data := map[string]any{
		"outer": map[string]any{
			"inner": "short",
		},
	}
	if err := ValidateFieldLengths(data); err != nil {
		t.Errorf("ValidateFieldLengths() error = %v, want nil", err)
	}
}

// --- DefaultOperationService.GetField ---

func TestGetField_ExistingEntry(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "github/user", map[string]any{"username": "alice", "password": "secret"})

	val, err := ops.GetField(v, "github/user", "username")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "alice" {
		t.Errorf("GetField() = %v, want alice", val)
	}
}

func TestGetField_EmptyFieldReturnsAllData(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "github/user", map[string]any{"username": "alice"})

	val, err := ops.GetField(v, "github/user", "")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	data, ok := val.(map[string]any)
	if !ok {
		t.Fatalf("GetField() returned %T, want map[string]any", val)
	}
	if data["username"] != "alice" {
		t.Errorf("data[username] = %v, want alice", data["username"])
	}
}

func TestGetField_EntryNotFound(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	_, err := ops.GetField(v, "nonexistent/path", "field")
	if err == nil {
		t.Fatal("GetField() error = nil, want error for nonexistent entry")
	}
}

func TestGetField_FieldNotFound(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "github/user", map[string]any{"username": "alice"})

	_, err := ops.GetField(v, "github/user", "nonexistent_field")
	if err == nil {
		t.Fatal("GetField() error = nil, want error for nonexistent field")
	}
}

func TestGetField_ReadError(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	// Try to read from a path with traversal (will fail validation)
	_, err := ops.GetField(v, "../escape/path", "field")
	if err == nil {
		t.Fatal("GetField() error = nil, want error for invalid path")
	}
}

// --- DefaultOperationService.UpsertEntry ---

func TestUpsertEntry_CreateNew(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	data := map[string]any{"username": "alice", "password": "secret123"}

	err := ops.UpsertEntry(v, "test/new-entry", data, "create", nil)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}

	// Verify the entry was created
	val, err := ops.GetField(v, "test/new-entry", "username")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "alice" {
		t.Errorf("username = %v, want alice", val)
	}
}

func TestUpsertEntry_UpdateExisting(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	// Create entry first
	writeTestEntry(t, v, "test/existing", map[string]any{"username": "alice"})

	// Update it
	data := map[string]any{"username": "alice-updated"}
	err := ops.UpsertEntry(v, "test/existing", data, "update", nil)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}

	val, err := ops.GetField(v, "test/existing", "username")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "alice-updated" {
		t.Errorf("username = %v, want alice-updated", val)
	}
}

func TestUpsertEntry_ValidationError(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	longValue := strings.Repeat("x", MaxFieldLength+1)
	data := map[string]any{"field": longValue}

	err := ops.UpsertEntry(v, "test/oversized", data, "create", nil)
	if err == nil {
		t.Fatal("UpsertEntry() error = nil, want error for oversized field")
	}
}

func TestUpsertEntry_WithProvenance(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	provenance := &WriteRecord{Action: "set", Field: "token"}
	data := map[string]any{"token": "abc123"}

	err := ops.UpsertEntry(v, "test/provenance", data, "", provenance)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}

	val, err := ops.GetField(v, "test/provenance", "token")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "abc123" {
		t.Errorf("token = %v, want abc123", val)
	}
}

func TestUpsertEntry_CreateWithAction(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	data := map[string]any{"key": "value"}

	err := ops.UpsertEntry(v, "test/action", data, "add-credential", nil)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}

	val, err := ops.GetField(v, "test/action", "key")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "value" {
		t.Errorf("key = %v, want value", val)
	}
}

func TestUpsertEntry_ReadError(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	data := map[string]any{"key": "value"}

	// Invalid path triggers a read error (not ErrNotExist specifically)
	err := ops.UpsertEntry(v, "../escape", data, "create", nil)
	if err == nil {
		t.Fatal("UpsertEntry() error = nil, want error for invalid path")
	}
}

func TestUpsertEntry_WeakPasswordTagged(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	data := map[string]any{"password": "123"}

	err := ops.UpsertEntry(v, "test/weak-pw", data, "create", nil)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}

	entry, err := ReadEntry(v.Dir, "test/weak-pw", v.Identity)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if !entry.HasTag(TagWeakPassword) {
		t.Error("expected weak-password tag on entry with weak password")
	}
}

func TestUpsertEntry_SingleFieldProvenance(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	provenance := &WriteRecord{Action: "rotate"}
	data := map[string]any{"api_key": "new-key-value"}

	err := ops.UpsertEntry(v, "test/single-field", data, "", provenance)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}
	if provenance.Field != "api_key" {
		t.Errorf("provenance.Field = %q, want api_key", provenance.Field)
	}
}

// --- DefaultOperationService.WriteEntry ---

func TestWriteEntry_Success(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	entry := &Entry{Data: map[string]any{"key": "value"}}

	err := ops.WriteEntry(v, "test/write", entry)
	if err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	val, err := ops.GetField(v, "test/write", "key")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "value" {
		t.Errorf("key = %v, want value", val)
	}
}

func TestWriteEntry_InvalidPath(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	entry := &Entry{Data: map[string]any{"key": "value"}}

	err := ops.WriteEntry(v, "../escape", entry)
	if err == nil {
		t.Fatal("WriteEntry() error = nil, want error for invalid path")
	}
}

// --- DefaultOperationService.GetEntry ---

func TestGetEntry_Success(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/get", map[string]any{"user": "bob"})

	entry, err := ops.GetEntry(v, "test/get")
	if err != nil {
		t.Fatalf("GetEntry() error = %v", err)
	}
	if entry.Data["user"] != "bob" {
		t.Errorf("Data[user] = %v, want bob", entry.Data["user"])
	}
}

func TestGetEntry_NotFound(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	_, err := ops.GetEntry(v, "nonexistent")
	if err == nil {
		t.Fatal("GetEntry() error = nil, want error for nonexistent entry")
	}
}

func TestGetEntry_ReadError(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	_, err := ops.GetEntry(v, "../escape")
	if err == nil {
		t.Fatal("GetEntry() error = nil, want error for invalid path")
	}
}

// --- DefaultOperationService.DeleteEntry ---

func TestDeleteEntry_Success(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/delete", map[string]any{"key": "val"})

	err := ops.DeleteEntry(v, "test/delete")
	if err != nil {
		t.Fatalf("DeleteEntry() error = %v", err)
	}

	// Verify entry is gone
	_, err = ops.GetEntry(v, "test/delete")
	if err == nil {
		t.Fatal("expected error reading deleted entry")
	}
}

func TestDeleteEntry_NotFound(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	err := ops.DeleteEntry(v, "nonexistent/entry")
	if err == nil {
		t.Fatal("DeleteEntry() error = nil, want error for nonexistent entry")
	}
}

// --- DefaultOperationService.ListEntries ---

func TestListEntries_Empty(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	entries, err := ops.ListEntries(v, "")
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("ListEntries() returned %d entries, want 0", len(entries))
	}
}

func TestListEntries_WithEntries(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/a", map[string]any{"k": "v1"})
	writeTestEntry(t, v, "test/b", map[string]any{"k": "v2"})

	entries, err := ops.ListEntries(v, "test/")
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("ListEntries() returned %d entries, want 2", len(entries))
	}
}

func TestListEntries_WithPrefix(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "work/aws", map[string]any{"key": "val"})
	writeTestEntry(t, v, "personal/github", map[string]any{"key": "val"})

	entries, err := ops.ListEntries(v, "work/")
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("ListEntries() returned %d entries, want 1", len(entries))
	}
}

func TestListEntries_ReadError(t *testing.T) {
	ops := DefaultOperationService{}

	_, err := ops.ListEntries(&Vault{Dir: "/nonexistent/vault/dir"}, "")
	if err == nil {
		t.Fatal("ListEntries() error = nil, want error for nonexistent vault")
	}
}

// --- DefaultOperationService.ListEntryInfos ---

func TestListEntryInfos_Empty(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	infos, err := ops.ListEntryInfos(v, "", 0)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if infos != nil {
		t.Errorf("ListEntryInfos() returned %v, want nil for empty vault", infos)
	}
}

func TestListEntryInfos_WithEntries(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/info", map[string]any{"username": "alice", "password": "secret"})

	infos, err := ops.ListEntryInfos(v, "test/", 2)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("ListEntryInfos() returned %d infos, want 1", len(infos))
	}
	if infos[0].Path != "test/info" {
		t.Errorf("Path = %q, want test/info", infos[0].Path)
	}
	if infos[0].FieldCount != 2 {
		t.Errorf("FieldCount = %d, want 2", infos[0].FieldCount)
	}
	if !infos[0].HasValue {
		t.Error("expected HasValue=true for entry with password field")
	}
}

func TestListEntryInfos_NoPasswordField(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/nopw", map[string]any{"username": "alice"})

	infos, err := ops.ListEntryInfos(v, "test/", 1)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("ListEntryInfos() returned %d infos, want 1", len(infos))
	}
	if infos[0].HasValue {
		t.Error("expected HasValue=false for entry without password/secret field")
	}
}

func TestListEntryInfos_DefaultWorkers(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/default-workers", map[string]any{"k": "v"})

	// configuredWorkers=0 should use default (min(NumCPU, 8))
	infos, err := ops.ListEntryInfos(v, "test/", 0)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("ListEntryInfos() returned %d infos, want 1", len(infos))
	}
}

func TestListEntryInfos_ManyEntries(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	for i := range 10 {
		writeTestEntry(t, v, fmt.Sprintf("test/entry-%d", i), map[string]any{
			"username": fmt.Sprintf("user%d", i),
			"password": fmt.Sprintf("pass%d", i),
		})
	}

	infos, err := ops.ListEntryInfos(v, "test/", 4)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if len(infos) != 10 {
		t.Fatalf("ListEntryInfos() returned %d infos, want 10", len(infos))
	}
}

// --- DefaultOperationService.FindEntries ---

func TestFindEntries_Success(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "github/user", map[string]any{"username": "alice"})

	matches, err := ops.FindEntries(v, "github", FindOptions{})
	if err != nil {
		t.Fatalf("FindEntries() error = %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("FindEntries() returned 0 matches, want >= 1")
	}
}

func TestFindEntries_NoMatches(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "github/user", map[string]any{"username": "alice"})

	matches, err := ops.FindEntries(v, "nonexistent", FindOptions{})
	if err != nil {
		t.Fatalf("FindEntries() error = %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("FindEntries() returned %d matches, want 0", len(matches))
	}
}

func TestFindEntries_SearchError(t *testing.T) {
	ops := DefaultOperationService{}
	_, err := ops.FindEntries(&Vault{Dir: "/nonexistent/vault/dir"}, "query", FindOptions{})
	if err == nil {
		t.Fatal("FindEntries() error = nil, want error for nonexistent vault")
	}
}

// --- DefaultOperationService.VaultDir ---

func TestVaultDir(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	dir := ops.VaultDir(v)
	if dir != v.Dir {
		t.Errorf("VaultDir() = %q, want %q", dir, v.Dir)
	}
}

// --- DefaultOperationService.VaultIdentity ---

func TestVaultIdentity(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	identity := ops.VaultIdentity(v)
	if identity != v.Identity {
		t.Error("VaultIdentity() returned wrong identity")
	}
}

// --- vaultDeleteHelper ---

func TestVaultDeleteHelper_Success(t *testing.T) {
	v := newTestVault(t)
	writeTestEntry(t, v, "test/vdh", map[string]any{"k": "v"})

	err := vaultDeleteHelper(v.Dir, "test/vdh", v.Identity)
	if err != nil {
		t.Fatalf("vaultDeleteHelper() error = %v", err)
	}
}

func TestVaultDeleteHelper_NotFound(t *testing.T) {
	v := newTestVault(t)

	err := vaultDeleteHelper(v.Dir, "nonexistent/path", v.Identity)
	if err == nil {
		t.Fatal("vaultDeleteHelper() error = nil, want error for nonexistent entry")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("vaultDeleteHelper() error = %v, want os.ErrNotExist", err)
	}
}

// --- VaultService delegation ---

func TestVaultService_DelegatesGetField(t *testing.T) {
	v := newTestVault(t)
	writeTestEntry(t, v, "test/delegate", map[string]any{"user": "alice"})

	svc := NewVaultService(v, nil)
	val, err := svc.GetField("test/delegate", "user")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "alice" {
		t.Errorf("GetField() = %v, want alice", val)
	}
}

func TestVaultService_DelegatesUpsertEntry(t *testing.T) {
	v := newTestVault(t)
	svc := NewVaultService(v, nil)

	data := map[string]any{"user": "bob"}
	if err := svc.UpsertEntry("test/delegate-upsert", data, "create", nil); err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}

	val, err := svc.GetField("test/delegate-upsert", "user")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "bob" {
		t.Errorf("user = %v, want bob", val)
	}
}

func TestVaultService_DelegatesWriteEntry(t *testing.T) {
	v := newTestVault(t)
	svc := NewVaultService(v, nil)

	entry := &Entry{Data: map[string]any{"token": "abc"}}
	if err := svc.WriteEntry("test/delegate-write", entry); err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	val, err := svc.GetField("test/delegate-write", "token")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "abc" {
		t.Errorf("token = %v, want abc", val)
	}
}

func TestVaultService_DelegatesDeleteEntry(t *testing.T) {
	v := newTestVault(t)
	writeTestEntry(t, v, "test/delegate-delete", map[string]any{"k": "v"})
	svc := NewVaultService(v, nil)

	if err := svc.DeleteEntry("test/delegate-delete"); err != nil {
		t.Fatalf("DeleteEntry() error = %v", err)
	}
}

func TestVaultService_DelegatesListEntries(t *testing.T) {
	v := newTestVault(t)
	writeTestEntry(t, v, "test/delegate-list", map[string]any{"k": "v"})
	svc := NewVaultService(v, nil)

	entries, err := svc.ListEntries("test/")
	if err != nil {
		t.Fatalf("ListEntries() error = %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("ListEntries() returned %d, want 1", len(entries))
	}
}

func TestVaultService_DelegatesListEntryInfos(t *testing.T) {
	v := newTestVault(t)
	writeTestEntry(t, v, "test/delegate-infos", map[string]any{"k": "v"})
	svc := NewVaultService(v, nil)

	infos, err := svc.ListEntryInfos("test/", 1)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if len(infos) != 1 {
		t.Errorf("ListEntryInfos() returned %d, want 1", len(infos))
	}
}

func TestVaultService_DelegatesFindEntries(t *testing.T) {
	v := newTestVault(t)
	writeTestEntry(t, v, "test/delegate-find", map[string]any{"k": "v"})
	svc := NewVaultService(v, nil)

	matches, err := svc.FindEntries("delegate-find", FindOptions{})
	if err != nil {
		t.Fatalf("FindEntries() error = %v", err)
	}
	if len(matches) == 0 {
		t.Error("FindEntries() returned 0 matches, want >= 1")
	}
}

func TestVaultService_DelegatesVaultDir(t *testing.T) {
	v := newTestVault(t)
	svc := NewVaultService(v, nil)

	if got := svc.VaultDir(); got != v.Dir {
		t.Errorf("VaultDir() = %q, want %q", got, v.Dir)
	}
}

func TestVaultService_DelegatesVaultIdentity(t *testing.T) {
	v := newTestVault(t)
	svc := NewVaultService(v, nil)

	if got := svc.VaultIdentity(); got != v.Identity {
		t.Error("VaultIdentity() returned wrong identity")
	}
}

func TestVaultService_DelegatesGetEntry(t *testing.T) {
	v := newTestVault(t)
	writeTestEntry(t, v, "test/delegate-get", map[string]any{"user": "carol"})
	svc := NewVaultService(v, nil)

	entry, err := svc.GetEntry("test/delegate-get")
	if err != nil {
		t.Fatalf("GetEntry() error = %v", err)
	}
	if entry.Data["user"] != "carol" {
		t.Errorf("Data[user] = %v, want carol", entry.Data["user"])
	}
}

// --- UpsertEntry edge cases ---

func TestUpsertEntry_UpdateWithProvenance(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/update-prov", map[string]any{"old": "data"})

	provenance := &WriteRecord{Action: "rotate"}
	data := map[string]any{"new": "data"}

	err := ops.UpsertEntry(v, "test/update-prov", data, "update", provenance)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}
}

func TestUpsertEntry_CreateWithProvenanceAction(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}

	provenance := &WriteRecord{Action: "import"}
	data := map[string]any{"imported": "value"}

	err := ops.UpsertEntry(v, "test/prov-action", data, "default-action", provenance)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}

	val, err := ops.GetField(v, "test/prov-action", "imported")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "value" {
		t.Errorf("imported = %v, want value", val)
	}
}

func TestUpsertEntry_UpdateWithAction(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/update-action", map[string]any{"k": "old"})

	data := map[string]any{"k": "new"}
	err := ops.UpsertEntry(v, "test/update-action", data, "change-password", nil)
	if err != nil {
		t.Fatalf("UpsertEntry() error = %v", err)
	}

	val, err := ops.GetField(v, "test/update-action", "k")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != "new" {
		t.Errorf("k = %v, want new", val)
	}
}

// --- GetField edge cases ---

func TestGetField_NestedFieldValue(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/nested", map[string]any{
		"config": map[string]any{
			"api_key": "secret-key",
		},
	})

	// Top-level field is a map, not a string
	val, err := ops.GetField(v, "test/nested", "config")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	config, ok := val.(map[string]any)
	if !ok {
		t.Fatalf("GetField() returned %T, want map[string]any", val)
	}
	if config["api_key"] != "secret-key" {
		t.Errorf("config[api_key] = %v, want secret-key", config["api_key"])
	}
}

// --- ListEntryInfos edge cases ---

func TestListEntryInfos_WithSecretField(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/secret-field", map[string]any{"secret": "mysecret"})

	infos, err := ops.ListEntryInfos(v, "test/", 1)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("ListEntryInfos() returned %d infos, want 1", len(infos))
	}
	if !infos[0].HasValue {
		t.Error("expected HasValue=true for entry with secret field")
	}
}

func TestListEntryInfos_LargeWorkerCount(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/large-workers", map[string]any{"k": "v"})

	// More workers than entries should still work (clamped to len(paths))
	infos, err := ops.ListEntryInfos(v, "test/", 100)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if len(infos) != 1 {
		t.Errorf("ListEntryInfos() returned %d infos, want 1", len(infos))
	}
}

func TestListEntryInfos_NegativeWorkerCount(t *testing.T) {
	v := newTestVault(t)
	ops := DefaultOperationService{}
	writeTestEntry(t, v, "test/neg-workers", map[string]any{"k": "v"})

	// Negative worker count should use default
	infos, err := ops.ListEntryInfos(v, "test/", -1)
	if err != nil {
		t.Fatalf("ListEntryInfos() error = %v", err)
	}
	if len(infos) != 1 {
		t.Errorf("ListEntryInfos() returned %d infos, want 1", len(infos))
	}
}

func TestListEntryInfos_ReadError(t *testing.T) {
	ops := DefaultOperationService{}

	_, err := ops.ListEntryInfos(&Vault{Dir: "/nonexistent/vault/dir"}, "", 0)
	if err == nil {
		t.Fatal("ListEntryInfos() error = nil, want error for nonexistent vault")
	}
}

// --- NewVaultService additional ---

func TestNewVaultService_KeepsCustomOps(t *testing.T) {
	v := newTestVault(t)
	fake := &fakeOperationService{}
	svc := NewVaultService(v, fake)

	// Calling GetField should go through the fake (returns nil, nil)
	val, err := svc.GetField("any/path", "any/field")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if val != nil {
		t.Errorf("GetField() = %v, want nil (from fake)", val)
	}
}

// --- ValidateFieldLengths additional ---

func TestValidateFieldLengths_MapWithNonStringNonMapValues(t *testing.T) {
	data := map[string]any{
		"ints":     12345,
		"floats":   3.14,
		"booleans": true,
		"nilval":   nil,
	}
	if err := ValidateFieldLengths(data); err != nil {
		t.Errorf("ValidateFieldLengths() error = %v, want nil", err)
	}
}

func TestValidateFieldLengths_DeepNestedNormal(t *testing.T) {
	data := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": "short",
			},
		},
	}
	if err := ValidateFieldLengths(data); err != nil {
		t.Errorf("ValidateFieldLengths() error = %v, want nil", err)
	}
}

func TestValidateFieldLengths_DeepNestedExceeds(t *testing.T) {
	long := strings.Repeat("c", MaxFieldLength+1)
	data := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"level3": long,
			},
		},
	}
	err := ValidateFieldLengths(data)
	if err == nil {
		t.Fatal("ValidateFieldLengths() error = nil, want error for deeply nested oversized field")
	}
}
