package vault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
)

const testRecipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
const testRecipient2 = "age1savzx9za5xg4fvwkeq788v50esvs3ccn9sscdxevw2fev9xdyeps8z9z65"

func TestNewRecipientsManager(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	if rm == nil {
		t.Fatal("NewRecipientsManager returned nil")
	}

	if rm.vaultDir != tmpDir {
		t.Errorf("expected vaultDir to be %q, got %q", tmpDir, rm.vaultDir)
	}
}

func TestRecipientsManager_ValidateVaultDir(t *testing.T) {
	tests := []struct {
		name     string
		vaultDir string
		wantErr  bool
	}{
		{
			name:     "valid path",
			vaultDir: t.TempDir(),
			wantErr:  false,
		},
		{
			name:     "path with parent traversal",
			vaultDir: "/tmp/../etc",
			wantErr:  true,
		},
		{
			name:     "path with literal dots in segment",
			vaultDir: filepath.Join(t.TempDir(), "my..vault"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := &RecipientsManager{vaultDir: tt.vaultDir}
			err := rm.validateVaultDir()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateVaultDir() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRecipientsManager_RecipientsFilePath(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	expected := filepath.Join(tmpDir, "recipients.txt")
	got := rm.RecipientsFilePath()

	if got != expected {
		t.Errorf("RecipientsFilePath() = %q, want %q", got, expected)
	}
}

func TestRecipientsManager_RecipientsFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	if rm.RecipientsFileExists() {
		t.Error("RecipientsFileExists() should return false for non-existent file")
	}

	if err := os.WriteFile(rm.RecipientsFilePath(), []byte{}, 0o600); err != nil {
		t.Fatalf("failed to create recipients file: %v", err)
	}

	if !rm.RecipientsFileExists() {
		t.Error("RecipientsFileExists() should return true for existing file")
	}
}

func TestRecipientsManager_LoadRecipients_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	if err := os.WriteFile(rm.RecipientsFilePath(), []byte{}, 0o600); err != nil {
		t.Fatalf("failed to create recipients file: %v", err)
	}

	recipients, err := rm.LoadRecipients()
	if err != nil {
		t.Errorf("LoadRecipients() error = %v", err)
	}

	if len(recipients) != 0 {
		t.Errorf("LoadRecipients() returned %d recipients, want 0", len(recipients))
	}
}

func TestRecipientsManager_LoadRecipients_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	recipients, err := rm.LoadRecipients()
	if err != nil {
		t.Errorf("LoadRecipients() error = %v", err)
	}

	if len(recipients) != 0 {
		t.Errorf("LoadRecipients() returned %d recipients, want 0", len(recipients))
	}
}

func TestRecipientsManager_LoadRecipients_WithComments(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	content := `# This is a comment
` + testRecipient + `
# Another comment
` + testRecipient2 + `
`

	if err := os.WriteFile(rm.RecipientsFilePath(), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to create recipients file: %v", err)
	}

	recipients, err := rm.LoadRecipients()
	if err != nil {
		t.Errorf("LoadRecipients() error = %v", err)
	}

	if len(recipients) != 2 {
		t.Errorf("LoadRecipients() returned %d recipients, want 2", len(recipients))
	}
}

func TestRecipientsManager_LoadRecipients_InvalidRecipient(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	content := testRecipient + `
invalid-recipient-key
`

	if err := os.WriteFile(rm.RecipientsFilePath(), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to create recipients file: %v", err)
	}

	_, err := rm.LoadRecipients()
	if err == nil {
		t.Error("LoadRecipients() should return error for invalid recipient")
	}
}

func TestRecipientsManager_LoadRecipientStrings(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	content := testRecipient + `
` + testRecipient2 + `
`

	if err := os.WriteFile(rm.RecipientsFilePath(), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to create recipients file: %v", err)
	}

	lines, err := rm.LoadRecipientStrings()
	if err != nil {
		t.Errorf("LoadRecipientStrings() error = %v", err)
	}

	if len(lines) != 2 {
		t.Errorf("LoadRecipientStrings() returned %d lines, want 2", len(lines))
	}

	if lines[0] != testRecipient {
		t.Errorf("LoadRecipientStrings()[0] = %q, want %q", lines[0], testRecipient)
	}
}

func TestRecipientsManager_AddRecipient_Success(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	var err error
	if err = rm.AddRecipient(testRecipient); err != nil {
		t.Errorf("AddRecipient() error = %v", err)
	}

	recipients, err := rm.LoadRecipients()
	if err != nil {
		t.Errorf("LoadRecipients() error = %v", err)
	}

	if len(recipients) != 1 {
		t.Errorf("got %d recipients, want 1", len(recipients))
	}
}

func TestRecipientsManager_AddRecipient_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	err := rm.AddRecipient("invalid-key")
	if err == nil {
		t.Error("AddRecipient() should return error for invalid key")
	}

	if !errors.Is(err, ErrInvalidRecipient) {
		t.Errorf("AddRecipient() error = %v, want ErrInvalidRecipient", err)
	}
}

func TestRecipientsManager_AddRecipient_Duplicate(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	if err := rm.AddRecipient(testRecipient); err != nil {
		t.Fatalf("first AddRecipient() failed: %v", err)
	}

	err := rm.AddRecipient(testRecipient)
	if err == nil {
		t.Error("AddRecipient() should return error for duplicate")
	}

	if !errors.Is(err, ErrRecipientAlreadyExists) {
		t.Errorf("AddRecipient() error = %v, want ErrRecipientAlreadyExists", err)
	}
}

func TestRecipientsManager_AddRecipient_MultipleRecipients(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	if err := rm.AddRecipient(testRecipient); err != nil {
		t.Fatalf("first AddRecipient() failed: %v", err)
	}

	if err := rm.AddRecipient(testRecipient2); err != nil {
		t.Fatalf("second AddRecipient() failed: %v", err)
	}

	recipients, err := rm.LoadRecipients()
	if err != nil {
		t.Fatalf("LoadRecipients() error = %v", err)
	}

	if len(recipients) != 2 {
		t.Errorf("got %d recipients, want 2", len(recipients))
	}
}

func TestRecipientsManager_AddRecipient_AppendToFileWithNewline(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	if err := rm.AddRecipient(testRecipient); err != nil {
		t.Fatalf("first AddRecipient() failed: %v", err)
	}

	if err := rm.AddRecipient(testRecipient2); err != nil {
		t.Fatalf("second AddRecipient() failed: %v", err)
	}

	recipients, err := rm.LoadRecipients()
	if err != nil {
		t.Fatalf("LoadRecipients() error = %v", err)
	}

	if len(recipients) != 2 {
		t.Errorf("got %d recipients, want 2", len(recipients))
	}
}

func TestRecipientsManager_AddRecipient_PathTraversal(t *testing.T) {
	rm := &RecipientsManager{vaultDir: "/tmp/../etc"}

	err := rm.AddRecipient(testRecipient)
	if err == nil {
		t.Error("AddRecipient() should return error for path traversal")
	}
}

func TestRecipientsManager_RemoveRecipient_Success(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	if err := rm.AddRecipient(testRecipient); err != nil {
		t.Fatalf("AddRecipient() failed: %v", err)
	}

	if err := rm.RemoveRecipient(testRecipient); err != nil {
		t.Errorf("RemoveRecipient() error = %v", err)
	}

	recipients, err := rm.LoadRecipients()
	if err != nil {
		t.Errorf("LoadRecipients() error = %v", err)
	}

	if len(recipients) != 0 {
		t.Errorf("got %d recipients, want 0", len(recipients))
	}
}

func TestRecipientsManager_RemoveRecipient_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	err := rm.RemoveRecipient(testRecipient)
	if err == nil {
		t.Error("RemoveRecipient() should return error for non-existent recipient")
	}

	if !errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("RemoveRecipient() error = %v, want ErrRecipientNotFound", err)
	}
}

func TestRecipientsManager_RemoveRecipient_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	if err := rm.AddRecipient(testRecipient); err != nil {
		t.Fatalf("AddRecipient() failed: %v", err)
	}

	err := rm.RemoveRecipient("invalid-key")
	if err == nil {
		t.Error("RemoveRecipient() should return error for invalid key")
	}

	if !errors.Is(err, ErrInvalidRecipient) {
		t.Errorf("RemoveRecipient() error = %v, want ErrInvalidRecipient", err)
	}
}

func TestRecipientsManager_RemoveRecipient_WithInvalidInFile(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	content := testRecipient + "\ninvalid-line\n" + testRecipient2 + "\n"
	if err := os.WriteFile(rm.RecipientsFilePath(), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to create recipients file: %v", err)
	}

	err := rm.RemoveRecipient(testRecipient)
	if err != nil {
		t.Errorf("RemoveRecipient() error = %v", err)
	}

	recipients, err := rm.LoadRecipientStrings()
	if err != nil {
		t.Errorf("LoadRecipientStrings() error = %v", err)
	}

	if len(recipients) != 2 {
		t.Errorf("got %d recipient strings, want 2 (invalid-line is kept + testRecipient2)", len(recipients))
	}

	for _, r := range recipients {
		if r == testRecipient {
			t.Error("testRecipient should have been removed")
		}
	}
}

func TestRecipientsManager_ListRecipients(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	content := `# Comment line
` + testRecipient + `
invalid-line
` + testRecipient2 + `
`

	if err := os.WriteFile(rm.RecipientsFilePath(), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to create recipients file: %v", err)
	}

	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Errorf("ListRecipients() error = %v", err)
	}

	if len(recipients) != 3 {
		t.Errorf("ListRecipients() returned %d recipients, want 3", len(recipients))
	}

	validCount := 0
	invalidCount := 0
	for _, r := range recipients {
		if r.Valid {
			validCount++
		} else {
			invalidCount++
		}
	}

	if validCount != 2 {
		t.Errorf("got %d valid recipients, want 2", validCount)
	}

	if invalidCount != 1 {
		t.Errorf("got %d invalid recipients, want 1", invalidCount)
	}
}

func TestRecipientsManager_ListRecipients_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	rm := NewRecipientsManager(tmpDir)

	recipients, err := rm.ListRecipients()
	if err != nil {
		t.Errorf("ListRecipients() error = %v", err)
	}

	if len(recipients) != 0 {
		t.Errorf("ListRecipients() returned %d recipients, want 0", len(recipients))
	}
}

func TestVault_GetAllRecipientsForEncryption(t *testing.T) {
	tmpDir := t.TempDir()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	v := &Vault{
		Dir:      tmpDir,
		Identity: identity,
	}

	rm := NewRecipientsManager(tmpDir)
	if err = rm.AddRecipient(testRecipient); err != nil {
		t.Fatalf("AddRecipient() failed: %v", err)
	}

	recipients, err := v.GetAllRecipientsForEncryption()
	if err != nil {
		t.Errorf("GetAllRecipientsForEncryption() error = %v", err)
	}

	if len(recipients) != 2 {
		t.Errorf("got %d recipients, want 2", len(recipients))
	}

	if recipients[0].String() != identity.Recipient().String() {
		t.Error("first recipient should be vault's own recipient")
	}
}

func TestVault_GetAllRecipientsForEncryption_NilIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	v := &Vault{
		Dir:      tmpDir,
		Identity: nil,
	}

	_, err := v.GetAllRecipientsForEncryption()
	if err == nil {
		t.Error("GetAllRecipientsForEncryption() should return error for nil identity")
	}

	if !errors.Is(err, vaultcrypto.ErrNilIdentity) {
		t.Errorf("GetAllRecipientsForEncryption() error = %v, want ErrNilIdentity", err)
	}
}

func TestWriteEntryWithRecipients(t *testing.T) {
	tmpDir := t.TempDir()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	rm := NewRecipientsManager(tmpDir)
	if err := rm.AddRecipient(testRecipient); err != nil {
		t.Fatalf("AddRecipient() failed: %v", err)
	}

	entry := &Entry{
		Data: map[string]any{
			"username": "testuser",
			"password": "testpass",
		},
	}

	if err := WriteEntryWithRecipients(tmpDir, "test/path", entry, identity); err != nil {
		t.Errorf("WriteEntryWithRecipients() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "entries", "test", "path.age")); os.IsNotExist(err) {
		t.Error("entry file was not created")
	}
}

func TestWriteEntryWithRecipients_NilEntry(t *testing.T) {
	tmpDir := t.TempDir()
	identity, _ := age.GenerateX25519Identity()

	err := WriteEntryWithRecipients(tmpDir, "test", nil, identity)
	if err == nil {
		t.Error("WriteEntryWithRecipients() should return error for nil entry")
	}
}

func TestWriteEntryWithRecipients_NilIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	entry := &Entry{Data: map[string]any{}}

	err := WriteEntryWithRecipients(tmpDir, "test", entry, nil)
	if err == nil {
		t.Error("WriteEntryWithRecipients() should return error for nil identity")
	}
}

func TestMergeEntryWithRecipients(t *testing.T) {
	tmpDir := t.TempDir()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	entry := &Entry{
		Data: map[string]any{
			"username": "testuser",
			"password": "testpass",
		},
	}

	if err = WriteEntryWithRecipients(tmpDir, "test/path", entry, identity); err != nil {
		t.Fatalf("WriteEntryWithRecipients() failed: %v", err)
	}

	merged, err := MergeEntryWithRecipients(tmpDir, "test/path", map[string]any{
		"url": "https://example.com",
	}, identity)
	if err != nil {
		t.Errorf("MergeEntryWithRecipients() error = %v", err)
	}

	if merged.Data["username"] != "testuser" {
		t.Error("existing data was not preserved")
	}

	if merged.Data["url"] != "https://example.com" {
		t.Error("new data was not merged")
	}
}

func TestMergeEntryWithRecipients_NilData(t *testing.T) {
	tmpDir := t.TempDir()

	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	entry := &Entry{
		Data: nil,
	}

	if err = WriteEntryWithRecipients(tmpDir, "test/nil-data", entry, identity); err != nil {
		t.Fatalf("WriteEntryWithRecipients() failed: %v", err)
	}

	merged, err := MergeEntryWithRecipients(tmpDir, "test/nil-data", map[string]any{
		"password": "newpassword",
	}, identity)
	if err != nil {
		t.Errorf("MergeEntryWithRecipients() error = %v", err)
	}

	if merged.Data["password"] != "newpassword" {
		t.Error("new data was not merged")
	}
}
