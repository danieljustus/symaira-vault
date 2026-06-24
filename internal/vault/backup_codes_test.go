package vault

import (
	"testing"
	"time"
)

func TestMigrateBackupCodes(t *testing.T) {
	t.Run("string gets migrated", func(t *testing.T) {
		entry := &Entry{Data: map[string]any{
			BackupCodesField: "code1\ncode2\n\ncode3",
		}}
		if !MigrateBackupCodes(entry) {
			t.Fatal("expected migration")
		}
		codes, ok := entry.Data[BackupCodesField].([]any)
		if !ok {
			t.Fatalf("backup_codes type = %T, want []any", entry.Data[BackupCodesField])
		}
		if len(codes) != 3 || codes[0] != "code1" || codes[1] != "code2" || codes[2] != "code3" {
			t.Errorf("codes = %v, want [code1 code2 code3]", codes)
		}
		used, ok := entry.Data[BackupCodesUsedField].(map[string]any)
		if !ok {
			t.Fatalf("backup_codes_used type = %T, want map[string]any", entry.Data[BackupCodesUsedField])
		}
		if len(used) != 0 {
			t.Errorf("used map length = %d, want 0", len(used))
		}
	})

	t.Run("already structured is unchanged", func(t *testing.T) {
		entry := &Entry{Data: map[string]any{
			BackupCodesField:     []any{"code1"},
			BackupCodesUsedField: map[string]any{},
		}}
		if MigrateBackupCodes(entry) {
			t.Error("expected no migration for already-structured codes")
		}
	})

	t.Run("empty string does nothing", func(t *testing.T) {
		entry := &Entry{Data: map[string]any{BackupCodesField: ""}}
		if MigrateBackupCodes(entry) {
			t.Error("expected no migration for empty string")
		}
	})
}

func TestBackupCodes(t *testing.T) {
	entry := &Entry{Data: map[string]any{
		BackupCodesField: "a\nb",
	}}
	codes := BackupCodes(entry)
	if len(codes) != 2 || codes[0] != "a" || codes[1] != "b" {
		t.Errorf("BackupCodes = %v, want [a b]", codes)
	}
}

func TestMarkBackupCodeUsed(t *testing.T) {
	entry := &Entry{Data: map[string]any{
		BackupCodesField: "a\nb",
	}}
	usedAt := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	if !MarkBackupCodeUsed(entry, "a", usedAt) {
		t.Fatal("expected marking code 'a' to succeed")
	}
	if !BackupCodeUsed(entry, "a") {
		t.Error("expected code 'a' to be used")
	}
	if BackupCodeUsed(entry, "b") {
		t.Error("expected code 'b' to be unused")
	}
	if MarkBackupCodeUsed(entry, "a", usedAt) {
		t.Error("expected re-marking used code to fail")
	}
	if MarkBackupCodeUsed(entry, "c", usedAt) {
		t.Error("expected marking unknown code to fail")
	}
}
