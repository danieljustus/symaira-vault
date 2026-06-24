package vault

import (
	"strings"
	"time"
)

const (
	// BackupCodesField is the canonical data key for stored recovery codes.
	BackupCodesField = "backup_codes"
	// BackupCodesUsedField holds a map of code -> ISO-8601 timestamp.
	BackupCodesUsedField = "backup_codes_used"
)

// MigrateBackupCodes converts a legacy string-backed backup_codes field into
// the structured array + used-map format. It is idempotent: entries that are
// already structured are left unchanged. The function mutates entry.Data in
// place and returns true when a migration was performed.
func MigrateBackupCodes(entry *Entry) bool {
	if entry == nil || entry.Data == nil {
		return false
	}
	raw, ok := entry.Data[BackupCodesField].(string)
	if !ok || raw == "" {
		return false
	}
	codes := splitBackupCodes(raw)
	entry.Data[BackupCodesField] = codes
	if _, usedExists := entry.Data[BackupCodesUsedField]; !usedExists {
		entry.Data[BackupCodesUsedField] = map[string]any{}
	}
	return true
}

// BackupCodes returns the current backup codes for an entry, migrating a
// legacy string value on demand. It returns nil when the entry has no backup
// codes field.
func BackupCodes(entry *Entry) []string {
	if entry == nil || entry.Data == nil {
		return nil
	}
	MigrateBackupCodes(entry)
	raw, ok := entry.Data[BackupCodesField].([]any)
	if !ok {
		return nil
	}
	codes := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			codes = append(codes, s)
		}
	}
	return codes
}

// BackupCodeUsed reports whether a backup code has been marked as used.
func BackupCodeUsed(entry *Entry, code string) bool {
	if entry == nil || entry.Data == nil {
		return false
	}
	used, ok := entry.Data[BackupCodesUsedField].(map[string]any)
	if !ok {
		return false
	}
	_, exists := used[code]
	return exists
}

// MarkBackupCodeUsed records a code as used at the given time. It returns true
// when the code existed and was not already used.
func MarkBackupCodeUsed(entry *Entry, code string, usedAt time.Time) bool {
	codes := BackupCodes(entry)
	found := false
	for _, c := range codes {
		if c == code {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if entry.Data[BackupCodesUsedField] == nil {
		entry.Data[BackupCodesUsedField] = map[string]any{}
	}
	used, ok := entry.Data[BackupCodesUsedField].(map[string]any)
	if !ok {
		return false
	}
	if _, alreadyUsed := used[code]; alreadyUsed {
		return false
	}
	used[code] = usedAt.UTC().Format(time.RFC3339)
	return true
}

func splitBackupCodes(value string) []any {
	lines := strings.Split(value, "\n")
	codes := make([]any, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		codes = append(codes, line)
	}
	return codes
}
