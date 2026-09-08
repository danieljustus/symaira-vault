package vault

import "time"

// PrepareEntryForWrite clones entry and applies the deterministic metadata
// mutations shared by all entry writers. It performs no I/O and does not read a
// clock; callers supply now so the transformation can be tested and ported
// byte-for-byte. The returned entry owns its mutable maps, slices, and pending
// record, leaving entry unchanged.
func PrepareEntryForWrite(entry *Entry, now time.Time, path string, pseudonymize bool) *Entry {
	prepared := cloneEntry(entry)
	if prepared == nil {
		return nil
	}
	now = now.UTC()
	if prepared.Metadata.Created.IsZero() {
		prepared.Metadata.Created = now
	}
	prepared.Metadata.Updated = now
	prepared.Metadata.Version++
	if prepared.Data == nil {
		prepared.Data = map[string]any{}
	}
	if prepared.PendingWrite != nil {
		record := *prepared.PendingWrite
		record.Timestamp = now
		prepared.Metadata.WriteHistory = append(prepared.Metadata.WriteHistory, record)
		prepared.PendingWrite = nil
	}
	if pseudonymize {
		prepared.Path = path
	}
	return prepared
}
