package vault

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestPrepareEntryForWriteDeterministicMetadata(t *testing.T) {
	now := time.Date(2026, 9, 8, 10, 11, 12, 123456789, time.FixedZone("fixture", 3600))
	created := time.Date(2026, 9, 7, 1, 2, 3, 987654321, time.FixedZone("old", -7200))
	entry := &Entry{
		Path: "original",
		Data: map[string]any{"nested": map[string]any{"keep": "value"}},
		Metadata: EntryMetadata{
			Created: created,
			Version: 4,
			WriteHistory: []WriteRecord{{
				Timestamp: created,
				Field:     "old",
				Action:    "create",
			}},
		},
		PendingWrite: &WriteRecord{Field: "token", Action: "set"},
	}
	beforeJSON, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}

	got := PrepareEntryForWrite(entry, now, "logical/path", true)
	afterJSON, err := json.Marshal(entry)
	if err != nil || string(afterJSON) != string(beforeJSON) || got == entry {
		t.Fatal("preparation must not mutate or reuse its input")
	}
	if !got.Metadata.Created.Equal(created) {
		t.Fatalf("created changed: %v", got.Metadata.Created)
	}
	wantNow := now.UTC()
	if !got.Metadata.Updated.Equal(wantNow) || got.Metadata.Updated.Nanosecond() != now.Nanosecond() {
		t.Fatalf("updated = %s, want exact UTC %s", got.Metadata.Updated.Format(time.RFC3339Nano), wantNow.Format(time.RFC3339Nano))
	}
	if got.Metadata.Version != 5 || got.Path != "logical/path" {
		t.Fatalf("metadata = %#v, path = %q", got.Metadata, got.Path)
	}
	if len(got.Metadata.WriteHistory) != 2 || got.Metadata.WriteHistory[1].Field != "token" || !got.Metadata.WriteHistory[1].Timestamp.Equal(wantNow) {
		t.Fatalf("history = %#v", got.Metadata.WriteHistory)
	}
	if got.PendingWrite != nil {
		t.Fatal("pending write was not cleared")
	}
	got.Data["nested"].(map[string]any)["keep"] = "changed"
	if entry.Data["nested"].(map[string]any)["keep"] != "value" {
		t.Fatal("nested input data was aliased")
	}
}

func TestPrepareEntryForWriteCreatedZeroAndNilData(t *testing.T) {
	now := time.Date(2026, 9, 8, 10, 11, 12, 123456789, time.UTC)
	got := PrepareEntryForWrite(&Entry{Metadata: EntryMetadata{Version: 0}}, now, "path", false)
	if !got.Metadata.Created.Equal(now) || !got.Metadata.Updated.Equal(now) {
		t.Fatalf("zero created metadata = %#v", got.Metadata)
	}
	if got.Data == nil || len(got.Data) != 0 {
		t.Fatalf("nil data = %#v", got.Data)
	}
	if got.Path != "" {
		t.Fatalf("path changed with pseudonymization disabled: %q", got.Path)
	}
}

func TestPrepareEntryForWriteVersionUsesGoIntBounds(t *testing.T) {
	got := PrepareEntryForWrite(&Entry{Metadata: EntryMetadata{Version: math.MaxInt}}, time.Unix(0, 0), "", false)
	if got.Metadata.Version != math.MinInt {
		t.Fatalf("version overflow = %d, want %d", got.Metadata.Version, math.MinInt)
	}
}

func TestPrepareEntryForWriteIsRepeatable(t *testing.T) {
	now := time.Date(2026, 9, 8, 10, 11, 12, 123456789, time.UTC)
	entry := &Entry{Data: map[string]any{"x": "y"}, PendingWrite: &WriteRecord{Field: "x", Action: "set"}}
	first := PrepareEntryForWrite(entry, now, "p", true)
	second := PrepareEntryForWrite(entry, now, "p", true)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same input and clock produced different results:\nfirst=%#v\nsecond=%#v", first, second)
	}
}
