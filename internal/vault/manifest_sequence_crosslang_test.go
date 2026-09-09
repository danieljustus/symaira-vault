package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

const manifestSequenceAdapter = "manifest-sequence-adapter"

var manifestSequenceBaseIDs = []string{"WRITE-MANIFEST-001", "WRITE-MANIFEST-002", "DELETE-MANIFEST-001", "MANIFEST-MISSING-001", "MANIFEST-MISSING-002", "MANIFEST-MALFORMED-001", "MANIFEST-MALFORMED-002"}

var manifestSequenceExtraIDs = []string{"MANIFEST-BOUNDARY-UPDATE-REMOVE-001", "MANIFEST-BOUNDARY-UPDATE-REMOVE-002", "MANIFEST-GENERATION-I64MAX-001"}

var manifestSequenceCases = append(append([]string{}, manifestSequenceBaseIDs...), manifestSequenceExtraIDs...)

type manifestSequenceOutcome struct {
	CaseID                      string `json:"case_id"`
	Direct                      string `json:"direct"`
	Highlevel                   string `json:"highlevel"`
	ManifestExists              bool   `json:"manifest_exists"`
	EntryExists                 bool   `json:"entry_exists"`
	AlphaRecordPresent          bool   `json:"alpha_record_present"`
	Generation                  int64  `json:"generation"`
	CreatedNonzero              bool   `json:"created_nonzero"`
	CreatedPreserved            bool   `json:"created_preserved"`
	UpdatedNonzero              bool   `json:"updated_nonzero"`
	EntryMTimeNonzero           bool   `json:"entry_mtime_nonzero"`
	DirectGeneration            int64  `json:"direct_generation"`
	RemoveGeneration            int64  `json:"remove_generation"`
	DirectRecordPresent         bool   `json:"direct_record_present"`
	RemoveRecordPresent         bool   `json:"remove_record_present"`
	DirectEntryMTimeUTC         bool   `json:"direct_entry_mtime_utc"`
	DirectMalformedPreserved    bool   `json:"direct_malformed_preserved"`
	HighlevelMalformedPreserved bool   `json:"highlevel_malformed_preserved"`
}

func TestManifestSequenceGoRustDifferential(t *testing.T) {
	declared := map[string]bool{}
	for _, id := range manifestSequenceCases {
		declared[id] = true
	}
	if len(manifestSequenceBaseIDs) != 7 || len(manifestSequenceExtraIDs) != 3 {
		t.Fatalf("unexpected manifest case partition: base=%d extra=%d", len(manifestSequenceBaseIDs), len(manifestSequenceExtraIDs))
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(mustManifestSource(t)), "../.."))
	target := os.Getenv("CARGO_TARGET_DIR")
	if target == "" {
		// Keep the fallback portable and scoped to this checkout; CI and local
		// verification normally provide CARGO_TARGET_DIR explicitly.
		target = filepath.Join(repo, "target")
	}
	manifestCargo := filepath.Join(repo, "crates", "symvault-store", "Cargo.toml")
	if output, err := runSearchIndexCommand(repo, target, "cargo", "build", "--locked", "--manifest-path", manifestCargo, "--example", manifestSequenceAdapter); err != nil {
		t.Fatalf("build Rust adapter: %v\n%s", err, output)
	}
	binary := filepath.Join(target, "debug", "examples", manifestSequenceAdapter)
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	executed := map[string]bool{}
	for _, id := range manifestSequenceCases {
		for _, pseudonymize := range []bool{false, true} {
			name := fmt.Sprintf("%s/pseudonymize=%t", id, pseudonymize)
			t.Run(name, func(t *testing.T) {
				executed[id] = true
				goRoot, goID := newManifestSequenceVaultVariant(t, pseudonymize)
				rustRoot := t.TempDir()
				if err := Init(rustRoot, goID, manifestSequenceConfig(rustRoot, pseudonymize)); err != nil {
					t.Fatal(err)
				}
				goOutcome := runManifestSequenceGo(t, id, goRoot, goID)
				rustOutcome := runManifestSequenceRust(t, binary, id, rustRoot, goID, pseudonymize)
				t.Logf("Go outcome: %+v", goOutcome)
				t.Logf("Rust outcome: %+v", rustOutcome)
				if goOutcome.CaseID != id || rustOutcome.CaseID != id {
					t.Fatalf("case ID mismatch: Go=%q Rust=%q", goOutcome.CaseID, rustOutcome.CaseID)
				}
				if !reflect.DeepEqual(goOutcome, rustOutcome) {
					t.Errorf("manifest parity mismatch\nGo:   %+v\nRust: %+v", goOutcome, rustOutcome)
				}
				wantRecord := id == "WRITE-MANIFEST-001" || id == "WRITE-MANIFEST-002" || id == "MANIFEST-MISSING-001"
				if id == "DELETE-MANIFEST-001" || id == "MANIFEST-MALFORMED-002" {
					wantRecord = false
				}
				if goOutcome.AlphaRecordPresent != wantRecord || rustOutcome.AlphaRecordPresent != wantRecord {
					t.Errorf("alpha manifest record presence: Go=%t Rust=%t want=%t", goOutcome.AlphaRecordPresent, rustOutcome.AlphaRecordPresent, wantRecord)
				}
				if wantRecord {
					assertManifestCiphertext(t, goRoot, goID, id)
					assertManifestCiphertext(t, rustRoot, goID, id)
				}
				if id == "WRITE-MANIFEST-001" || id == "WRITE-MANIFEST-002" || id == "DELETE-MANIFEST-001" {
					if goOutcome.Highlevel != "ok" || rustOutcome.Highlevel != "ok" {
						t.Errorf("high-level mutation outcome: Go=%s Rust=%s want ok", goOutcome.Highlevel, rustOutcome.Highlevel)
					}
				}
				if id == "WRITE-MANIFEST-002" {
					if !goOutcome.CreatedPreserved || !rustOutcome.CreatedPreserved {
						t.Errorf("replacement must preserve creation timestamp independently: Go=%t Rust=%t", goOutcome.CreatedPreserved, rustOutcome.CreatedPreserved)
					}
				}
				if id == "MANIFEST-GENERATION-I64MAX-001" {
					for name, outcome := range map[string]manifestSequenceOutcome{"Go": goOutcome, "Rust": rustOutcome} {
						if outcome.DirectGeneration != -9223372036854775808 || outcome.RemoveGeneration != -9223372036854775807 {
							t.Errorf("%s i64 generation: direct=%d remove=%d want -9223372036854775808/-9223372036854775807", name, outcome.DirectGeneration, outcome.RemoveGeneration)
						}
						if !outcome.DirectRecordPresent || outcome.RemoveRecordPresent || !outcome.CreatedPreserved {
							t.Errorf("%s i64 generation records/created: direct=%t remove=%t created=%t", name, outcome.DirectRecordPresent, outcome.RemoveRecordPresent, outcome.CreatedPreserved)
						}
					}
				}
				if id == "MANIFEST-BOUNDARY-UPDATE-REMOVE-001" || id == "MANIFEST-BOUNDARY-UPDATE-REMOVE-002" {
					wantCreatedNonzero := id == "MANIFEST-BOUNDARY-UPDATE-REMOVE-002"
					for name, outcome := range map[string]manifestSequenceOutcome{"Go": goOutcome, "Rust": rustOutcome} {
						if outcome.DirectGeneration != 2147483648 || outcome.RemoveGeneration != 2147483649 {
							t.Errorf("%s boundary generations: direct=%d remove=%d want 2147483648/2147483649", name, outcome.DirectGeneration, outcome.RemoveGeneration)
						}
						if !outcome.DirectRecordPresent || outcome.RemoveRecordPresent {
							t.Errorf("%s boundary record presence: direct=%t remove=%t want true/false", name, outcome.DirectRecordPresent, outcome.RemoveRecordPresent)
						}
						if !outcome.CreatedPreserved {
							t.Errorf("%s boundary created timestamp was not preserved", name)
						}
						if outcome.CreatedNonzero != wantCreatedNonzero {
							t.Errorf("%s boundary created nonzero: got %t want %t", name, outcome.CreatedNonzero, wantCreatedNonzero)
						}
					}
				}
			})
		}
	}
	if !reflect.DeepEqual(declared, executed) {
		t.Fatalf("declared/executed case IDs differ: declared=%v executed=%v", declared, executed)
	}
}

func manifestSequenceConfig(root string, pseudonymize bool) *config.Config {
	cfg := testConfig(root)
	cfg.Vault = &config.VaultConfig{PseudonymizePaths: pseudonymize}
	return cfg
}
func newManifestSequenceVaultVariant(t *testing.T, pseudonymize bool) (string, *age.X25519Identity) {
	t.Helper()
	root := t.TempDir()
	id := testutil.TempIdentity(t)
	if err := Init(root, id, manifestSequenceConfig(root, pseudonymize)); err != nil {
		t.Fatal(err)
	}
	return root, id
}
func mustManifestSource(t *testing.T) string {
	_, p, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	return p
}

func classifyManifestErr(err error) string {
	if err == nil {
		return "ok"
	}
	if os.IsNotExist(err) {
		return "missing"
	}
	s := err.Error()
	if bytes.Contains([]byte(s), []byte("manifest")) || bytes.Contains([]byte(s), []byte("decrypt")) || bytes.Contains([]byte(s), []byte("unmarshal")) {
		return "malformed"
	}
	return "error"
}

func runManifestSequenceGo(t *testing.T, id, root string, identity *age.X25519Identity) manifestSequenceOutcome {
	t.Helper()
	out := manifestSequenceOutcome{CaseID: id, Direct: "ok", Highlevel: "ok"}
	entry := &Entry{Data: map[string]any{"value": "one"}}
	var before, after *Manifest
	load := func() *Manifest {
		m, err := LoadManifest(root, identity)
		if err != nil {
			return nil
		}
		return m
	}
	switch id {
	case "WRITE-MANIFEST-001":
		out.Highlevel = classifyManifestErr(WriteEntry(root, "alpha", entry, identity))
	case "WRITE-MANIFEST-002":
		out.Highlevel = classifyManifestErr(WriteEntry(root, "alpha", entry, identity))
		if out.Highlevel == "ok" {
			before = load()
			out.Highlevel = classifyManifestErr(WriteEntry(root, "alpha", &Entry{Data: map[string]any{"value": "two"}}, identity))
			after = load()
		}
	case "DELETE-MANIFEST-001":
		out.Highlevel = classifyManifestErr(WriteEntry(root, "alpha", entry, identity))
		before = load()
		if out.Highlevel == "ok" {
			out.Highlevel = classifyManifestErr(DeleteEntry(root, "alpha", identity))
		}
		after = load()
	case "MANIFEST-MISSING-001":
		out.Direct = classifyManifestErr(UpdateManifestEntry(root, "alpha", []byte("ciphertext"), identity))
	case "MANIFEST-MISSING-002":
		out.Direct = classifyManifestErr(RemoveManifestEntry(root, "alpha", identity))
	case "MANIFEST-BOUNDARY-UPDATE-REMOVE-001", "MANIFEST-BOUNDARY-UPDATE-REMOVE-002":
		seedManifestSequenceBoundary(t, root, identity, id == "MANIFEST-BOUNDARY-UPDATE-REMOVE-002")
		before = load()
		out.Direct = classifyManifestErr(UpdateManifestEntry(root, "alpha", []byte("ciphertext"), identity))
		if m := load(); m != nil {
			out.DirectGeneration = int64(m.Generation)
			_, out.DirectRecordPresent = m.Entries["alpha"]
			if record, ok := m.Entries["alpha"]; ok {
				out.DirectEntryMTimeUTC = record.MTime.Location() == time.UTC && !record.MTime.IsZero()
			}
		}
		out.Highlevel = classifyManifestErr(RemoveManifestEntry(root, "alpha", identity))
		after = load()
		if m := after; m != nil {
			out.RemoveGeneration = int64(m.Generation)
			_, out.RemoveRecordPresent = m.Entries["alpha"]
		}
	case "MANIFEST-GENERATION-I64MAX-001":
		seedManifestSequenceI64Max(t, root, identity)
		before = load()
		out.Direct = classifyManifestErr(UpdateManifestEntry(root, "alpha", []byte("ciphertext"), identity))
		if m := load(); m != nil {
			out.DirectGeneration = int64(m.Generation)
			_, out.DirectRecordPresent = m.Entries["alpha"]
		}
		out.Highlevel = classifyManifestErr(RemoveManifestEntry(root, "alpha", identity))
		after = load()
		if m := after; m != nil {
			out.RemoveGeneration = int64(m.Generation)
			_, out.RemoveRecordPresent = m.Entries["alpha"]
		}
	case "MANIFEST-MALFORMED-001":
		mustWriteSequenceFile(t, filepath.Join(root, manifestFileName), []byte("malformed manifest bytes"))
		out.Direct = classifyManifestErr(UpdateManifestEntry(root, "alpha", []byte("ciphertext"), identity))
		out.DirectMalformedPreserved = bytes.Equal(mustReadSequenceFile(t, filepath.Join(root, manifestFileName)), []byte("malformed manifest bytes"))
		out.Highlevel = classifyManifestErr(WriteEntry(root, "alpha", entry, identity))
		out.HighlevelMalformedPreserved = bytes.Equal(mustReadSequenceFile(t, filepath.Join(root, manifestFileName)), []byte("malformed manifest bytes"))
	case "MANIFEST-MALFORMED-002":
		if err := WriteEntry(root, "alpha", entry, identity); err != nil {
			t.Fatal(err)
		}
		mustWriteSequenceFile(t, filepath.Join(root, manifestFileName), []byte("malformed manifest bytes"))
		out.Direct = classifyManifestErr(RemoveManifestEntry(root, "alpha", identity))
		out.DirectMalformedPreserved = bytes.Equal(mustReadSequenceFile(t, filepath.Join(root, manifestFileName)), []byte("malformed manifest bytes"))
		out.Highlevel = classifyManifestErr(DeleteEntry(root, "alpha", identity))
		out.HighlevelMalformedPreserved = bytes.Equal(mustReadSequenceFile(t, filepath.Join(root, manifestFileName)), []byte("malformed manifest bytes"))
	}
	if before != nil && after != nil {
		out.CreatedPreserved = before.Created.Equal(after.Created)
	}
	populateManifestOutcome(t, &out, root, identity)
	return out
}

func seedManifestSequenceBoundary(t *testing.T, root string, identity *age.X25519Identity, nonzeroCreated bool) {
	t.Helper()
	created := time.Time{}
	if nonzeroCreated {
		created = time.Date(2026, 9, 8, 10, 11, 12, 0, time.UTC)
	}
	plain, err := json.Marshal(&Manifest{Version: 1, Generation: int(^uint32(0) >> 1), Created: created, Updated: time.Time{}, Entries: map[string]ManifestEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	v := &Vault{Dir: root, Identity: identity}
	recipients, err := v.GetAllRecipientsForEncryption()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := vaultcrypto.EncryptWithRecipients(plain, recipients...)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteSequenceFile(t, filepath.Join(root, manifestFileName), ciphertext)
}

func seedManifestSequenceI64Max(t *testing.T, root string, identity *age.X25519Identity) {
	t.Helper()
	plain, err := json.Marshal(&Manifest{Version: 1, Generation: int(^uint64(0) >> 1), Created: time.Time{}, Updated: time.Time{}, Entries: map[string]ManifestEntry{}})
	if err != nil {
		t.Fatal(err)
	}
	v := &Vault{Dir: root, Identity: identity}
	recipients, err := v.GetAllRecipientsForEncryption()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := vaultcrypto.EncryptWithRecipients(plain, recipients...)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteSequenceFile(t, filepath.Join(root, manifestFileName), ciphertext)
}

func populateManifestOutcome(t *testing.T, out *manifestSequenceOutcome, root string, identity *age.X25519Identity) {
	t.Helper()
	_, err := os.Stat(filepath.Join(root, manifestFileName))
	if err == nil {
		out.ManifestExists = true
	}
	if m, e := LoadManifest(root, identity); e == nil {
		out.Generation = int64(m.Generation)
		_, out.AlphaRecordPresent = m.Entries["alpha"]
		out.CreatedNonzero = !m.Created.IsZero()
		out.UpdatedNonzero = !m.Updated.IsZero() && m.Updated.Location() == time.UTC
		out.EntryMTimeNonzero = true
		for _, record := range m.Entries {
			if record.MTime.IsZero() || record.MTime.Location() != time.UTC {
				out.EntryMTimeNonzero = false
			}
		}
	}
	out.EntryExists = fileExists(entryStoragePathForTest(t, root, "alpha", identity))
}

func runManifestSequenceRust(t *testing.T, binary, id, root string, identity *age.X25519Identity, pseudonymize bool) manifestSequenceOutcome {
	t.Helper()
	req, err := json.Marshal(map[string]any{"case_id": id, "root": root, "identity": identity.String(), "now": "2026-09-08T10:11:12Z", "pseudonymize": pseudonymize})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary)
	cmd.Dir = root
	cmd.Stdin = bytes.NewReader(req)
	cmd.WaitDelay = time.Second
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Rust %s: %v: %s", id, err, raw)
	}
	var out manifestSequenceOutcome
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("decode Rust %s: %v (%s)", id, err, raw)
	}
	return out
}

func assertManifestCiphertext(t *testing.T, root string, identity *age.X25519Identity, id string) {
	t.Helper()
	m, err := LoadManifest(root, identity)
	if err != nil {
		return
	}
	for logical, record := range m.Entries {
		path := entryStoragePathForTest(t, root, logical, identity)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if record.SHA256 != fmt.Sprintf("%x", sum) || record.Size != int64(len(data)) {
			t.Fatalf("%s manifest record %s integrity mismatch", id, logical)
		}
	}
}
func entryStoragePathForTest(t *testing.T, root, path string, id *age.X25519Identity) string {
	cfg, err := loadVaultConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	return entryStoragePath(root, path, id, cfg)
}
func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

func TestManifestSequenceJSONTransportControls(t *testing.T) {
	for _, want := range []bool{false, true} {
		payload, err := json.Marshal(map[string]any{"pseudonymize": want, "generation": int64(2147483647)})
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Pseudonymize bool        `json:"pseudonymize"`
			Generation   json.Number `json:"generation"`
		}
		dec := json.NewDecoder(bytes.NewReader(payload))
		dec.UseNumber()
		if err := dec.Decode(&decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Pseudonymize != want || decoded.Generation.String() != "2147483647" {
			t.Fatalf("transport control lost exact values: %s", payload)
		}
	}
	zero := `{"created":"0001-01-01T00:00:00Z","generation":2147483647}`
	var control struct {
		Created    string      `json:"created"`
		Generation json.Number `json:"generation"`
	}
	dec := json.NewDecoder(bytes.NewBufferString(zero))
	dec.UseNumber()
	if err := dec.Decode(&control); err != nil {
		t.Fatal(err)
	}
	if control.Created != "0001-01-01T00:00:00Z" || control.Generation.String() != "2147483647" {
		t.Fatalf("zero-created/max-generation control drifted: %+v", control)
	}
	left, right := json.Number("2147483648"), json.Number("2147483649")
	if left == right || left.String() == right.String() {
		t.Fatal("adjacent large-integer comparator control collapsed distinct values")
	}
}
