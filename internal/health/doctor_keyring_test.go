package health

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBlobAttr(t *testing.T) {
	tests := []struct {
		line    string
		wantKey string
		wantVal string
	}{
		{line: `    "svce"<blob>="symaira"`, wantKey: "svce", wantVal: "symaira"},
		{line: `    "acct"<blob>="audit-hmac-key:/tmp/x"`, wantKey: "acct", wantVal: "audit-hmac-key:/tmp/x"},
		{line: `    0x00000007 <blob>="symaira"`, wantKey: "0x00000007", wantVal: "symaira"},
		{line: `    0x00000008 <blob>="audit-hmac-key:/tmp/x"`, wantKey: "0x00000008", wantVal: "audit-hmac-key:/tmp/x"},
		{line: `    "data"<blob>=0xabc123`, wantKey: "data", wantVal: "0xabc123"},
		{line: `    class: "genp"`, wantKey: "", wantVal: ""},
		{line: `keychain: "/tmp/login.keychain-db"`, wantKey: "", wantVal: ""},
	}
	for _, tt := range tests {
		key, val := parseBlobAttr(tt.line)
		if key != tt.wantKey || val != tt.wantVal {
			t.Errorf("parseBlobAttr(%q) = (%q, %q), want (%q, %q)", tt.line, key, val, tt.wantKey, tt.wantVal)
		}
	}
}

// TestParseKeychainDump exercises the structure real `security dump-keychain`
// output has on recent macOS: each item starts with the numeric attribute
// form (kSecAttrService/kSecAttrAccount), is followed by the human-readable
// summary, and items are separated by "keychain:" header lines with no blank
// lines in between. Both the current "symaira" service and the legacy
// "openpass" service (pre-rename) must be picked up; other services and
// non-audit accounts must be ignored.
func TestParseKeychainDump(t *testing.T) {
	dump := `keychain: "/Users/dev/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="openpass"
    0x00000008 <blob>=<NULL>
    "acct"<blob>="audit-hmac-key:/tmp/dead-vault-1"
    "cdat"<timedate>=0x31  "20260101T000000Z\000"
    "svce"<blob>="openpass"
    "type"<uint32>=<NULL>
keychain: "/Users/dev/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="symaira"
    0x00000008 <blob>=<NULL>
    "acct"<blob>="audit-hmac-key:/tmp/dead-vault-2"
    "svce"<blob>="symaira"
    "type"<uint32>=<NULL>
keychain: "/Users/dev/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="symvault:/tmp/real-vault"
    0x00000008 <blob>=<NULL>
    "acct"<blob>="session"
    "svce"<blob>="symvault:/tmp/real-vault"
    "type"<uint32>=<NULL>
keychain: "/Users/dev/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="symaira"
    0x00000008 <blob>=<NULL>
    "acct"<blob>="audit-hmac-key:/tmp/live-vault"
    "svce"<blob>="symaira"
    "type"<uint32>=<NULL>
`
	entries := parseKeychainDump([]byte(dump))
	want := []keyringAccountEntry{
		{service: "openpass", account: "audit-hmac-key:/tmp/dead-vault-1"},
		{service: "symaira", account: "audit-hmac-key:/tmp/dead-vault-2"},
		{service: "symaira", account: "audit-hmac-key:/tmp/live-vault"},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %v, want %v", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entries[%d] = %+v, want %+v", i, entries[i], want[i])
		}
	}
}

// TestAuditKeyringOrphansResult_NoOrphans covers the healthy case: entries
// whose vault directory still exists are not orphans.
func TestAuditKeyringOrphansResult_NoOrphans(t *testing.T) {
	live := t.TempDir()
	r := auditKeyringOrphansResult([]keyringAccountEntry{
		{service: "symaira", account: "audit-hmac-key:" + live},
		{service: "openpass", account: "audit-hmac-key:" + live},
	})
	if r.Status != StatusOK {
		t.Fatalf("status = %s, want ok (message: %s)", r.Status, r.Message)
	}
	if r.Fixable || r.Fix != nil {
		t.Error("no orphans must not be fixable")
	}
}

// TestAuditKeyringOrphansResult_ReportsAndFixesOrphans covers the #801
// maintenance path: entries pointing at deleted vault directories are
// reported as orphans (under both the current and the legacy service name)
// and the fix closure deletes exactly those.
func TestAuditKeyringOrphansResult_ReportsAndFixesOrphans(t *testing.T) {
	live := t.TempDir()
	dead := filepath.Join(t.TempDir(), "gone") // never created

	r := auditKeyringOrphansResult([]keyringAccountEntry{
		{service: "symaira", account: "audit-hmac-key:" + live},
		{service: "symaira", account: "audit-hmac-key:" + dead},
		{service: "openpass", account: "audit-hmac-key:/tmp/also-gone"},
	})
	if r.Status != StatusWarn {
		t.Fatalf("status = %s, want warn (message: %s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "2 audit HMAC key(s)") {
		t.Errorf("message = %q, want it to count 2 orphans", r.Message)
	}
	if !r.Fixable || r.Fix == nil {
		t.Fatal("expected Fixable with a fix closure")
	}

	var deleted []keyringAccountEntry
	oldDelete := keyringEntryDelete
	keyringEntryDelete = func(service, account string) error {
		deleted = append(deleted, keyringAccountEntry{service: service, account: account})
		return nil
	}
	t.Cleanup(func() { keyringEntryDelete = oldDelete })

	if err := r.Fix(); err != nil {
		t.Fatalf("Fix() error = %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("fix deleted %d entries, want 2: %v", len(deleted), deleted)
	}
	for _, e := range deleted {
		if strings.Contains(e.account, live) {
			t.Errorf("fix deleted the live vault's entry %+v", e)
		}
	}
}

// TestAuditKeyringOrphansResult_SkipsNonSchemeAccounts ensures accounts that
// do not use the audit-hmac-key: scheme are never considered or deleted.
func TestAuditKeyringOrphansResult_SkipsNonSchemeAccounts(t *testing.T) {
	r := auditKeyringOrphansResult([]keyringAccountEntry{
		{service: "symaira", account: "grant-signing-key:/tmp/whatever"},
		{service: "symaira", account: "audit-hmac-key"},
	})
	if r.Status != StatusOK {
		t.Fatalf("status = %s, want ok (message: %s)", r.Status, r.Message)
	}
}

// TestCheckAuditKeyringOrphans_TestEnvSkipsEnumeration ensures doctor runs
// inside test binaries never enumerate (or modify) the real keychain.
func TestCheckAuditKeyringOrphans_TestEnvSkipsEnumeration(t *testing.T) {
	called := false
	old := keyringAuditKeyAccounts
	keyringAuditKeyAccounts = func() ([]keyringAccountEntry, error) {
		called = true
		return nil, nil
	}
	t.Cleanup(func() { keyringAuditKeyAccounts = old })

	r := checkAuditKeyringOrphans("", Options{})
	if called {
		t.Error("keychain enumeration was invoked from a test process")
	}
	if r.Status != StatusOK {
		t.Fatalf("status = %s, want ok (message: %s)", r.Status, r.Message)
	}
}
