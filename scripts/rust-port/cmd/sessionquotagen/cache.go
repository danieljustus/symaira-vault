package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danieljustus/symaira-vault/internal/session"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
)

// This file freezes the SESSION-001 cache lifecycle (idle/maximum TTL,
// touching versus non-refreshing probes, revoke, corrupted records, keyring
// failure and concurrent access) from the production session.Manager.
//
// Only transport and serialized clock inputs are controlled. The Go oracle
// uses time.Now, so the fixture never stores absolute instants: stored
// timestamps are rewritten as "N nanoseconds ago" and every threshold is
// exercised far from its boundary. Exact boundary arithmetic is pinned by the
// Rust unit tests and by the package-internal Go port-contract tests.
//
// The session cache has no on-disk representation. The oracle sources import
// neither "os" nor any file API for it, and the generator proves that again by
// running every scenario with HOME/TMPDIR pointing at an empty scratch root.
// File modes therefore belong to QUOTA-002 (.quotas.json), not to this row.

const (
	cacheVault    = "fixture-vault"
	cacheVaultKey = "symvault:" + cacheVault + "|"
)

// fixedWrapKey is a known 32-byte AES-256 wrap key used to seal deterministic
// vectors, so the fixture can prove Rust opens bytes that Go's Manager opens.
var fixedWrapKey = func() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}()

var errCacheFault = errors.New("fixture keyring fault")

type cacheFault struct {
	Get      bool
	Set      bool
	Delete   bool
	Accounts []string
}

func (f cacheFault) hits(key string) bool {
	if len(f.Accounts) == 0 {
		return true
	}
	for _, account := range f.Accounts {
		if strings.HasSuffix(key, "|"+account) {
			return true
		}
	}
	return false
}

// cacheKeyring is a mutex-protected transport double with fault injection. All
// session decisions, encryption and expiry stay in internal/session.
type cacheKeyring struct {
	mu     sync.Mutex
	values map[string]string
	fault  cacheFault
}

func newCacheKeyring() *cacheKeyring { return &cacheKeyring{values: map[string]string{}} }

func (k *cacheKeyring) Get(key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fault.Get && k.fault.hits(key) {
		return "", errCacheFault
	}
	value, ok := k.values[key]
	if !ok {
		return "", session.ErrKeyringNotFound
	}
	return value, nil
}

func (k *cacheKeyring) Set(key, value string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fault.Set && k.fault.hits(key) {
		return errCacheFault
	}
	k.values[key] = value
	return nil
}

func (k *cacheKeyring) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fault.Delete && k.fault.hits(key) {
		return errCacheFault
	}
	delete(k.values, key)
	return nil
}

func (k *cacheKeyring) setFault(f cacheFault) {
	k.mu.Lock()
	k.fault = f
	k.mu.Unlock()
}

func (k *cacheKeyring) raw(account string) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.values[cacheVaultKey+account]
	return value, ok
}

func (k *cacheKeyring) putRaw(account, value string) {
	k.mu.Lock()
	k.values[cacheVaultKey+account] = value
	k.mu.Unlock()
}

func (k *cacheKeyring) dropRaw(account string) {
	k.mu.Lock()
	delete(k.values, cacheVaultKey+account)
	k.mu.Unlock()
}

type cacheStep struct {
	Op              string                     `json:"op"`
	Secret          string                     `json:"secret,omitempty"`
	TTLNS           *int64                     `json:"ttl_ns,omitempty"`
	MaxLifetimeNS   *int64                     `json:"max_lifetime_ns,omitempty"`
	Account         string                     `json:"account,omitempty"`
	SavedAgoNS      *int64                     `json:"saved_ago_ns,omitempty"`
	LastAccessAgoNS *int64                     `json:"last_access_ago_ns,omitempty"`
	Set             map[string]json.RawMessage `json:"set,omitempty"`
	Remove          []string                   `json:"remove,omitempty"`
	Value           *string                    `json:"value,omitempty"`
	FaultGet        bool                       `json:"fault_get,omitempty"`
	FaultSet        bool                       `json:"fault_set,omitempty"`
	FaultDelete     bool                       `json:"fault_delete,omitempty"`
	FaultAccounts   []string                   `json:"fault_accounts,omitempty"`
	Expect          cacheExpect                `json:"expect"`
}

type cacheShape struct {
	SessionFields     []string `json:"session_fields"`
	IdentityFields    []string `json:"identity_fields"`
	WrapKeyEncoding   string   `json:"wrap_key_encoding"`
	NonceBytes        int      `json:"nonce_bytes"`
	TimestampsUTCZ    bool     `json:"timestamps_utc_z"`
	TTLNS             int64    `json:"ttl_ns"`
	MaxLifetimeNS     int64    `json:"max_lifetime_ns"`
	SessionSavedAtEq  bool     `json:"identity_inherits_session_saved_at"`
	CiphertextAddsTag bool     `json:"ciphertext_adds_16_byte_tag"`
}

type cacheExpect struct {
	Result         string      `json:"result,omitempty"`
	Value          string      `json:"value,omitempty"`
	Flag           *bool       `json:"flag,omitempty"`
	Present        []string    `json:"present"`
	Changed        []string    `json:"changed"`
	FallbackActive *bool       `json:"fallback_active,omitempty"`
	Shape          *cacheShape `json:"shape,omitempty"`
}

type cacheScenario struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Backend     string      `json:"backend"`
	Steps       []cacheStep `json:"steps"`
}

type concurrencyCase struct {
	Name          string              `json:"name"`
	Description   string              `json:"description"`
	Workers       int                 `json:"workers"`
	Iterations    int                 `json:"iterations"`
	Workload      []string            `json:"workload"`
	Permitted     map[string][]string `json:"permitted_results"`
	ProbeExpected map[string]bool     `json:"probe_expected,omitempty"`
	Revokers      int                 `json:"revokers,omitempty"`
	FinalPresent  []string            `json:"final_present"`
	FinalResult   []string            `json:"final_load_results"`
	FinalRecover  string              `json:"after_sequential_save,omitempty"`
}

type storageContract struct {
	Backend           string   `json:"backend"`
	FilesystemImports []string `json:"filesystem_imports"`
	OnDiskFiles       int      `json:"on_disk_files"`
}

type cacheFixture struct {
	Scenarios   []cacheScenario   `json:"scenarios"`
	Concurrency []concurrencyCase `json:"concurrency"`
	Storage     storageContract   `json:"storage"`
}

func i64(v int64) *int64 { return &v }
func str(v string) *string {
	return &v
}

const (
	nsMinute = int64(time.Minute)
	nsHour   = int64(time.Hour)
)

func save(ttl, max int64) cacheStep {
	return cacheStep{Op: "save_passphrase", Secret: "s3cret", TTLNS: i64(ttl), MaxLifetimeNS: i64(max)}
}
func saveIdentity(secret string, max int64) cacheStep {
	return cacheStep{Op: "save_identity", Secret: secret, TTLNS: i64(nsHour), MaxLifetimeNS: i64(max)}
}
func op(name string) cacheStep { return cacheStep{Op: name} }
func age(account string, savedAgo, lastAgo int64) cacheStep {
	step := cacheStep{Op: "edit", Account: account, LastAccessAgoNS: i64(lastAgo)}
	if savedAgo >= 0 {
		step.SavedAgoNS = i64(savedAgo)
	}
	return step
}
func edit(account string, set map[string]any, remove ...string) cacheStep {
	step := cacheStep{Op: "edit", Account: account, Remove: remove, Set: map[string]json.RawMessage{}}
	for key, value := range set {
		data, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}
		step.Set[key] = data
	}
	return step
}
func rawSet(account, value string) cacheStep {
	return cacheStep{Op: "raw_set", Account: account, Value: str(value)}
}
func rawDelete(account string) cacheStep { return cacheStep{Op: "raw_delete", Account: account} }
func fault(get, set, del bool, accounts ...string) cacheStep {
	return cacheStep{Op: "set_fault", FaultGet: get, FaultSet: set, FaultDelete: del, FaultAccounts: accounts}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// sealedSession builds a session record the production manager must open. The
// nonce is fixed so the fixture bytes are stable; the cipher is the documented
// AES-256-GCM/no-AAD/standard-base64 layout.
func sealedSession(secret string, extra map[string]any) string {
	ciphertext, nonce := sealWithFixedKey([]byte(secret))
	record := map[string]any{
		"saved_at":             "2000-01-01T00:00:00Z",
		"last_access":          "2000-01-01T00:00:00Z",
		"encrypted_passphrase": ciphertext,
		"nonce":                nonce,
		"ttl_ns":               int64(time.Hour),
		"max_lifetime_ns":      int64(8 * time.Hour),
	}
	for key, value := range extra {
		record[key] = value
	}
	data, err := json.Marshal(record)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func cacheScenarios() []cacheScenario {
	short := int64(time.Hour)
	long := int64(8 * time.Hour)
	var scenarios []cacheScenario
	add := func(name, description string, steps ...cacheStep) {
		scenarios = append(scenarios, cacheScenario{Name: name, Description: description, Backend: "memory", Steps: steps})
	}
	addFallback := func(name, description string, steps ...cacheStep) {
		scenarios = append(scenarios, cacheScenario{Name: name, Description: description, Backend: "fallback", Steps: steps})
	}

	add("idle_ttl_touch_then_evict",
		"a load inside the idle TTL touches the session; a load past it reports expired and evicts session, identity and wrap key",
		save(short, long), saveIdentity("id-1", long),
		age("session", 3*nsMinute, 30*nsMinute),
		op("load_passphrase"),
		age("session", 3*nsMinute, 2*nsHour),
		op("is_session_expired"),
		op("load_passphrase"),
		op("load_passphrase"),
		op("is_session_expired"),
	)
	add("nonpositive_ttl_is_expired_without_eviction",
		"zero, negative and absent ttl_ns report expired but leave the cache entry in place",
		save(short, long),
		edit("session", map[string]any{"ttl_ns": 0}),
		op("load_passphrase"), op("is_session_expired"),
		edit("session", map[string]any{"ttl_ns": -1}),
		op("load_passphrase"), op("is_session_expired"),
		edit("session", nil, "ttl_ns"),
		op("load_passphrase"), op("is_session_expired"),
	)
	add("maximum_lifetime_is_absolute",
		"activity refreshes last_access but never saved_at: an old saved_at expires a recently used session; a missing maximum falls back to eight hours",
		save(24*nsHour, nsHour),
		age("session", 30*nsMinute, 1*nsMinute),
		op("load_passphrase"),
		age("session", 2*nsHour, 0),
		op("is_session_expired"),
		op("load_passphrase"),
		save(24*nsHour, 0),
		age("session", 9*nsHour, 1*nsMinute),
		op("is_session_expired"),
		op("load_passphrase"),
		save(24*nsHour, 0),
		age("session", 7*nsHour, 1*nsMinute),
		op("load_passphrase"),
	)
	add("probes_do_not_refresh_or_evict",
		"is_*_expired and PeekIdentity never rewrite or delete cache entries, expired or not; LoadIdentity on an expired cache evicts",
		save(short, long), saveIdentity("id-1", long),
		age("session", 3*nsMinute, 30*nsMinute), age("identity", 3*nsMinute, 30*nsMinute),
		op("is_session_expired"), op("is_identity_expired"), op("peek_identity"),
		age("session", 3*nsMinute, 2*nsHour), age("identity", 3*nsMinute, 2*nsHour),
		op("is_session_expired"), op("is_identity_expired"), op("peek_identity"),
		op("load_identity"),
		op("is_identity_expired"),
	)
	add("touch_scope_passphrase_vs_identity",
		"LoadPassphrase touches only the session record; LoadIdentity touches the identity and the shared session",
		save(short, long), saveIdentity("id-1", long),
		age("session", 3*nsMinute, 30*nsMinute), age("identity", 3*nsMinute, 30*nsMinute),
		op("load_passphrase"),
		age("session", 3*nsMinute, 30*nsMinute),
		op("load_identity"),
		op("peek_identity"),
	)
	add("identity_expiry_follows_session_metadata",
		"identity expiry is judged by the shared session when present and by the identity's own metadata otherwise; a non-positive TTL expires without evicting",
		save(short, long), saveIdentity("id-1", long),
		age("identity", 3*nsMinute, 2*nsHour),
		op("is_identity_expired"), op("peek_identity"),
		age("session", 3*nsMinute, 2*nsHour),
		op("is_identity_expired"), op("peek_identity"),
		rawDelete("session"),
		op("is_identity_expired"), op("load_identity"),
		op("is_identity_expired"),
		save(short, long), saveIdentity("id-1", long),
		edit("identity", map[string]any{"ttl_ns": 0}),
		edit("session", map[string]any{"ttl_ns": 0}),
		op("load_identity"), op("peek_identity"), op("is_identity_expired"),
	)
	add("revoke_and_clear",
		"ClearSession deletes session, identity and wrap key and is idempotent; ClearIdentity removes only the identity",
		save(short, long), saveIdentity("id-1", long),
		op("clear_identity"), op("clear_identity"),
		age("session", 3*nsMinute, 30*nsMinute),
		op("load_passphrase"),
		saveIdentity("id-2", long),
		op("clear_session"),
		op("load_passphrase"), op("peek_identity"),
		op("clear_session"),
	)
	add("revoke_with_delete_failures",
		"a failing session delete aborts ClearSession before the other entries are touched; failing wrap-key or identity deletes are swallowed",
		save(short, long), saveIdentity("id-1", long),
		fault(false, false, true, "session"),
		op("clear_session"),
		fault(false, false, true, "wrap-key"),
		op("clear_session"),
		fault(false, false, false),
		op("clear_session"),
		save(short, long), saveIdentity("id-1", long),
		fault(false, false, true, "identity"),
		op("clear_session"),
		fault(false, false, false),
		op("clear_session"),
	)
	add("corrupted_session_record",
		"undecodable JSON, an invalid timestamp, a wrong field type and a zero TTL after a bad timestamp all fail as malformed without evicting",
		save(short, long),
		rawSet("session", "not-json"),
		op("load_passphrase"), op("is_session_expired"), op("has_legacy_plaintext"),
		rawSet("session", `{"saved_at":"nope","last_access":"nope","ttl_ns":3600000000000}`),
		op("load_passphrase"), op("is_session_expired"),
		rawSet("session", `{"saved_at":"2099-01-01T00:00:00Z","last_access":"2099-01-01T00:00:00Z","ttl_ns":0,"nonce":5}`),
		op("load_passphrase"),
		rawSet("session", `{"saved_at":"bad","last_access":"2099-01-01T00:00:00Z","ttl_ns":0}`),
		op("load_passphrase"),
	)
	add("incomplete_session_record",
		"a record without saved_at is expired and evicted, null time fields are Go zero time, and a record without ciphertext or nonce is expired but kept",
		save(short, long),
		edit("session", nil, "saved_at"),
		op("is_session_expired"), op("load_passphrase"),
		save(short, long),
		edit("session", map[string]any{"saved_at": nil, "last_access": nil}),
		op("is_session_expired"), op("load_passphrase"),
		save(short, long),
		edit("session", map[string]any{"encrypted_passphrase": ""}),
		op("load_passphrase"),
		save(short, long),
		edit("session", map[string]any{"nonce": ""}),
		op("load_passphrase"),
		save(short, long),
		edit("session", nil, "encrypted_passphrase", "nonce"),
		op("load_passphrase"),
	)
	add("last_access_defaults_to_saved_at",
		"a missing or null last_access falls back to saved_at before the idle check",
		save(short, long),
		age("session", 2*nsHour, 0),
		edit("session", nil, "last_access"),
		op("is_session_expired"), op("load_passphrase"),
		save(short, long),
		age("session", 1*nsMinute, 0),
		edit("session", map[string]any{"last_access": nil}),
		op("is_session_expired"), op("load_passphrase"),
	)
	add("tampered_and_misaddressed_ciphertext",
		"bad ciphertext, an undecodable ciphertext, or a different wrap key fail as decrypt errors and keep the entry",
		save(short, long),
		edit("session", map[string]any{"encrypted_passphrase": b64(bytes.Repeat([]byte{0x41}, 32))}),
		op("load_passphrase"),
		edit("session", map[string]any{"encrypted_passphrase": "***not-base64***"}),
		op("load_passphrase"),
		save(short, long),
		rawSet("wrap-key", b64(bytes.Repeat([]byte{0x07}, 32))),
		op("load_passphrase"),
	)
	add("wrap_key_states",
		"a missing, non-base64 or wrong-length wrap key fails the load; saving replaces any unusable wrap key",
		save(short, long), saveIdentity("id-1", long),
		rawDelete("wrap-key"),
		op("load_passphrase"), op("load_identity"),
		rawSet("wrap-key", "***"),
		op("load_passphrase"),
		rawSet("wrap-key", b64(bytes.Repeat([]byte{0x01}, 16))),
		op("load_passphrase"),
		save(short, long),
		age("session", 3*nsMinute, 30*nsMinute),
		op("load_passphrase"),
		rawSet("wrap-key", b64(bytes.Repeat([]byte{0x01}, 16))),
		saveIdentity("id-1", long),
		age("identity", 3*nsMinute, 30*nsMinute), age("session", 3*nsMinute, 30*nsMinute),
		op("load_identity"),
	)
	add("corrupted_identity_record",
		"an undecodable identity fails as malformed everywhere, and a corrupt shared session blocks identity loads without eviction",
		save(short, long), saveIdentity("id-1", long),
		rawSet("identity", "garbage"),
		op("load_identity"), op("peek_identity"), op("is_identity_expired"),
		saveIdentity("id-1", long),
		rawSet("session", "garbage"),
		op("load_identity"), op("peek_identity"), op("is_identity_expired"),
		rawSet("session", "garbage"),
		edit("identity", map[string]any{"saved_at": "nope"}),
		op("load_identity"),
	)
	add("legacy_plaintext_lifecycle",
		"a live legacy plaintext session is refused until migrated; migration is a one-shot upgrade and a no-op without a session",
		rawSet("session", `{"saved_at":"2000-01-01T00:00:00Z","last_access":"2000-01-01T00:00:00Z","passphrase":"legacy-secret","ttl_ns":3600000000000}`),
		age("session", 1*nsMinute, 1*nsMinute),
		op("has_legacy_plaintext"), op("load_passphrase"),
		op("migrate_session"),
		op("has_legacy_plaintext"), op("load_passphrase"),
		op("migrate_session"),
		op("clear_session"),
		op("has_legacy_plaintext"), op("migrate_session"),
	)
	add("keyring_failures",
		"keyring failures surface as keyring errors, never as misses, and never delete or rewrite the cache",
		save(short, long), saveIdentity("id-1", long),
		fault(true, false, false),
		op("load_passphrase"), op("load_identity"), op("peek_identity"),
		op("is_session_expired"), op("is_identity_expired"), op("has_legacy_plaintext"), op("migrate_session"),
		fault(false, true, false),
		save(short, long), saveIdentity("id-1", long),
		age("session", 3*nsMinute, 30*nsMinute),
		op("load_passphrase"),
		fault(true, true, true),
		save(short, long),
		fault(false, false, false),
		op("load_passphrase"),
	)
	add("go_sealed_vector",
		"a record sealed with a known wrap key opens, with the passphrase round trip pinned by AES-256-GCM, standard base64, a 12-byte nonce and no AAD",
		rawSet("wrap-key", b64(fixedWrapKey)),
		rawSet("session", sealedSession("vector-secret", nil)),
		age("session", 1*nsMinute, 1*nsMinute),
		op("load_passphrase"),
		rawSet("session", sealedSession("vector-secret", map[string]any{"max_lifetime_ns": 0})),
		age("session", 1*nsMinute, 1*nsMinute),
		op("load_passphrase"),
	)
	add("record_shape",
		"the stored JSON field sets, the wrap-key encoding, the nonce length and the shared saved_at between session and identity are pinned",
		save(short, long), saveIdentity("id-1", long),
		op("inspect"),
		save(short, 0), saveIdentity("id-1", 0),
		op("inspect"),
	)
	addFallback("fallback_miss_does_not_activate",
		"a not-found from a healthy primary is an ordinary miss and does not switch to memory",
		op("load_passphrase"), op("is_session_expired"),
	)
	addFallback("fallback_activates_on_set_failure",
		"a primary Set failure is absorbed by the in-memory fallback and the session keeps working for the process",
		fault(false, true, false),
		save(short, long),
		op("load_passphrase"),
		fault(false, false, false),
		op("load_passphrase"),
		op("clear_session"),
		op("load_passphrase"),
	)
	addFallback("fallback_activates_on_get_failure",
		"a primary Get failure activates the fallback permanently: earlier primary entries stay invisible even after the primary recovers",
		save(short, long),
		age("session", 3*nsMinute, 30*nsMinute),
		op("load_passphrase"),
		fault(true, false, false),
		op("load_passphrase"),
		fault(false, false, false),
		op("load_passphrase"),
		save(short, long),
		op("load_passphrase"),
	)
	addFallback("fallback_activates_on_delete_failure",
		"a primary Delete failure is absorbed and activates the fallback",
		save(short, long),
		fault(false, false, true),
		op("clear_session"),
		op("load_passphrase"),
	)
	return scenarios
}

type scenarioRun struct {
	keyring  *cacheKeyring
	manager  *session.Manager
	fallback interface{ IsFallbackActive() bool }
}

func newScenarioRun(backend string) *scenarioRun {
	keyring := newCacheKeyring()
	run := &scenarioRun{keyring: keyring}
	if backend == "fallback" {
		wrapped := session.NewFallbackKeyring(keyring)
		active, ok := wrapped.(interface{ IsFallbackActive() bool })
		if !ok {
			panic("fallback keyring does not report activation")
		}
		run.fallback = active
		run.manager = session.NewManager(wrapped, nil)
		return run
	}
	run.manager = session.NewManager(keyring, nil)
	return run
}

var cacheAccounts = []string{"session", "identity", "wrap-key"}

func (r *scenarioRun) snapshot() map[string]string {
	result := map[string]string{}
	for _, account := range cacheAccounts {
		if value, ok := r.keyring.raw(account); ok {
			result[account] = value
		}
	}
	return result
}

func presentList(snapshot map[string]string) []string {
	list := []string{}
	for _, account := range cacheAccounts {
		value, ok := snapshot[account]
		if !ok {
			continue
		}
		name := strings.ReplaceAll(account, "-", "_")
		if account == "wrap-key" {
			if raw, err := base64.StdEncoding.DecodeString(value); err != nil || len(raw) != 32 {
				name += ":invalid"
			}
		}
		list = append(list, name)
	}
	return list
}

func changedList(before, after map[string]string) []string {
	list := []string{}
	for _, account := range cacheAccounts {
		b, bok := before[account]
		a, aok := after[account]
		if bok != aok || b != a {
			list = append(list, strings.ReplaceAll(account, "-", "_"))
		}
	}
	return list
}

func classify(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, session.ErrLegacyPlaintextSession):
		return "legacy_plaintext"
	case errors.Is(err, errCacheFault):
		return "keyring_unavailable"
	case errors.Is(err, session.ErrKeyringNotFound):
		return "not_found"
	}
	message := err.Error()
	switch {
	case strings.Contains(message, "TTL is zero or negative"):
		return "expired_zero_ttl"
	case strings.Contains(message, "no passphrase data available"):
		return "expired_no_data"
	case strings.Contains(message, "expired for vault"):
		return "expired"
	case strings.Contains(message, "wrap key not found"):
		return "wrap_key_missing"
	case strings.Contains(message, "wrap key has invalid length"), strings.Contains(message, "decode wrap key"):
		return "wrap_key_invalid"
	case strings.Contains(message, "decode session"), strings.Contains(message, "decode identity"):
		return "malformed"
	case strings.Contains(message, "decrypt"):
		return "decrypt_failed"
	}
	panic(fmt.Errorf("unclassified oracle error: %w", err))
}

var utcTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d*[1-9])?Z$`)

func (r *scenarioRun) shape() *cacheShape {
	decode := func(account string) map[string]json.RawMessage {
		raw, ok := r.keyring.raw(account)
		if !ok {
			panic("inspect: missing " + account)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			panic(err)
		}
		return fields
	}
	keys := func(fields map[string]json.RawMessage) []string {
		list := make([]string, 0, len(fields))
		for key := range fields {
			list = append(list, key)
		}
		sort.Strings(list)
		return list
	}
	sess, ident := decode("session"), decode("identity")
	wrap, _ := r.keyring.raw("wrap-key")
	encoding := "other"
	if raw, err := base64.StdEncoding.DecodeString(wrap); err == nil && len(raw) == 32 {
		encoding = "base64_std_32_bytes"
	}
	textOf := func(fields map[string]json.RawMessage, key string) string {
		var out string
		if err := json.Unmarshal(fields[key], &out); err != nil {
			panic(err)
		}
		return out
	}
	numberOf := func(fields map[string]json.RawMessage, key string) int64 {
		var out int64
		if raw, ok := fields[key]; ok {
			if err := json.Unmarshal(raw, &out); err != nil {
				panic(err)
			}
		}
		return out
	}
	nonce, err := base64.StdEncoding.DecodeString(textOf(sess, "nonce"))
	if err != nil {
		panic(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(textOf(sess, "encrypted_passphrase"))
	if err != nil {
		panic(err)
	}
	return &cacheShape{
		SessionFields:     keys(sess),
		IdentityFields:    keys(ident),
		WrapKeyEncoding:   encoding,
		NonceBytes:        len(nonce),
		TimestampsUTCZ:    utcTimestamp.MatchString(textOf(sess, "saved_at")) && utcTimestamp.MatchString(textOf(sess, "last_access")) && utcTimestamp.MatchString(textOf(ident, "saved_at")),
		TTLNS:             numberOf(sess, "ttl_ns"),
		MaxLifetimeNS:     numberOf(sess, "max_lifetime_ns"),
		SessionSavedAtEq:  textOf(sess, "saved_at") == textOf(ident, "saved_at"),
		CiphertextAddsTag: len(ciphertext) == len("s3cret")+16,
	}
}

func (r *scenarioRun) execute(step cacheStep) (result, value string, flag *bool) {
	boolean := func(v bool, err error) (string, string, *bool) {
		if err != nil {
			return classify(err), "", nil
		}
		return "ok", "", &v
	}
	switch step.Op {
	case "save_passphrase":
		err := r.manager.SavePassphraseWithMaxLifetime(cacheVault, []byte(step.Secret), time.Duration(*step.TTLNS), time.Duration(*step.MaxLifetimeNS))
		return classify(err), "", nil
	case "save_identity":
		err := r.manager.SaveIdentityWithMaxLifetime(cacheVault, step.Secret, time.Duration(*step.TTLNS), time.Duration(*step.MaxLifetimeNS))
		return classify(err), "", nil
	case "load_passphrase":
		got, err := r.manager.LoadPassphrase(cacheVault)
		if err != nil {
			return classify(err), "", nil
		}
		return "ok", string(got), nil
	case "load_identity":
		got, err := r.manager.LoadIdentity(cacheVault)
		if err != nil {
			return classify(err), "", nil
		}
		return "ok", got, nil
	case "peek_identity":
		got, err := r.manager.PeekIdentity(cacheVault)
		if err != nil {
			return classify(err), "", nil
		}
		return "ok", got, nil
	case "is_session_expired":
		v := r.manager.IsSessionExpired(cacheVault)
		return "ok", "", &v
	case "is_identity_expired":
		v := r.manager.IsIdentityExpired(cacheVault)
		return "ok", "", &v
	case "clear_session":
		return classify(r.manager.ClearSession(cacheVault)), "", nil
	case "clear_identity":
		return classify(r.manager.ClearIdentity(cacheVault)), "", nil
	case "has_legacy_plaintext":
		return boolean(r.manager.HasLegacyPlaintextSession(cacheVault))
	case "migrate_session":
		return boolean(r.manager.MigrateSession(cacheVault))
	case "edit":
		r.edit(step)
		return "", "", nil
	case "raw_set":
		r.keyring.putRaw(step.Account, *step.Value)
		return "", "", nil
	case "raw_delete":
		r.keyring.dropRaw(step.Account)
		return "", "", nil
	case "set_fault":
		r.keyring.setFault(cacheFault{Get: step.FaultGet, Set: step.FaultSet, Delete: step.FaultDelete, Accounts: step.FaultAccounts})
		return "", "", nil
	case "inspect":
		return "", "", nil
	}
	panic("unknown cache op " + step.Op)
}

func (r *scenarioRun) edit(step cacheStep) {
	raw, ok := r.keyring.raw(step.Account)
	if !ok {
		panic("edit: missing " + step.Account)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	stamp := func(ago int64) json.RawMessage {
		data, err := json.Marshal(now.Add(-time.Duration(ago)).Format(time.RFC3339Nano))
		if err != nil {
			panic(err)
		}
		return data
	}
	if step.SavedAgoNS != nil {
		fields["saved_at"] = stamp(*step.SavedAgoNS)
	}
	if step.LastAccessAgoNS != nil {
		fields["last_access"] = stamp(*step.LastAccessAgoNS)
	}
	for key, value := range step.Set {
		fields[key] = value
	}
	for _, key := range step.Remove {
		delete(fields, key)
	}
	data, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	r.keyring.putRaw(step.Account, string(data))
}

func runScenario(sc cacheScenario) cacheScenario {
	run := newScenarioRun(sc.Backend)
	out := sc
	out.Steps = make([]cacheStep, len(sc.Steps))
	for i, step := range sc.Steps {
		before := run.snapshot()
		result, value, flag := run.execute(step)
		after := run.snapshot()
		step.Expect = cacheExpect{Result: result, Value: value, Flag: flag, Present: presentList(after), Changed: changedList(before, after)}
		if run.fallback != nil {
			active := run.fallback.IsFallbackActive()
			step.Expect.FallbackActive = &active
		}
		if step.Op == "inspect" {
			step.Expect.Shape = run.shape()
		}
		switch step.Op {
		case "edit", "raw_set", "raw_delete", "set_fault":
			// Scenario plumbing, not an observation.
			step.Expect = cacheExpect{Present: []string{}, Changed: []string{}}
		}
		out.Steps[i] = step
	}
	return out
}

func sealWithFixedKey(plaintext []byte) (ciphertext, nonce string) {
	return sealGCM(fixedWrapKey, bytes.Repeat([]byte{0x09}, 12), plaintext)
}

// buildCacheFixture runs every scenario twice and refuses to freeze a result
// that depends on timing or map order.
func buildCacheFixture(root string) (cacheFixture, error) {
	scratch, err := os.MkdirTemp("", "symvault-session-cache-")
	if err != nil {
		return cacheFixture{}, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	restore := scopeEnvironment(scratch)
	defer restore()
	// The fallback keyring prints a one-time stderr warning when it activates.
	// Its wording belongs to the CLI layer, not to this fixture.
	cliout.SetQuiet(true)
	defer cliout.SetQuiet(false)

	fx := cacheFixture{}
	for _, sc := range cacheScenarios() {
		first, second := runScenario(sc), runScenario(sc)
		a, marshalErr := json.Marshal(first)
		if marshalErr != nil {
			return cacheFixture{}, marshalErr
		}
		b, marshalErr := json.Marshal(second)
		if marshalErr != nil {
			return cacheFixture{}, marshalErr
		}
		if !bytes.Equal(a, b) {
			return cacheFixture{}, fmt.Errorf("scenario %s is not deterministic", sc.Name)
		}
		fx.Scenarios = append(fx.Scenarios, first)
	}
	for _, c := range concurrencyCases() {
		observed, runErr := runConcurrency(c)
		if runErr != nil {
			return cacheFixture{}, runErr
		}
		fx.Concurrency = append(fx.Concurrency, observed)
	}
	imports, err := filesystemImports(root)
	if err != nil {
		return cacheFixture{}, err
	}
	files := 0
	if err := filepath.WalkDir(scratch, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path != scratch {
			files++
		}
		return nil
	}); err != nil {
		return cacheFixture{}, err
	}
	if files != 0 {
		return cacheFixture{}, fmt.Errorf("session cache wrote %d filesystem entries; the contract says it is keyring-only", files)
	}
	fx.Storage = storageContract{Backend: "keyring", FilesystemImports: imports, OnDiskFiles: files}
	return fx, nil
}

func scopeEnvironment(scratch string) func() {
	names := []string{"HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"}
	previous := map[string]*string{}
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok {
			value := value
			previous[name] = &value
		} else {
			previous[name] = nil
		}
		if name == "TMPDIR" || name == "TEMP" || name == "TMP" || name == "HOME" || name == "USERPROFILE" || strings.HasPrefix(name, "XDG_") {
			if err := os.Setenv(name, scratch); err != nil {
				panic(err)
			}
		}
	}
	return func() {
		for name, value := range previous {
			if value == nil {
				_ = os.Unsetenv(name)
			} else {
				_ = os.Setenv(name, *value)
			}
		}
	}
}

// filesystemImports lists file-system packages imported by the pinned session
// cache sources. An empty list is the static half of "keyring-only".
func filesystemImports(root string) ([]string, error) {
	found := map[string]bool{}
	repository, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() { _ = repository.Close() }()
	for _, name := range []string{"internal/session/session.go", "internal/session/keyring.go", "internal/session/memory_keyring.go"} {
		source, err := repository.ReadFile(filepath.FromSlash(name))
		if err != nil {
			return nil, err
		}
		for _, banned := range []string{"os", "io/ioutil", "os/exec", "io/fs"} {
			if bytes.Contains(source, []byte("\n\t\""+banned+"\"\n")) {
				found[banned] = true
			}
		}
	}
	list := make([]string, 0, len(found))
	for name := range found {
		list = append(list, name)
	}
	sort.Strings(list)
	return list, nil
}

func concurrencyCases() []concurrencyCase {
	return []concurrencyCase{
		{
			Name:        "concurrent_touch_and_probe_keep_live_session",
			Description: "parallel loads, touches and non-refreshing probes never evict, corrupt or fail a live session",
			Workers:     8, Iterations: 25,
			Workload:      []string{"load_passphrase", "load_identity", "peek_identity", "is_session_expired", "is_identity_expired"},
			Permitted:     map[string][]string{"load_passphrase": {"ok"}, "load_identity": {"ok"}, "peek_identity": {"ok"}},
			ProbeExpected: map[string]bool{"is_session_expired": false, "is_identity_expired": false},
			FinalPresent:  []string{"session", "identity", "wrap_key"},
			FinalResult:   []string{"ok"},
		},
		{
			Name:        "concurrent_revoke_during_loads",
			Description: "revoke racing loaders yields only a hit, a miss or a missing wrap key, never a panic or a torn record; a final revoke always leaves nothing",
			Workers:     6, Iterations: 20, Revokers: 2,
			Workload:     []string{"load_passphrase", "load_identity"},
			Permitted:    map[string][]string{"load_passphrase": {"ok", "not_found", "wrap_key_missing"}, "load_identity": {"ok", "not_found", "wrap_key_missing"}},
			FinalPresent: []string{},
			FinalResult:  []string{"not_found"},
		},
		{
			Name:        "concurrent_saves_recover_by_sequential_save",
			Description: "racing first saves may leave a session sealed under a different wrap key (decrypt error); one sequential save always recovers it",
			Workers:     8, Iterations: 5,
			Workload:     []string{"save_passphrase"},
			Permitted:    map[string][]string{"save_passphrase": {"ok"}},
			FinalPresent: []string{"session", "wrap_key"},
			FinalResult:  []string{"ok", "decrypt_failed"},
			FinalRecover: "ok",
		},
	}
}

func seedConcurrency(run *scenarioRun, c concurrencyCase) {
	if c.Workload[0] == "save_passphrase" {
		return
	}
	if result, _, _ := run.execute(save(int64(time.Hour), int64(8*time.Hour))); result != "ok" {
		panic("seed save: " + result)
	}
	if result, _, _ := run.execute(saveIdentity("id-1", int64(8*time.Hour))); result != "ok" {
		panic("seed identity: " + result)
	}
}

func runConcurrency(c concurrencyCase) (concurrencyCase, error) {
	run := newScenarioRun("memory")
	seedConcurrency(run, c)
	permitted := map[string]map[string]bool{}
	for name, list := range c.Permitted {
		permitted[name] = map[string]bool{}
		for _, item := range list {
			permitted[name][item] = true
		}
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failures []string
	)
	record := func(format string, args ...any) {
		mu.Lock()
		failures = append(failures, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	for worker := 0; worker < c.Workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			defer func() {
				if recovered := recover(); recovered != nil {
					record("worker %d panicked: %v", worker, recovered)
				}
			}()
			for i := 0; i < c.Iterations; i++ {
				for _, name := range c.Workload {
					step := cacheStep{Op: name, Secret: "s3cret", TTLNS: i64(int64(time.Hour)), MaxLifetimeNS: i64(int64(8 * time.Hour))}
					result, _, flag := run.execute(step)
					if want, probe := c.ProbeExpected[name]; probe {
						if flag == nil || *flag != want {
							record("%s returned %v, want %v", name, flag, want)
						}
						continue
					}
					if !permitted[name][result] {
						record("%s returned %s outside %v", name, result, c.Permitted[name])
					}
				}
			}
		}(worker)
	}
	for revoker := 0; revoker < c.Revokers; revoker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < c.Iterations; i++ {
				if result, _, _ := run.execute(op("clear_session")); result != "ok" {
					record("clear_session returned %s", result)
				}
			}
		}()
	}
	wg.Wait()
	if len(failures) > 0 {
		return c, fmt.Errorf("%s: %s", c.Name, strings.Join(failures, "; "))
	}
	for _, account := range []string{"session", "identity"} {
		if raw, ok := run.keyring.raw(account); ok {
			var decoded map[string]json.RawMessage
			if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
				return c, fmt.Errorf("%s: torn %s record: %w", c.Name, account, err)
			}
		}
	}
	if c.Revokers > 0 {
		if result, _, _ := run.execute(op("clear_session")); result != "ok" {
			return c, fmt.Errorf("%s: final clear_session %s", c.Name, result)
		}
	}
	present := presentList(run.snapshot())
	want := append([]string{}, c.FinalPresent...)
	for i := range want {
		want[i] = strings.ReplaceAll(want[i], "-", "_")
	}
	if !reflect.DeepEqual(present, orderedAccounts(want)) {
		return c, fmt.Errorf("%s: final entries %v, want %v", c.Name, present, want)
	}
	result, _, _ := run.execute(op("load_passphrase"))
	allowedFinal := false
	for _, allowed := range c.FinalResult {
		allowedFinal = allowedFinal || result == allowed
	}
	if !allowedFinal {
		return c, fmt.Errorf("%s: final load %s outside %v", c.Name, result, c.FinalResult)
	}
	if c.FinalRecover == "" {
		return c, nil
	}
	if result, _, _ := run.execute(save(int64(time.Hour), int64(8*time.Hour))); result != "ok" {
		return c, fmt.Errorf("%s: recovery save %s", c.Name, result)
	}
	if result, value, _ := run.execute(op("load_passphrase")); result != c.FinalRecover || value != "s3cret" {
		return c, fmt.Errorf("%s: recovery load %s %q", c.Name, result, value)
	}
	return c, nil
}

func orderedAccounts(names []string) []string {
	list := []string{}
	for _, account := range cacheAccounts {
		name := strings.ReplaceAll(account, "-", "_")
		for _, want := range names {
			if want == name {
				list = append(list, name)
			}
		}
	}
	return list
}

// sealGCM reproduces the documented session cipher layout with a caller-owned
// nonce so test vectors are stable. The production manager still performs the
// decryption the fixture observes.
func sealGCM(key, nonce, plaintext []byte) (ciphertext, encodedNonce string) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil) // #nosec G407 -- fixed nonce is deliberate for a frozen test vector
	return b64(sealed), b64(nonce)
}
