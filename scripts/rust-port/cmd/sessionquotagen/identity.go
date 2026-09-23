package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/danieljustus/symaira-vault/internal/session"
)

// Observe the real manager; only storage transport and serialized clock inputs
// are controlled. No native keychain or human authentication is used here.
func identityMetadataCases() []sessionCase {
	const vault = "fixture-vault"
	const sessionKey = "symvault:fixture-vault|session"
	const identityKey = "symvault:fixture-vault|identity"
	backend := &fakeKeyring{values: map[string]string{}}
	manager := session.NewManager(backend, nil)
	if err := manager.SavePassphrase(vault, []byte("fixture-secret"), time.Hour); err != nil {
		panic(err)
	}
	if err := manager.SaveIdentity(vault, "fixture-identity", time.Hour); err != nil {
		panic(err)
	}
	decode := func(key string) map[string]json.RawMessage {
		var value map[string]json.RawMessage
		if err := json.Unmarshal([]byte(backend.values[key]), &value); err != nil {
			panic(err)
		}
		return value
	}
	store := func(key string, value map[string]json.RawMessage) {
		data, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}
		backend.values[key] = string(data)
	}
	old, err := json.Marshal(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	for _, key := range []string{sessionKey, identityKey} {
		value := decode(key)
		value["last_access"] = old
		value["ttl_ns"] = json.RawMessage("9223372036854775807")
		store(key, value)
	}
	if value, err := manager.PeekIdentity(vault); err != nil || value != "fixture-identity" {
		panic(fmt.Errorf("identity peek returned %q: %w", value, err))
	}
	if string(decode(sessionKey)["last_access"]) != string(old) || string(decode(identityKey)["last_access"]) != string(old) {
		panic("identity peek refreshed a cache record")
	}
	peek := sessionCase{Name: "identity_peek_does_not_refresh", Operations: []string{"save_passphrase", "save_identity", "age_both_last_access", "peek_identity"}, Expected: "both_unchanged"}
	if value, err := manager.LoadIdentity(vault); err != nil {
		panic(fmt.Errorf("identity refresh: %w", err))
	} else if value != "fixture-identity" {
		panic(fmt.Errorf("identity refresh returned %q, want fixture-identity", value))
	}
	sess, ident := decode(sessionKey), decode(identityKey)
	if string(sess["last_access"]) == string(old) || string(sess["last_access"]) != string(ident["last_access"]) {
		panic("identity load did not refresh both records")
	}
	refresh := sessionCase{Name: "identity_refreshes_shared_session", Operations: []string{"save_passphrase", "save_identity", "age_both_last_access", "load_identity", "compare_both_last_access"}, Expected: "both_refreshed"}
	sess["last_access"] = old
	sess["ttl_ns"] = json.RawMessage("1")
	store(sessionKey, sess)
	if !manager.IsIdentityExpired(vault) {
		panic("identity expiry ignored expired shared session")
	}
	expiry := sessionCase{Name: "identity_expiry_uses_shared_session", Operations: []string{"expire_session_only", "is_identity_expired"}, Expected: "expired"}
	return []sessionCase{peek, refresh, expiry}
}
