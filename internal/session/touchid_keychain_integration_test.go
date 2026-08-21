//go:build darwin && cgo

package session

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// keychainIntegrationEnv gates the tests in this file. They talk to the real
// login keychain of the machine they run on, so they stay opt-in: CI builds
// darwin with CGO_ENABLED=0 and runs the test job on ubuntu, and a developer
// running `go test ./...` should not get entries written into their personal
// keychain as a side effect.
const keychainIntegrationEnv = "SYMVAULT_KEYCHAIN_INTEGRATION"

// defaultKeychain returns the path of the user's default keychain — the one
// SecItemAdd writes to when a query names no keychain.
func defaultKeychain(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("security", "default-keychain", "-d", "user").Output()
	if err != nil {
		t.Fatalf("resolve default keychain: %v", err)
	}
	return strings.Trim(strings.TrimSpace(string(out)), `"`)
}

// searchListContainsDefaultKeychain reports whether the user-domain keychain
// search list contains the default keychain. When it does not, writes and
// lookups target different keychains and SecItemAdd starts reporting
// errSecDuplicateItem — the condition the fallback exists for.
func searchListContainsDefaultKeychain(t *testing.T) bool {
	t.Helper()
	out, err := exec.Command("security", "list-keychains", "-d", "user").Output()
	if err != nil {
		t.Fatalf("read keychain search list: %v", err)
	}
	return strings.Contains(string(out), defaultKeychain(t))
}

// removeKeychainItem deletes the scratch item a test created.
//
// It deliberately does not go through touchIDPassphraseStore.Delete: that path
// treats errSecItemNotFound as success (delete is idempotent by contract), so
// under the very search list this test breaks on purpose it reports success
// while leaving the item behind. Addressing the default keychain directly is
// the only cleanup that actually removes it.
func removeKeychainItem(t *testing.T, vaultDir string) {
	t.Helper()
	service := biometricServiceName(vaultDir)
	keychain := defaultKeychain(t)
	for range 8 {
		if err := exec.Command("security", "delete-generic-password",
			"-s", service, "-a", biometricAccount, keychain).Run(); err != nil {
			return
		}
	}
	t.Logf("cleanup: keychain item %q still present after 8 deletions", service)
}

// TestStorePassphraseRecoversFromDuplicateItem is the regression guard for the
// errSecDuplicateItem fallback in touch_id_store_passphrase.
//
// The guard only has teeth when the user-domain keychain search list does not
// contain the default keychain. In that state the SecItemDelete at the top of
// touch_id_store_passphrase misses, while SecItemAdd still resolves to the
// default keychain and reports errSecDuplicateItem (-25299). The fallback then
// updates the existing item — but only because its match query is pinned to
// the default keychain. Without that pin the update resolves through the same
// empty search list and misses too, turning -25299 into errSecItemNotFound
// (-25300), and the second Save below fails.
//
// On a healthy machine the delete succeeds and the duplicate path is simply
// unreachable, so the test skips rather than passing: a green result here must
// not be read as "the fallback works".
//
// To exercise it deliberately — this makes the vault unreadable until the
// search list is restored, so restore it in the same breath:
//
//	security list-keychains -d user                                        # save this
//	security list-keychains -d user -s                                     # break it
//	SYMVAULT_KEYCHAIN_INTEGRATION=1 go test ./internal/session/ -run Duplicate
//	security list-keychains -d user -s ~/Library/Keychains/login.keychain-db
func TestStorePassphraseRecoversFromDuplicateItem(t *testing.T) {
	if os.Getenv(keychainIntegrationEnv) != "1" {
		t.Skipf("set %s=1 to run keychain integration tests", keychainIntegrationEnv)
	}
	store := &touchIDPassphraseStore{}
	if !store.IsAvailable() {
		t.Skip("Touch ID not available on this machine")
	}
	if searchListContainsDefaultKeychain(t) {
		t.Skip("keychain search list contains the default keychain, so SecItemDelete succeeds and the errSecDuplicateItem path is unreachable — see the doc comment to exercise it")
	}

	ctx := context.Background()
	vaultDir := t.TempDir()
	t.Cleanup(func() { removeKeychainItem(t, vaultDir) })

	if err := store.Save(ctx, vaultDir, []byte("first-passphrase")); err != nil {
		t.Fatalf("first Save() = %v, want nil", err)
	}
	// The delete inside this second Save misses, so SecItemAdd reports
	// errSecDuplicateItem and only the pinned SecItemUpdate can recover.
	if err := store.Save(ctx, vaultDir, []byte("second-passphrase")); err != nil {
		t.Fatalf("second Save() = %v, want nil (the errSecDuplicateItem fallback did not recover)", err)
	}
	// Repeat: every further Save takes the same path, so a fallback that
	// happens to work once but corrupts the item would surface here.
	if err := store.Save(ctx, vaultDir, []byte("third-passphrase")); err != nil {
		t.Fatalf("third Save() = %v, want nil", err)
	}
}
