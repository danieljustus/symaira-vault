package health

import (
	"errors"
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/session"
)

// installFakeSessionStatus swaps the process-wide session manager for one
// whose cache status reports the given backend, and restores the original on
// cleanup. This lets checkSessionCache/checkSessionKeyring exercise their
// OS-keyring branches without touching the real keychain. The keyring
// backend itself is never used by those checks (they call GetCacheStatus and
// the injectable probe only), so nil is safe here.
func installFakeSessionStatus(t *testing.T, backend string) {
	t.Helper()
	old := session.DefaultManager()
	t.Cleanup(func() { session.SetDefaultManager(old) })
	session.SetDefaultManager(session.NewManager(nil, func() session.CacheStatus {
		return session.CacheStatus{Backend: backend, Persistent: backend == session.CacheBackendOSKeyring}
	}))
}

// TestSessionKeyringResult_SetOKGetFailsReportsFail is the #802 regression:
// a keyring that accepts writes but fails reads (e.g. the login keychain
// dropped out of the search list) must make the doctor keyring check FAIL,
// not report green.
func TestSessionKeyringResult_SetOKGetFailsReportsFail(t *testing.T) {
	probe := func() error {
		return errors.New("keyring read-back failed: secret not found")
	}
	r := sessionKeyringResult(session.CacheBackendOSKeyring, probe, false)
	if r.Status != StatusFail {
		t.Fatalf("status = %s, want fail (message: %s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "persistence check failed") {
		t.Errorf("message = %q, want it to mention the persistence check", r.Message)
	}
}

// TestSessionKeyringResult_HealthyProbeReportsOK ensures a healthy keyring
// still reports OK (the honest-green case).
func TestSessionKeyringResult_HealthyProbeReportsOK(t *testing.T) {
	r := sessionKeyringResult(session.CacheBackendOSKeyring, func() error { return nil }, false)
	if r.Status != StatusOK {
		t.Fatalf("status = %s, want ok (message: %s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "verified") {
		t.Errorf("message = %q, want it to say persistence was verified", r.Message)
	}
}

// TestSessionKeyringResult_FallbackActiveReportsFail is the #802 regression
// for the degraded state: when the session layer has already fallen back to
// in-memory storage in production, the check must surface that as a failure
// instead of a green roundtrip (which would be served from memory).
func TestSessionKeyringResult_FallbackActiveReportsFail(t *testing.T) {
	r := sessionKeyringResult(session.CacheBackendMemory, func() error { return nil }, false)
	if r.Status != StatusFail {
		t.Fatalf("status = %s, want fail (message: %s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "in-memory") {
		t.Errorf("message = %q, want it to mention the in-memory fallback", r.Message)
	}
}

// TestSessionKeyringResult_TestEnvMemoryIsNotAFailure ensures test/CI
// processes (where the in-memory backend is forced) are not misreported as a
// broken keyring.
func TestSessionKeyringResult_TestEnvMemoryIsNotAFailure(t *testing.T) {
	r := sessionKeyringResult(session.CacheBackendMemory, func() error { return nil }, true)
	if r.Status != StatusWarn {
		t.Fatalf("status = %s, want warn (message: %s)", r.Status, r.Message)
	}
}

// TestCheckSessionCache_ReportsVerifiedNotConfiguredState is the #802
// regression for the cache check: with the backend claiming os-keyring but a
// failing probe, it must report persistent:false (verified), never the
// configured persistent:true.
func TestCheckSessionCache_ReportsVerifiedNotConfiguredState(t *testing.T) {
	installFakeSessionStatus(t, session.CacheBackendOSKeyring)
	oldProbe := sessionKeyringProbe
	sessionKeyringProbe = func() error { return errors.New("keyring read-back failed: secret not found") }
	t.Cleanup(func() { sessionKeyringProbe = oldProbe })

	r := checkSessionCache("", Options{})
	if r.Status != StatusFail {
		t.Fatalf("status = %s, want fail (message: %s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "persistent: false") {
		t.Errorf("message = %q, want it to report persistent: false", r.Message)
	}
}

// TestCheckSessionCache_HealthyProbeReportsVerifiedGreen ensures the cache
// check reports the verified persistent state when the probe succeeds.
func TestCheckSessionCache_HealthyProbeReportsVerifiedGreen(t *testing.T) {
	installFakeSessionStatus(t, session.CacheBackendOSKeyring)
	oldProbe := sessionKeyringProbe
	sessionKeyringProbe = func() error { return nil }
	t.Cleanup(func() { sessionKeyringProbe = oldProbe })

	r := checkSessionCache("", Options{})
	if r.Status != StatusOK {
		t.Fatalf("status = %s, want ok (message: %s)", r.Status, r.Message)
	}
	if !strings.Contains(r.Message, "persistent: true (verified)") {
		t.Errorf("message = %q, want it to report persistent: true (verified)", r.Message)
	}
}
