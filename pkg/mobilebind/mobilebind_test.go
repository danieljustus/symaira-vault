package mobilebind_test

import (
	"strings"
	"testing"

	"github.com/danieljustus/symaira-vault/pkg/mobilebind"
)

// TestPkgMobilebindReexport verifies the non-internal export surface re-exposes
// the internal mobilebind API correctly. pkg/mobilebind is a thin re-export so
// gomobile can bind it (gomobile cannot bind internal/... paths); this guards
// against a future drift between the two packages.
func TestPkgMobilebindReexport(t *testing.T) {
	id, err := mobilebind.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if !strings.HasPrefix(id, "AGE-SECRET-KEY-") {
		t.Fatalf("expected AGE-SECRET-KEY prefix, got %q", id)
	}

	pub, err := mobilebind.IdentityPublicKey(id)
	if err != nil {
		t.Fatalf("IdentityPublicKey: %v", err)
	}
	if !strings.HasPrefix(pub, "age1") {
		t.Fatalf("expected age1 prefix, got %q", pub)
	}
	if got := mobilebind.PublicKeyFingerprint(pub); got == "" {
		t.Fatalf("empty fingerprint")
	}
}
