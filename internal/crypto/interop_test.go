package crypto

import (
	"errors"
	"testing"

	"filippo.io/age"
)

func TestEncryptZeroKeyFixtureRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	params := Argon2idParams{Time: 1, Memory: 32, Threads: 1}
	raw, err := EncryptZeroKeyFixture(identity, 17, params)
	if err != nil {
		t.Fatalf("EncryptZeroKeyFixture: %v", err)
	}

	recovered, err := RecoverZeroKeyIdentity(raw, 17, ZeroKeyAuthorityForRecipient(identity.Recipient().String()))
	if err != nil {
		t.Fatalf("RecoverZeroKeyIdentity: %v", err)
	}
	if recovered.String() != identity.String() {
		t.Fatalf("recovered identity mismatch: got %q, want %q", recovered.String(), identity.String())
	}
}

func TestEncryptZeroKeyFixtureRejectsInvalidInputs(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	params := Argon2idParams{Time: 1, Memory: 32, Threads: 1}
	tests := []struct {
		name   string
		id     *age.X25519Identity
		length int
		want   error
	}{
		{name: "nil identity", length: 17, want: ErrNilIdentity},
		{name: "zero length", id: identity, want: ErrZeroKeyPassphraseLen},
		{name: "above bound", id: identity, length: MaxZeroKeyPassphraseLen + 1, want: ErrZeroKeyPassphraseLen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptZeroKeyFixture(tt.id, tt.length, params)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}
