package crypto

import (
	"bytes"
	"fmt"

	"filippo.io/age"
)

// EncryptZeroKeyFixture creates the historical Argon2id zero-key envelope used
// only by the Rust interoperability corpus. It never writes storage and is
// intentionally named so production callers cannot confuse it with a safe
// encryption primitive.
func EncryptZeroKeyFixture(id *age.X25519Identity, passphraseLength int, params Argon2idParams) ([]byte, error) {
	if id == nil {
		return nil, ErrNilIdentity
	}
	if passphraseLength <= 0 || passphraseLength > MaxZeroKeyPassphraseLen {
		return nil, ErrZeroKeyPassphraseLen
	}
	zeros := make([]byte, passphraseLength)
	defer Wipe(zeros)
	recipient := NewArgon2idRecipient(string(zeros), params)
	var buf bytes.Buffer
	writer, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("create zero-key fixture encryptor: %w", err)
	}
	if _, err := writer.Write([]byte(id.String())); err != nil {
		return nil, fmt.Errorf("write zero-key fixture: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("close zero-key fixture: %w", err)
	}
	return buf.Bytes(), nil
}
