package cli

import (
	"crypto/rand"
	"fmt"
	"math/big"

	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
)

const lowerChars = "abcdefghjkmnpqrstuvwxyz"
const upperChars = "ABCDEFGHJKMNPQRSTUVWXYZ"
const digitChars = "23456789"
const symbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"

// GeneratePassword generates a password using an ambiguous-character-free
// charset. The returned cleanup function MUST be called to zero and release
// the underlying memory when the password is no longer needed.
func GeneratePassword(length int, useSymbols bool) (string, func(), error) {
	if length < 1 {
		return "", func() {}, fmt.Errorf("password length must be at least 1")
	}
	if length > 4096 {
		length = 4096
	}

	chars := lowerChars + upperChars + digitChars
	if useSymbols {
		chars += symbolChars
	}

	buf := make([]byte, length)
	for i := range buf {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", func() {}, fmt.Errorf("cannot generate random index: %w", err)
		}
		buf[i] = chars[idx.Int64()]
	}

	s, cleanup := cryptopkg.SecureString(buf)
	cryptopkg.Wipe(buf)
	return s, cleanup, nil
}
