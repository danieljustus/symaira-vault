package cli

import (
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
)

// GeneratePassword generates a password using an ambiguous-character-free
// charset. The returned cleanup function MUST be called to zero and release
// the underlying memory when the password is no longer needed.
func GeneratePassword(length int, useSymbols bool) (string, func(), error) {
	return cryptopkg.GeneratePassword(length, useSymbols)
}
