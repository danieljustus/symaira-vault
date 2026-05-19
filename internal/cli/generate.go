package cli

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const lowerChars = "abcdefghjkmnpqrstuvwxyz"
const upperChars = "ABCDEFGHJKMNPQRSTUVWXYZ"
const digitChars = "23456789"
const symbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"

func GeneratePassword(length int, useSymbols bool) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("password length must be at least 1")
	}
	if length > 4096 {
		length = 4096
	}

	chars := lowerChars + upperChars + digitChars
	if useSymbols {
		chars += symbolChars
	}

	password := make([]byte, length)
	for i := range password {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("cannot generate random index: %w", err)
		}
		password[i] = chars[idx.Int64()]
	}

	return string(password), nil
}
