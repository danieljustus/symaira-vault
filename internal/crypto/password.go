package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"math/big"
	"unicode"
)

// MaxPasswordLength is the upper bound for generated password length.
const MaxPasswordLength = 1024

func GeneratePassword(length int, useSymbols bool) (string, error) {
	return generatePasswordWithReader(length, useSymbols, rand.Reader)
}

func generatePasswordWithReader(length int, useSymbols bool, reader io.Reader) (string, error) {
	const (
		letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	)

	if length <= 0 {
		length = 16
	}
	if length > MaxPasswordLength {
		return "", fmt.Errorf("password length must be at most %d", MaxPasswordLength)
	}

	charset := letters
	if useSymbols {
		charset += symbols
	}

	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		result[i] = charset[n.Int64()]
	}

	return string(result), nil
}

// PasswordStrength represents the result of a password strength assessment.
type PasswordStrength struct {
	Weak    bool    `json:"weak"`
	Message string  `json:"message,omitempty"`
	Entropy float64 `json:"entropy"`
}

// AssessPasswordStrength evaluates password strength without blocking.
// Returns a PasswordStrength struct with Weak=true if the password fails
// the minimum requirements (at least 10 characters, 60 bits of entropy).
func AssessPasswordStrength(password string) PasswordStrength {
	var s PasswordStrength

	if len(password) < 10 {
		s.Weak = true
		s.Message = "password too short: must be at least 10 characters"
		return s
	}

	charsetSize := 0
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSymbol := false

	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSymbol = true
		}
	}

	if hasLower {
		charsetSize += 26
	}
	if hasUpper {
		charsetSize += 26
	}
	if hasDigit {
		charsetSize += 10
	}
	if hasSymbol {
		charsetSize += 32
	}
	if charsetSize == 0 {
		charsetSize = 256
	}

	s.Entropy = float64(len(password)) * math.Log2(float64(charsetSize))
	if s.Entropy < 60 {
		s.Weak = true
		s.Message = fmt.Sprintf("password too weak: estimated entropy %.1f bits, need at least 60 bits", s.Entropy)
	}

	return s
}

// ValidatePasswordStrength checks if a password meets minimum strength requirements.
// It requires at least 10 characters and 60 bits of entropy based on charset diversity.
// This is a convenience wrapper around AssessPasswordStrength for callers that
// want a blocking error return.
func ValidatePasswordStrength(password string) error {
	s := AssessPasswordStrength(password)
	if s.Weak {
		return fmt.Errorf("%s", s.Message)
	}
	return nil
}
