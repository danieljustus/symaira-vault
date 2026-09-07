package crypto

import (
	"crypto/hmac"
	"crypto/sha1" //#nosec G505 -- SHA1 is required by RFC 6238 (TOTP); this is intentional, not a security weakness
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"
)

// TOTPCode represents a generated TOTP code with metadata
type TOTPCode struct {
	ExpiresAt time.Time
	Code      string
	Period    int
}

func ValidateTOTPSecret(secret string) error {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	if len(secret) > 256 {
		return fmt.Errorf("TOTP secret too long: maximum 256 base32 characters")
	}

	var decoded []byte
	var err error

	decoded, err = base32.StdEncoding.DecodeString(secret)
	if err != nil {
		decoded, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		if err != nil {
			return fmt.Errorf("TOTP secret must be Base32-encoded (spaces allowed)")
		}
	}

	if len(decoded) < 16 {
		return fmt.Errorf("TOTP secret too short: minimum 16 bytes required (26 base32 characters)")
	}

	if allBytesSame(decoded) {
		return fmt.Errorf("TOTP secret is trivially weak: all bytes identical")
	}
	if bytesSequential(decoded) {
		return fmt.Errorf("TOTP secret is trivially weak: bytes are sequential")
	}

	return nil
}

// ValidateTOTPParams enforces RFC 6238 bounds on TOTP parameters.
// Empty algorithm and zero digits/period are accepted (used to detect if values need to be set).
// This prevents DoS/overflow from malformed entries.
func ValidateTOTPParams(algorithm string, digits, period int) error {
	algo := strings.ToUpper(algorithm)
	if algo != "" && algo != "SHA1" && algo != "SHA256" && algo != "SHA512" {
		return fmt.Errorf("invalid TOTP algorithm %q: must be SHA1, SHA256, or SHA512", algorithm)
	}
	if digits != 0 && digits != 6 && digits != 8 {
		return fmt.Errorf("invalid TOTP digits %d: must be 6 or 8", digits)
	}
	if period != 0 && (period <= 0 || period > 3600) {
		return fmt.Errorf("invalid TOTP period %d: must be 1-3600 seconds", period)
	}
	return nil
}

// ValidateTOTPData extracts and validates TOTP configuration from entry data.
func ValidateTOTPData(data map[string]any) error {
	if totpData, ok := data["totp"].(map[string]any); ok {
		if secret, ok := totpData["secret"].(string); ok && secret != "" {
			if err := ValidateTOTPSecret(secret); err != nil {
				return err
			}
		}
		var algo string
		var digits, period int
		if a, ok := totpData["algorithm"].(string); ok {
			algo = a
		}
		if d, ok := totpData["digits"].(float64); ok {
			digits = int(d)
		}
		if p, ok := totpData["period"].(float64); ok {
			period = int(p)
		}
		if err := ValidateTOTPParams(algo, digits, period); err != nil {
			return fmt.Errorf("invalid TOTP: %w", err)
		}
	}
	return nil
}

// GenerateTOTP generates a TOTP code from the current system time.
func GenerateTOTP(secret string, algorithm string, digits int, period int) (*TOTPCode, error) {
	return GenerateTOTPAt(secret, algorithm, digits, period, time.Now())
}

// GenerateTOTPAt is the explicit-clock seam used by deterministic callers and
// the language-neutral Rust-port fixture generator.
func GenerateTOTPAt(secret string, algorithm string, digits int, period int, now time.Time) (*TOTPCode, error) {
	if err := ValidateTOTPParams(algorithm, digits, period); err != nil {
		return nil, err
	}

	// Set defaults
	if algorithm == "" {
		algorithm = "SHA1"
	}
	if digits == 0 {
		digits = 6
	}
	if period == 0 {
		period = 30
	}

	// Clean the secret (remove spaces and convert to uppercase)
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))

	// Decode base32 secret
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		// Try without padding
		key, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		if err != nil {
			return nil, fmt.Errorf("invalid TOTP secret: %w", err)
		}
	}

	// The explicit clock is supplied by GenerateTOTP or the fixture generator.
	unixTime := now.Unix()
	if unixTime < 0 {
		return nil, fmt.Errorf("system time is before Unix epoch")
	}
	counter := uint64(unixTime) / uint64(period) // #nosec G115 // unixTime checked negative above

	// Calculate next expiration time
	expiresAt := now.Add(time.Duration(period) * time.Second)
	expiresAt = expiresAt.Add(-time.Duration(expiresAt.Unix()%int64(period)) * time.Second)

	// Generate HMAC
	var h hash.Hash
	switch strings.ToUpper(algorithm) {
	case "SHA256":
		h = hmac.New(sha256.New, key)
	case "SHA512":
		h = hmac.New(sha512.New, key)
	default: // SHA1
		h = hmac.New(sha1.New, key)
	}

	// Write counter as 8-byte big-endian
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	// Modulo to get desired number of digits
	mod := power10(digits)
	if mod < 0 || mod > int(^uint32(0)) {
		return nil, fmt.Errorf("digits value %d produces out-of-range modulus", digits)
	}
	code %= uint32(mod)

	// Format with leading zeros
	codeStr := fmt.Sprintf("%0*d", digits, code)

	return &TOTPCode{
		Code:      codeStr,
		ExpiresAt: expiresAt,
		Period:    period,
	}, nil
}

func allBytesSame(b []byte) bool {
	for i := 1; i < len(b); i++ {
		if b[i] != b[0] {
			return false
		}
	}
	return true
}

func bytesSequential(b []byte) bool {
	for i := 1; i < len(b); i++ {
		if b[i] != b[i-1]+1 {
			return false
		}
	}
	return true
}

// power10 returns 10^n
func power10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}
