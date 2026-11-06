package importer

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/crypto"
)

// TOTP default parameters per RFC 6238 and the otpauth Key URI Format
// (https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
const (
	totpDefaultAlgorithm = "SHA1"
	totpDefaultDigits    = 6
	totpDefaultPeriod    = 30
)

// ParseTOTP normalizes a TOTP value from an external export into the
// structured shape used by vault entries:
//
//	map[string]any{"secret": ..., "algorithm": ..., "digits": ..., "period": ...}
//
// It accepts either a bare Base32 secret or a full otpauth://totp/... URI.
// For URIs, the secret parameter is extracted and algorithm, digits and period
// are read from the query string, falling back to the RFC 6238 defaults
// (SHA1, 6, 30) when absent. The issuer and label are tolerated and ignored.
// Other otpauth types (e.g. otpauth://hotp/...) are rejected with a clear
// error. The secret is validated with the same rules the vault applies when
// writing entries (see crypto.ValidateTOTPSecret).
func ParseTOTP(value string) (map[string]any, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty TOTP value")
	}

	secret := value
	algorithm := totpDefaultAlgorithm
	digits := totpDefaultDigits
	period := totpDefaultPeriod

	if strings.HasPrefix(strings.ToLower(value), "otpauth://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return nil, fmt.Errorf("parse otpauth URI: %w", err)
		}
		if !strings.EqualFold(parsed.Scheme, "otpauth") {
			return nil, fmt.Errorf("unsupported TOTP scheme %q: only otpauth is supported", parsed.Scheme)
		}
		if parsed.Host == "" {
			return nil, fmt.Errorf("otpauth URI is missing the type (expected otpauth://totp/...)")
		}
		if !strings.EqualFold(parsed.Host, "totp") {
			return nil, fmt.Errorf("unsupported otpauth type %q: only otpauth://totp/... is supported", parsed.Host)
		}

		query := parsed.Query()
		if query.Get("secret") == "" {
			return nil, fmt.Errorf("otpauth URI is missing the secret parameter")
		}
		secret = query.Get("secret")

		if a := query.Get("algorithm"); a != "" {
			algorithm = strings.ToUpper(a)
		}
		if d := query.Get("digits"); d != "" {
			n, err := strconv.Atoi(d)
			if err != nil {
				return nil, fmt.Errorf("invalid TOTP digits %q in otpauth URI: %w", d, err)
			}
			if n != 6 && n != 8 {
				return nil, fmt.Errorf("invalid TOTP digits %d in otpauth URI: must be 6 or 8", n)
			}
			digits = n
		}
		if p := query.Get("period"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, fmt.Errorf("invalid TOTP period %q in otpauth URI: %w", p, err)
			}
			if n <= 0 || n > 3600 {
				return nil, fmt.Errorf("invalid TOTP period %d in otpauth URI: must be 1-3600 seconds", n)
			}
			period = n
		}
	}

	if err := crypto.ValidateTOTPSecret(secret); err != nil {
		return nil, fmt.Errorf("invalid TOTP secret: %w", err)
	}
	if err := crypto.ValidateTOTPParams(algorithm, digits, period); err != nil {
		return nil, fmt.Errorf("invalid TOTP configuration: %w", err)
	}

	// digits and period are float64 to match the shape vault entries have
	// after a JSON round trip (see vault.ExtractTOTP and crypto.ValidateTOTPData).
	return map[string]any{
		"secret":    secret,
		"algorithm": algorithm,
		"digits":    float64(digits),
		"period":    float64(period),
	}, nil
}
