package masking

import (
	"regexp"
	"strings"
	"unicode"
)

// ValidateLuhn validates a credit card number using the Luhn algorithm.
// It strips any non-digit characters (spaces, dashes) before validation.
// Returns true if the number passes the Luhn check and has 13-19 digits.
func ValidateLuhn(value string) bool {
	// Strip non-digits
	var buf strings.Builder
	buf.Grow(len(value))
	for _, r := range value {
		if unicode.IsDigit(r) {
			buf.WriteRune(r)
		}
	}
	digits := buf.String()

	// Credit card numbers are typically 13-19 digits
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	parity := len(digits) % 2
	for i, r := range digits {
		d := int(r - '0')
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// ibanRegex is used by ValidateIBAN to strip spaces and check structure.
var ibanRegex = regexp.MustCompile(`^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$`)

// ValidateIBAN validates an IBAN (International Bank Account Number).
// It strips spaces and checks:
//  1. Length is between 15 and 34 characters (inclusive)
//  2. Format matches [A-Z]{2}\d{2}[A-Z0-9]{1,30}
//  3. MOD-97 check passes (standard IBAN validation)
//
// Returns true if the IBAN is valid.
func ValidateIBAN(value string) bool {
	// Strip spaces and convert to uppercase
	cleaned := strings.ToUpper(strings.ReplaceAll(value, " ", ""))

	// IBAN length must be 15-34 characters
	if len(cleaned) < 15 || len(cleaned) > 34 {
		return false
	}

	// Check basic format
	if !ibanRegex.MatchString(cleaned) {
		return false
	}

	// MOD-97 validation:
	// 1. Move first 4 characters to the end
	// 2. Replace letters with numbers (A=10, B=11, ..., Z=35)
	// 3. Parse as integer and compute mod 97
	// 4. Result must be 1
	rearranged := cleaned[4:] + cleaned[:4]

	var numBuilder strings.Builder
	numBuilder.Grow(len(rearranged) * 2)
	for _, r := range rearranged {
		if r >= 'A' && r <= 'Z' {
			numBuilder.WriteString(string('0' + (r-'A'+10)/10))
			numBuilder.WriteString(string('0' + (r-'A'+10)%10))
		} else {
			numBuilder.WriteRune(r)
		}
	}
	numStr := numBuilder.String()

	// Compute mod 97 by processing in chunks
	// Use a rolling modulo to avoid large integer overflow
	remainder := 0
	for _, r := range numStr {
		remainder = (remainder*10 + int(r-'0')) % 97
	}
	return remainder == 1
}
