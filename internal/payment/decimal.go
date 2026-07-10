package payment

import (
	"fmt"
	"math/big"
)

// maxDecimalLen caps the length of strings parsed by this package. It is
// generous enough for typical currency values while preventing the
// malformed-string memory blowup described in CVE-2022-23772.
const maxDecimalLen = 30

// parseAmount parses a decimal string (e.g. "75.00", "-10") or a rational
// string produced by big.Rat.RatString() (e.g. "3/10", "-1/2"). It validates
// length and format before invoking big.Rat.SetString.
func parseAmount(s string) (*big.Rat, error) {
	if len(s) == 0 || len(s) > maxDecimalLen {
		return nil, fmt.Errorf("invalid amount %q", s)
	}
	sawDot := false
	sawSlash := false
	hasDigit := false
	for i, r := range s {
		switch r {
		case '-':
			if i != 0 {
				return nil, fmt.Errorf("invalid amount %q", s)
			}
		case '.':
			if sawSlash || sawDot {
				return nil, fmt.Errorf("invalid amount %q", s)
			}
			sawDot = true
		case '/':
			if sawSlash || sawDot {
				return nil, fmt.Errorf("invalid amount %q", s)
			}
			sawSlash = true
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			hasDigit = true
		default:
			return nil, fmt.Errorf("invalid amount %q", s)
		}
	}
	if !hasDigit {
		return nil, fmt.Errorf("invalid amount %q", s)
	}
	// Length and format are validated above, so the input cannot trigger the
	// malformed-string memory blowup described in CVE-2022-23772.
	// #nosec G113
	rat, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("invalid amount %q", s)
	}
	return rat, nil
}
