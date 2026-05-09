package wizard

import "unicode"

// PassphraseStrength is a qualitative rating for a passphrase.
type PassphraseStrength int

const (
	StrengthWeak PassphraseStrength = iota
	StrengthFair
	StrengthGood
	StrengthStrong
)

func (s PassphraseStrength) String() string {
	switch s {
	case StrengthFair:
		return "fair"
	case StrengthGood:
		return "good"
	case StrengthStrong:
		return "strong"
	default:
		return "weak"
	}
}

// Bar returns a visual progress indicator.
func (s PassphraseStrength) Bar() string {
	switch s {
	case StrengthFair:
		return "[▓▓░░] fair"
	case StrengthGood:
		return "[▓▓▓░] good"
	case StrengthStrong:
		return "[▓▓▓▓] strong"
	default:
		return "[▓░░░] weak"
	}
}

// MeasureStrength rates a passphrase using length and character diversity.
// No external libraries — intentionally simple and dependency-light.
func MeasureStrength(p string) PassphraseStrength {
	if len(p) == 0 {
		return StrengthWeak
	}
	score := 0

	// Length score (0-4 pts).
	switch {
	case len(p) >= 20:
		score += 4
	case len(p) >= 16:
		score += 3
	case len(p) >= 12:
		score += 2
	case len(p) >= 8:
		score++
	}

	// Character diversity (1 pt each, max 4 pts).
	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, ch := range p {
		switch {
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsDigit(ch):
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if hasLower {
		score++
	}
	if hasUpper {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}

	switch {
	case score >= 7:
		return StrengthStrong
	case score >= 5:
		return StrengthGood
	case score >= 3:
		return StrengthFair
	default:
		return StrengthWeak
	}
}
