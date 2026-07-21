package vault

import (
	"regexp"
	"strings"
)

// SecretType represents the semantic type of a secret entry.
type SecretType string

const (
	SecretTypeAPIKey      SecretType = "api_key"
	SecretTypeBearerToken SecretType = "bearer_token"
	SecretTypeBasicAuth   SecretType = "basic_auth"
	SecretTypeSSHKey      SecretType = "ssh_key"
	SecretTypePassword    SecretType = "password"
	SecretTypeCertificate SecretType = "certificate"
	SecretTypeDatabaseURL SecretType = "database_url"
	SecretTypeTOTPSeed    SecretType = "totp_seed"
	SecretTypePayment     SecretType = "payment"
	SecretTypeCustom      SecretType = "custom"
)

// AllSecretTypes returns all valid secret types.
func AllSecretTypes() []SecretType {
	return []SecretType{
		SecretTypeAPIKey,
		SecretTypeBearerToken,
		SecretTypeBasicAuth,
		SecretTypeSSHKey,
		SecretTypePassword,
		SecretTypeCertificate,
		SecretTypeDatabaseURL,
		SecretTypeTOTPSeed,
		SecretTypePayment,
		SecretTypeCustom,
	}
}

// SecretTypeFromString parses a secret type from string, defaulting to custom.
func SecretTypeFromString(s string) SecretType {
	switch strings.ToLower(s) {
	case string(SecretTypeAPIKey):
		return SecretTypeAPIKey
	case string(SecretTypeBearerToken):
		return SecretTypeBearerToken
	case string(SecretTypeBasicAuth):
		return SecretTypeBasicAuth
	case string(SecretTypeSSHKey):
		return SecretTypeSSHKey
	case string(SecretTypePassword):
		return SecretTypePassword
	case string(SecretTypeCertificate):
		return SecretTypeCertificate
	case string(SecretTypeDatabaseURL):
		return SecretTypeDatabaseURL
	case string(SecretTypeTOTPSeed):
		return SecretTypeTOTPSeed
	case string(SecretTypePayment):
		return SecretTypePayment
	case string(SecretTypeCustom):
		return SecretTypeCustom
	default:
		return SecretTypeCustom
	}
}

// IsValidSecretType checks if the given string is a valid secret type.
func IsValidSecretType(s string) bool {
	switch strings.ToLower(s) {
	case string(SecretTypeAPIKey), string(SecretTypeBearerToken), string(SecretTypeBasicAuth), string(SecretTypeSSHKey),
		string(SecretTypePassword), string(SecretTypeCertificate), string(SecretTypeDatabaseURL), string(SecretTypeTOTPSeed),
		string(SecretTypePayment), string(SecretTypeCustom):
		return true
	}
	return false
}

// detection patterns for common secret types
var (
	awsAccessKeyPattern      = regexp.MustCompile(`^AKIA[0-9A-Z]{16}$`)
	githubPATPattern         = regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36}$`)
	githubFineGrainedPattern = regexp.MustCompile(`^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$`)
	githubOAuthPattern       = regexp.MustCompile(`^gho_[a-zA-Z0-9]{36}$`)
	githubAppPattern         = regexp.MustCompile(`^ghs_[a-zA-Z0-9]{36}$`)
	githubRefreshPattern     = regexp.MustCompile(`^ghr_[a-zA-Z0-9]{36}$`)
	sshRSAPattern            = regexp.MustCompile(`(?i)^-----BEGIN RSA PRIVATE KEY-----`)
	sshECDSAPattern          = regexp.MustCompile(`(?i)^-----BEGIN EC PRIVATE KEY-----`)
	sshED25519Pattern        = regexp.MustCompile(`(?i)^-----BEGIN OPENSSH PRIVATE KEY-----`)
	sshDSAPattern            = regexp.MustCompile(`(?i)^-----BEGIN DSA PRIVATE KEY-----`)
	databaseURLPattern       = regexp.MustCompile(`^(postgres(ql)?|mysql|mongodb(\+srv)?|redis|sqlite|mariadb)://`)
	basicAuthPattern         = regexp.MustCompile(`^[^:]+:[^:]+$`)
	genericAPIKeyPattern     = regexp.MustCompile(`^[a-zA-Z0-9_-]{32,}$`)
	bearerTokenPattern       = regexp.MustCompile(`^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$`)
	totpSeedPattern          = regexp.MustCompile(`^[A-Z2-7]{16,}$`)
	certPattern              = regexp.MustCompile(`(?i)^-----BEGIN CERTIFICATE-----`)
)

// DetectSecretType attempts to automatically detect the secret type from its value.
// Returns the most specific matching type, or SecretTypePassword as a fallback.
//
//nolint:gocyclo // complexity inherent to pattern matching against many secret type signatures
func DetectSecretType(value string) SecretType {
	value = strings.TrimSpace(value)
	if value == "" {
		return SecretTypePassword
	}

	// Check for SSH keys first (most specific)
	if sshRSAPattern.MatchString(value) || sshECDSAPattern.MatchString(value) ||
		sshED25519Pattern.MatchString(value) || sshDSAPattern.MatchString(value) {
		return SecretTypeSSHKey
	}

	// Check for certificates
	if certPattern.MatchString(value) {
		return SecretTypeCertificate
	}

	// Check for database URLs
	if databaseURLPattern.MatchString(value) {
		return SecretTypeDatabaseURL
	}

	// Check for GitHub tokens
	if githubPATPattern.MatchString(value) || githubFineGrainedPattern.MatchString(value) ||
		githubOAuthPattern.MatchString(value) || githubAppPattern.MatchString(value) ||
		githubRefreshPattern.MatchString(value) {
		return SecretTypeBearerToken
	}

	// Check for AWS keys
	if awsAccessKeyPattern.MatchString(value) {
		return SecretTypeAPIKey
	}

	// Check for TOTP seeds (base32 encoded)
	if totpSeedPattern.MatchString(value) && len(value) >= 16 {
		return SecretTypeTOTPSeed
	}

	// Check for JWT/bearer tokens
	if bearerTokenPattern.MatchString(value) {
		return SecretTypeBearerToken
	}

	// Check for basic auth format
	if basicAuthPattern.MatchString(value) && strings.Contains(value, ":") {
		// Make sure it's not just a URL or something else
		parts := strings.SplitN(value, ":", 2)
		if len(parts) == 2 && len(parts[0]) > 0 && len(parts[1]) > 0 {
			return SecretTypeBasicAuth
		}
	}

	// Check for generic API keys (long alphanumeric strings)
	if genericAPIKeyPattern.MatchString(value) && len(value) >= 32 {
		return SecretTypeAPIKey
	}

	// Default to password for anything else
	return SecretTypePassword
}

// DetectTypeFromPath infers a secret type from the entry path segments.
// Returns an empty string when no strong signal is present.
//
// Certificate/PKCS#12 tokens ("cert", "certificate", "pfx") are deliberately
// not matched here: a certificate payload always self-identifies via its PEM
// header (see DetectSecretType) or an explicit --type, whereas a bare value
// can just as easily be the passphrase for a same-path PKCS#12 file (e.g.
// "apple-developer/certificate-p12"). Treating that path segment as a strong
// signal silently mis-files the passphrase under the cert_pem field.
//
//nolint:goconst // matching against natural language path tokens is clearer as literals
func DetectTypeFromPath(path string) SecretType {
	path = strings.ToLower(path)
	for _, part := range strings.Split(path, "/") {
		// Check full hyphenated tokens first so "api-key" is recognized as a
		// single API-key signal before being split into "api" and "key".
		switch part {
		case "api-key", "apikey":
			return SecretTypeAPIKey
		}
		for _, seg := range strings.Split(part, "-") {
			switch seg {
			case "apikey":
				return SecretTypeAPIKey
			case "token":
				return SecretTypeBearerToken
			case "ssh":
				return SecretTypeSSHKey
			case "seed", "mnemonic":
				return SecretTypeTOTPSeed
			case "database", "db":
				return SecretTypeDatabaseURL
			case "password", "pass":
				return SecretTypePassword
			}
		}
	}
	return ""
}

// DetectTypeFromFieldName infers a secret type from a data field name.
// Returns an empty string when the field name is not a strong type signal.
//
//nolint:goconst // matching against natural language field names is clearer as literals
func DetectTypeFromFieldName(field string) SecretType {
	field = strings.ToLower(strings.TrimSpace(field))
	switch field {
	case "api_key", "apikey":
		return SecretTypeAPIKey
	case "token", "access_token", "bearer_token":
		return SecretTypeBearerToken
	case "seed_phrase", "mnemonic":
		return SecretTypeTOTPSeed
	case "private_key", "ssh_key":
		return SecretTypeSSHKey
	case "database_url", "connection_string":
		return SecretTypeDatabaseURL
	case "cert_pem", "certificate":
		return SecretTypeCertificate
	default:
		return ""
	}
}

// InferSecretType combines explicit type, value pattern, path and field-name
// signals to choose the most appropriate secret type, in that fixed
// precedence order:
//
//  1. explicitType (the user-provided --type flag)
//  2. the value's own content (DetectSecretType) — a value that
//     self-identifies (a PEM certificate/key, a JWT, a DB URL, ...) always
//     wins, because it is the strongest available evidence
//  3. the entry path (DetectTypeFromPath) — a naming convention, weaker than
//     the value itself
//  4. the data field name (DetectTypeFromFieldName) — weakest, since it is
//     rarely known ahead of the type at entry-creation time
//
// A PKCS#12 (.p12/.pfx) certificate and its import passphrase are different
// materials that commonly share a path (e.g. "apple-developer/certificate-p12"
// holding the passphrase under a "password" field). Store the certificate
// payload as PEM text (self-identifying) or via an explicit --type on its own
// entry/field, and the passphrase as a separate password entry or field, so
// this precedence order never has to guess between the two.
//
// The explicitType parameter is the user-provided --type flag; pass an empty
// string when the caller has not specified a type.
func InferSecretType(path, fieldName, value, explicitType string) SecretType {
	if explicitType != "" {
		return SecretTypeFromString(explicitType)
	}
	if t := DetectSecretType(value); t != SecretTypePassword {
		return t
	}
	if t := DetectTypeFromPath(path); t != "" {
		return t
	}
	if t := DetectTypeFromFieldName(fieldName); t != "" {
		return t
	}
	return SecretTypePassword
}

// PrimaryFieldForType returns the conventional primary data field name for a
// secret type. This keeps newly-added entries consistent so the TUI and MCP
// tools can find the secret value without guessing.
func PrimaryFieldForType(t SecretType) string {
	switch t {
	case SecretTypeAPIKey:
		return "api_key"
	case SecretTypeBearerToken:
		return "token"
	case SecretTypeSSHKey:
		return "private_key"
	case SecretTypeDatabaseURL:
		return "connection_string"
	case SecretTypeCertificate:
		return "cert_pem"
	case SecretTypeTOTPSeed:
		return "seed"
	case SecretTypePayment:
		return PaymentFieldCardNumber
	case SecretTypeBasicAuth:
		return string(SecretTypeBasicAuth)
	default:
		return "password"
	}
}

// UsageHintForType returns a predefined usage hint for the given secret type.
func UsageHintForType(t SecretType) string {
	switch t {
	case SecretTypeAPIKey:
		return "Set as header or query parameter depending on API documentation. Common: X-API-Key: <key> or ?api_key=<key>"
	case SecretTypeBearerToken:
		return "Set Header Authorization: Bearer <token>"
	case SecretTypeBasicAuth:
		return "Encode as base64(user:pass) and set Header Authorization: Basic <encoded>"
	case SecretTypeSSHKey:
		return "Write to temporary file with chmod 600 before use. Use with ssh -i <keyfile>"
	case SecretTypePassword:
		return "Use for authentication. Consider using a password manager or secret injection."
	case SecretTypeCertificate:
		return "Use with TLS/SSL configuration. May require private key pairing."
	case SecretTypeDatabaseURL:
		return "Use as connection string. Ensure credentials are not logged."
	case SecretTypeTOTPSeed:
		return "Use with TOTP generator. Never share the seed - only share generated codes."
	case SecretTypePayment:
		return "Payment card or bank account details. Sensitive fields (card_number, cvc, iban) are redacted by default."
	case SecretTypeCustom:
		return "Follow the specific integration instructions for this secret."
	default:
		return ""
	}
}

// SecretTypeIcon returns an icon/emoji for the given secret type.
func SecretTypeIcon(t SecretType) string {
	switch t {
	case SecretTypeAPIKey:
		return "🔑"
	case SecretTypeBearerToken:
		return "🎫"
	case SecretTypeBasicAuth:
		return "🔐"
	case SecretTypeSSHKey:
		return "🔒"
	case SecretTypePassword:
		return "🗝️"
	case SecretTypeCertificate:
		return "📜"
	case SecretTypeDatabaseURL:
		return "🗄️"
	case SecretTypeTOTPSeed:
		return "⏱️"
	case SecretTypePayment:
		return "💳"
	case SecretTypeCustom:
		return "📦"
	default:
		return "❓"
	}
}
