package intake

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// fieldConfidence scores how strongly a parsed key maps to a vault field.
// High-confidence keys map to first-class vault fields (username, password,
// token, ...); everything else lands in a generic field with lower
// confidence. Suggestions are never authoritative — the review step decides.
func fieldConfidence(key string) (string, float64) {
	k := strings.ToLower(strings.TrimSpace(key))
	switch k {
	case "username", "user", "login", "login_id", "loginid", "account", "email", "mail", "userid", "user_id":
		return "username", 0.95
	case "password", "pass", "passwd", "pwd", "password_plain", "secret":
		return "password", 0.95
	case "token", "access_token", "accesstoken", "api_key", "apikey", "api-key", "key", "auth_token", "authtoken", "bearer":
		return "token", 0.9
	case "totp", "otp", "otpauth", "secret_key", "secretkey", "2fa", "two_factor":
		return "totp", 0.85
	case "client_id", "clientid", "client-id":
		return "client_id", 0.8
	case "client_secret", "clientsecret", "client-secret":
		return "client_secret", 0.85
	case "certificate", "cert", "cert_p12", "certificate_p12", "pfx", "p12":
		return "certificate", 0.8
	case "note", "notes", "comment", "comments", "description", "desc":
		return "notes", 0.5
	default:
		return "", 0.6
	}
}

// Parse derives field/attachment suggestions from the sniffed content. The
// proposed entry path is always derived from the source base name; values are
// internal and must not be rendered into JSON/log output.
func Parse(data []byte, st SourceType, sourceName string) []Suggestion {
	entryPath := ProposedEntryPath(sourceName)
	switch st {
	case SourceTypeEnv:
		return parseEnv(data, entryPath)
	case SourceTypeJSON:
		return parseJSON(data, entryPath)
	case SourceTypeText:
		return parseText(data, entryPath)
	case SourceTypeCert, SourceTypeKey, SourceTypeImage, SourceTypePDF, SourceTypeArchive, SourceTypeOther:
		// Exact-file fallback: the source bytes are the credential material.
		return []Suggestion{{
			Path:       entryPath,
			Field:      AttachmentField,
			Confidence: 1.0,
			Attachment: true,
		}}
	default:
		return []Suggestion{{
			Path:       entryPath,
			Field:      AttachmentField,
			Confidence: 1.0,
			Attachment: true,
		}}
	}
}

func parseEnv(data []byte, entryPath string) []Suggestion {
	var out []Suggestion
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split on the first '=' only; values may contain '='.
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		value := strings.TrimSpace(line[i+1:])
		if value == "" {
			continue
		}
		field, conf := fieldConfidence(key)
		if field == "" {
			field = envFieldName(key)
		}
		out = append(out, Suggestion{
			Path:       entryPath,
			Field:      field,
			Value:      value,
			Confidence: conf,
		})
	}
	if len(out) == 0 {
		out = append(out, Suggestion{
			Path:       entryPath,
			Field:      AttachmentField,
			Confidence: 1.0,
			Attachment: true,
		})
	}
	return out
}

// envFieldName derives a stable, lowercase field name from an env-style key
// (e.g. DATABASE_URL -> database_url). Keys already mapped by
// fieldConfidence keep their canonical field name.
func envFieldName(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func parseJSON(data []byte, entryPath string) []Suggestion {
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		// Not a JSON object (maybe an array): treat as attachment.
		return []Suggestion{{
			Path:       entryPath,
			Field:      AttachmentField,
			Confidence: 1.0,
			Attachment: true,
		}}
	}
	var out []Suggestion
	for key, raw := range obj {
		value, ok := raw.(string)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		field, conf := fieldConfidence(key)
		if field == "" {
			field = envFieldName(key)
		}
		out = append(out, Suggestion{
			Path:       entryPath,
			Field:      field,
			Value:      value,
			Confidence: conf,
		})
	}
	if len(out) == 0 {
		out = append(out, Suggestion{
			Path:       entryPath,
			Field:      AttachmentField,
			Confidence: 1.0,
			Attachment: true,
		})
	}
	return out
}

// textCredentialPatterns are line prefixes that hint at a credential field in
// a plain-text file ("username: alice", "password: hunter2", ...).
var textCredentialPatterns = []struct {
	prefix string
	field  string
	conf   float64
}{
	{"username:", "username", 0.8},
	{"user name:", "username", 0.8},
	{"user:", "username", 0.8},
	{"login:", "username", 0.8},
	{"login id:", "username", 0.8},
	{"account:", "username", 0.6},
	{"email:", "username", 0.7},
	{"password:", "password", 0.85},
	{"pass:", "password", 0.8},
	{"passwd:", "password", 0.8},
	{"pwd:", "password", 0.8},
	{"secret:", "password", 0.7},
	{"token:", "token", 0.8},
	{"api key:", "token", 0.85},
	{"api-key:", "token", 0.85},
	{"apikey:", "token", 0.85},
	{"access token:", "token", 0.85},
	{"auth token:", "token", 0.8},
	{"totp:", "totp", 0.8},
	{"otp:", "totp", 0.8},
	{"2fa:", "totp", 0.7},
	{"client id:", "client_id", 0.7},
	{"client secret:", "client_secret", 0.8},
}

func parseText(data []byte, entryPath string) []Suggestion {
	lines := strings.Split(string(data), "\n")
	var out []Suggestion
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		for _, p := range textCredentialPatterns {
			if strings.HasPrefix(lower, p.prefix) {
				value := strings.TrimSpace(trimmed[len(p.prefix):])
				if value != "" {
					out = append(out, Suggestion{
						Path:       entryPath,
						Field:      p.field,
						Value:      value,
						Confidence: p.conf,
					})
				}
				break
			}
		}
	}
	if len(out) == 0 {
		// No credential hints: the exact file is the material.
		out = append(out, Suggestion{
			Path:       entryPath,
			Field:      AttachmentField,
			Confidence: 1.0,
			Attachment: true,
		})
	}
	return out
}

// SourceFileType returns the human-readable source type label for a path,
// used for provenance display before content sniffing.
func SourceFileType(name string) SourceType {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic":
		return SourceTypeImage
	case ".pdf":
		return SourceTypePDF
	case ".pem", ".crt", ".cer", ".der":
		return SourceTypeCert
	case ".key", ".p12", ".pfx", ".p8", ".jks":
		return SourceTypeKey
	case ".env", ".ini", ".cfg", ".conf", ".properties":
		return SourceTypeEnv
	case ".json":
		return SourceTypeJSON
	case ".txt", ".md", ".log", ".csv", ".yaml", ".yml":
		return SourceTypeText
	case ".zip", ".tar", ".gz", ".7z":
		return SourceTypeArchive
	default:
		return SourceTypeOther
	}
}
