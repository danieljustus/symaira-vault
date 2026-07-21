package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

const defaultTOTPAlgorithm = "SHA1"

// Entry represents a vault entry with flexible data storage using map[string]any.
type Entry struct {
	Path           string               `json:"path,omitempty"`
	Data           map[string]any       `json:"data"`
	Metadata       EntryMetadata        `json:"meta"`
	SecretMetadata SecretMetadata       `json:"secret_meta,omitempty"`
	Classification taint.Classification `json:"classification,omitempty"`
	Canary         bool                 `json:"canary,omitempty"`
	PendingWrite   *WriteRecord         `json:"-"`
}

// WriteRecord tracks a write operation on an entry for audit/provenance.
type WriteRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Field     string    `json:"field,omitempty"`
	Action    string    `json:"action"`
}

// EntryMetadata contains metadata about an entry
type EntryMetadata struct {
	Created      time.Time     `json:"created"`
	Updated      time.Time     `json:"updated"`
	Version      int           `json:"version"`
	Tags         []string      `json:"tags,omitempty"`
	WriteHistory []WriteRecord `json:"write_history,omitempty"`
}

// SecretMetadata contains semantic metadata about a secret for AI agent usage.
type SecretMetadata struct {
	Type        SecretType                `json:"type,omitempty"`
	UsageHint   string                    `json:"usage_hint,omitempty"`
	AutoRotate  bool                      `json:"auto_rotate,omitempty"`
	ExpiresAt   *time.Time                `json:"expires_at,omitempty"`
	Attachments map[string]AttachmentInfo `json:"attachments,omitempty"`
}

// AttachmentInfo records provenance for a Data field holding base64-encoded
// binary file content added via `symvault file add`, so `file get`/`file use`
// can detect silent corruption and report the original filename/size without
// having to guess whether a field is text or a file attachment.
type AttachmentInfo struct {
	Filename string `json:"filename,omitempty"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// MarshalJSON implements custom JSON marshaling for Entry
func (e Entry) MarshalJSON() ([]byte, error) {
	type alias Entry
	return json.Marshal(alias(e))
}

// UnmarshalJSON implements custom JSON unmarshaling for Entry
func (e *Entry) UnmarshalJSON(data []byte) error {
	type alias Entry
	var v alias
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*e = Entry(v)
	if e.Data == nil {
		e.Data = map[string]any{}
	}
	return nil
}

// TagWeakPassword is the tag applied to entries whose password is assessed as weak.
const TagWeakPassword = "weak-password"

// HasTag returns true if the entry has the given tag.
func (e *Entry) HasTag(tag string) bool {
	for _, t := range e.Metadata.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// AddTag adds a tag to the entry if not already present.
func (e *Entry) AddTag(tag string) {
	if !e.HasTag(tag) {
		e.Metadata.Tags = append(e.Metadata.Tags, tag)
	}
}

// RemoveTag removes a tag from the entry if present.
func (e *Entry) RemoveTag(tag string) {
	for i, t := range e.Metadata.Tags {
		if t == tag {
			e.Metadata.Tags = append(e.Metadata.Tags[:i], e.Metadata.Tags[i+1:]...)
			return
		}
	}
}

// ExtractTOTP extracts TOTP configuration from entry data.
func ExtractTOTP(data map[string]any) (secret, algorithm string, digits, period int, hasTOTP bool) {
	totpData, ok := data["totp"].(map[string]any)
	if !ok {
		return "", "", 0, 0, false
	}
	secretVal, ok := totpData["secret"].(string)
	if !ok || secretVal == "" {
		return "", "", 0, 0, false
	}
	algorithm = defaultTOTPAlgorithm
	if v, ok := totpData["algorithm"].(string); ok && v != "" {
		algorithm = v
	}
	digits = 6
	if v, ok := totpData["digits"].(float64); ok {
		digits = int(v)
	}
	period = 30
	if v, ok := totpData["period"].(float64); ok {
		period = int(v)
	}
	return secretVal, algorithm, digits, period, true
}

// GetField retrieves a field value from the entry data map.
func (e *Entry) GetField(name string) (any, bool) {
	if e.Data == nil {
		return nil, false
	}
	val, ok := e.Data[name]
	return val, ok
}

// fieldString converts a Data field value to a string representation.
func fieldString(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return fmt.Sprint(v)
	}
}

// FieldUntrusted returns a field value wrapped as taint.Untrusted with provenance tracking.
func (e *Entry) FieldUntrusted(name string) (taint.Untrusted, bool) {
	val, ok := e.GetField(name)
	if !ok {
		return taint.Untrusted{}, false
	}
	return taint.Wrap(fieldString(val), taint.Provenance{
		Source:    "vault.field",
		EntryPath: e.Path,
		FieldName: name,
	}), true
}

// TagsUntrusted returns all entry tags as Untrusted values with provenance tracking.
func (e *Entry) TagsUntrusted() []taint.Untrusted {
	if len(e.Metadata.Tags) == 0 {
		return []taint.Untrusted{}
	}
	result := make([]taint.Untrusted, len(e.Metadata.Tags))
	for i, tag := range e.Metadata.Tags {
		result[i] = taint.Wrap(tag, taint.Provenance{
			Source:    "vault.tag",
			EntryPath: e.Path,
		})
	}
	return result
}

// UsageHintUntrusted returns the entry UsageHint as an Untrusted value with provenance tracking.
func (e *Entry) UsageHintUntrusted() taint.Untrusted {
	return taint.Wrap(e.SecretMetadata.UsageHint, taint.Provenance{
		Source:    "vault.usage_hint",
		EntryPath: e.Path,
	})
}

// Handles returns a SecretHandle for each field in the entry Data map.
func (e *Entry) Handles(path string) []taint.SecretHandle {
	if len(e.Data) == 0 {
		return nil
	}
	result := make([]taint.SecretHandle, 0, len(e.Data))
	for field := range e.Data {
		result = append(result, taint.SecretHandle{
			Path:  path,
			Field: field,
		})
	}
	return result
}

// SetField sets a field value in the entry data map
func (e *Entry) SetField(name string, value any) {
	if e.Data == nil {
		e.Data = make(map[string]any)
	}
	e.Data[name] = value
}

// HasField checks if a field exists in the entry
func (e *Entry) HasField(name string) bool {
	if e.Data == nil {
		return false
	}
	_, ok := e.Data[name]
	return ok
}

// HashAttachmentSHA256 returns the lowercase hex-encoded SHA-256 digest of
// file content, recorded in AttachmentInfo at add time and re-checked at
// get/use time to detect silent corruption of the stored base64 content.
func HashAttachmentSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
