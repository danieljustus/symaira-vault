// Package intake implements review-gated local credential intake for loose
// credential material (text files, JSON exports, screenshots, certificate
// files, backup-code images). It validates source files, copies them into a
// private spool, sniffs content, derives field/attachment suggestions, and
// writes quarantined review batches — never authoritative vault entries.
//
// The package is intentionally standalone: it does not depend on the CLI
// layer, so the core contract can be reused by the macOS client and the
// consume-folder watcher later.
package intake

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Default limits. Per-file and batch limits are hard caps that keep spool and
// vault entries sane by default; callers may raise them explicitly.
const (
	// DefaultMaxFileSize caps a single intake source file (1 MiB, matching
	// the `file add` attachment default).
	DefaultMaxFileSize int64 = 1 << 20
	// DefaultMaxBatchSize caps the total bytes of one intake invocation.
	DefaultMaxBatchSize int64 = 32 << 20
	// DefaultMaxFiles caps the number of files per intake invocation.
	DefaultMaxFiles = 100
	// AttachmentField is the default entry field name under which the exact
	// source bytes are stored as an encrypted base64 attachment.
	AttachmentField = "attachment"
)

// SourceType classifies the sniffed content of an intake source file.
type SourceType string

const (
	SourceTypeText    SourceType = "text"
	SourceTypeEnv     SourceType = "env"
	SourceTypeJSON    SourceType = "json"
	SourceTypeCert    SourceType = "certificate"
	SourceTypeKey     SourceType = "key"
	SourceTypeImage   SourceType = "image"
	SourceTypePDF     SourceType = "pdf"
	SourceTypeArchive SourceType = "archive"
	SourceTypeOther   SourceType = "other"
)

// Provenance records verifiable metadata about the source file. It is the
// only information about the source that may appear in logs, JSON output or
// audit events — never extracted secret values.
type Provenance struct {
	SourcePath string     `json:"source_path"`
	SourceName string     `json:"source_name"`
	SourceType SourceType `json:"source_type"`
	Size       int64      `json:"size"`
	SHA256     string     `json:"sha256"`
	MTime      time.Time  `json:"mtime"`
	SpoolPath  string     `json:"-"`
}

// Suggestion is a proposed (never authoritative) mapping of parsed source
// content to a vault field. Value carries the extracted secret internally;
// it must never be rendered into JSON output, logs or audit events (use
// SanitizedSuggestion for anything user-visible).
type Suggestion struct {
	Path       string  `json:"path"`
	Field      string  `json:"field"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
	Warning    string  `json:"warning,omitempty"`
	Attachment bool    `json:"attachment,omitempty"`
}

// SanitizedSuggestion is the metadata-only view of a Suggestion suitable for
// JSON status output and logs: field names, confidence and warnings, never
// the extracted value.
type SanitizedSuggestion struct {
	Path       string  `json:"path"`
	Field      string  `json:"field"`
	Confidence float64 `json:"confidence"`
	Warning    string  `json:"warning,omitempty"`
	Attachment bool    `json:"attachment,omitempty"`
}

// FileResult is the outcome for one intake source file.
type FileResult struct {
	File        string                `json:"file"`
	Status      string                `json:"status"` // ok | skipped | error
	Reason      string                `json:"reason,omitempty"`
	Provenance  *Provenance           `json:"provenance,omitempty"`
	Suggestions []SanitizedSuggestion `json:"suggestions,omitempty"`
	Duplicates  []string              `json:"duplicates,omitempty"`

	// internal: full suggestions with values, spool path and source bytes
	// reference, used by WriteBatch. Never serialized.
	raw         []Suggestion
	spoolPath   string
	sourceBytes []byte
}

// Options controls one intake run.
type Options struct {
	DryRun       bool
	MaxFileSize  int64
	MaxBatchSize int64
	MaxFiles     int
}

// DefaultOptions returns the standard limits.
func DefaultOptions() Options {
	return Options{
		MaxFileSize:  DefaultMaxFileSize,
		MaxBatchSize: DefaultMaxBatchSize,
		MaxFiles:     DefaultMaxFiles,
	}
}

// ValidateRegularFile rejects anything that is not a stable regular file:
// symlinks, directories, devices, sockets, FIFOs and files that change size
// or mtime while being read. It returns the file info on success.
func ValidateRegularFile(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("reject %q: symlinks are not accepted", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("reject %q: not a regular file (type %s)", path, fi.Mode().Type())
	}
	return fi, nil
}

// readBounded reads the file at path (after validation), enforcing the
// per-file size limit, and verifies the file did not change during the read
// (stable size and mtime) so a source cannot be swapped mid-intake.
func readBounded(path string, limit int64) ([]byte, os.FileInfo, error) {
	before, err := ValidateRegularFile(path)
	if err != nil {
		return nil, nil, err
	}
	if before.Size() > limit {
		return nil, nil, fmt.Errorf("reject %q: %d bytes exceeds the %d byte per-file limit", path, before.Size(), limit)
	}
	f, err := os.Open(path) // #nosec G304 -- intake source is an explicit user-supplied CLI argument
	if err != nil {
		return nil, nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	data := make([]byte, limit+1)
	n, err := f.Read(data)
	if err != nil && n == 0 {
		return nil, nil, fmt.Errorf("read %q: %w", path, err)
	}
	data = data[:n]
	if int64(n) > limit {
		return nil, nil, fmt.Errorf("reject %q: file exceeds the %d byte per-file limit", path, limit)
	}
	after, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("re-stat %q: %w", path, err)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, nil, fmt.Errorf("reject %q: file changed during intake (size/mtime not stable)", path)
	}
	return data, after, nil
}

// HashSHA256 returns the lowercase hex SHA-256 of data.
func HashSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ProposedEntryPath derives a safe quarantine entry path from the source file
// name. It uses only the base name, strips common extensions, and sanitizes
// characters that are invalid in vault entry paths, so a hostile filename
// cannot escape the quarantine prefix or inject path segments.
func ProposedEntryPath(sourceName string) string {
	base := filepath.Base(sourceName)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"..", "_",
		" ", "_",
	)
	base = replacer.Replace(base)
	base = strings.Trim(base, "._")
	if base == "" {
		base = "entry"
	}
	return base
}

// Sanitize returns the metadata-only view of s for JSON/log output.
func (s Suggestion) Sanitize() SanitizedSuggestion {
	return SanitizedSuggestion{
		Path:       s.Path,
		Field:      s.Field,
		Confidence: s.Confidence,
		Warning:    s.Warning,
		Attachment: s.Attachment,
	}
}

// Sanitized returns the metadata-only FileResult view for JSON/log output.
func (r *FileResult) Sanitized() *FileResult {
	out := *r
	out.raw = nil
	out.spoolPath = ""
	out.sourceBytes = nil
	if out.Suggestions == nil {
		out.Suggestions = []SanitizedSuggestion{}
	}
	return &out
}

// EncodeAttachment base64-encodes the exact source bytes for storage.
func EncodeAttachment(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// ErrSkipped reports a file deliberately excluded from intake (unsupported
// type, over-limit, duplicate). It carries a user-facing reason.
type ErrSkipped struct{ Reason string }

func (e *ErrSkipped) Error() string { return e.Reason }

// IsSkipped reports whether err is a deliberate intake skip.
func IsSkipped(err error) bool {
	var s *ErrSkipped
	return errors.As(err, &s)
}
