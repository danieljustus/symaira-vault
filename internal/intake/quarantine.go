package intake

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/vault"
)

// Vault is the minimal vault surface intake needs to write quarantined
// batches and detect duplicates. The CLI's VaultService satisfies it.
type Vault interface {
	GetEntry(entryPath string) (*vault.Entry, error)
	WriteEntry(entryPath string, entry *vault.Entry) error
	ListEntries(prefix string) ([]string, error)
}

// BatchOptions controls the quarantined batch write.
type BatchOptions struct {
	// ImportID is the quarantine batch id; entries land under
	// quarantine/<ImportID>/. Empty generates one.
	ImportID string
	// DryRun reports what would be written without writing.
	DryRun bool
}

// WriteBatch writes the successfully processed files into a quarantined
// review batch under quarantine/<import-id>/. It never writes to normal vault
// paths, never overwrites an existing entry, and never deletes source files.
// Source bytes are stored exactly as an encrypted base64 attachment with
// verified provenance; suggestions become structured fields (values capped
// at the vault's field-length limits).
//
// It returns the import ID and the list of quarantine entry paths written.
func WriteBatch(v Vault, results []FileResult, opts BatchOptions) (string, []string, error) {
	importID := opts.ImportID
	if importID == "" {
		importID = GenerateImportID()
	}
	prefix := "quarantine/" + importID + "/"

	var written []string
	for i := range results {
		r := &results[i]
		if r.Status != StatusOK || r.spoolPath == "" {
			continue
		}
		bytes, err := os.ReadFile(r.spoolPath) // #nosec G304 -- staged spool copy created by intake
		if err != nil {
			return "", nil, fmt.Errorf("read staged copy for %q: %w", r.File, err)
		}
		if HashSHA256(bytes) != r.Provenance.SHA256 {
			return "", nil, fmt.Errorf("staged copy hash mismatch for %q before write", r.File)
		}

		entryPath := proposalPath(prefix, r.Provenance.SourceName)
		exists, err := entryExists(v, entryPath)
		if err != nil {
			return "", nil, err
		}
		if exists {
			r.Status = StatusSkipped
			r.Reason = "quarantine entry already exists: " + entryPath
			continue
		}

		// Duplicate source-hash detection: the same bytes must not be
		// quarantined twice without an explicit review decision.
		dupes, err := findDuplicateHashes(v, r.Provenance.SHA256)
		if err != nil {
			return "", nil, err
		}
		if len(dupes) > 0 {
			r.Status = StatusSkipped
			r.Reason = "duplicate source hash already quarantined"
			r.Duplicates = dupes
			continue
		}

		if opts.DryRun {
			r.Status = StatusOK
			continue
		}

		entry := &vault.Entry{Data: map[string]any{}}
		entry.SecretMetadata.Attachments = map[string]vault.AttachmentInfo{}

		// Structured field suggestions (never the attachment itself).
		for _, sug := range r.raw {
			if sug.Attachment || sug.Field == AttachmentField {
				continue
			}
			if sug.Value == "" || len(sug.Value) > 4096 {
				continue
			}
			if _, ok := entry.Data[sug.Field]; ok {
				continue
			}
			entry.Data[sug.Field] = sug.Value
		}
		// Exact source bytes as encrypted attachment.
		entry.Data[AttachmentField] = base64.StdEncoding.EncodeToString(bytes)
		entry.SecretMetadata.Attachments[AttachmentField] = vault.AttachmentInfo{
			Filename: r.Provenance.SourceName,
			Size:     r.Provenance.Size,
			SHA256:   r.Provenance.SHA256,
		}
		now := time.Now().UTC()
		entry.Metadata.Created = now
		entry.Metadata.Updated = now
		entry.Metadata.Version = 1

		if err := v.WriteEntry(entryPath, entry); err != nil {
			return "", nil, fmt.Errorf("write quarantine entry %q: %w", entryPath, err)
		}
		written = append(written, entryPath)
	}
	return importID, written, nil
}

// proposalPath derives a safe quarantine entry path from the source name.
// Only the sanitized base name is used, so a hostile filename cannot escape
// the quarantine prefix. Collisions with live vault entries are detected in
// WriteBatch (entryExists) and skipped, never overwritten.
func proposalPath(prefix, sourceName string) string {
	return path.Join(prefix, ProposedEntryPath(sourceName))
}

// GenerateImportID produces a short unique quarantine batch id.
func GenerateImportID() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("intake-%s-%d", time.Now().UTC().Format("20060102"), time.Now().UnixNano()%0x100000000)
	}
	return fmt.Sprintf("intake-%s-%x", time.Now().UTC().Format("20060102"), buf)
}

// findDuplicateHashes scans the quarantine prefix for an existing attachment
// with the same SHA-256, so identical source material is never staged twice
// without an explicit review decision.
func findDuplicateHashes(v Vault, sha string) ([]string, error) {
	paths, err := v.ListEntries("quarantine/")
	if err != nil {
		return nil, err
	}
	var dupes []string
	for _, p := range paths {
		e, err := v.GetEntry(p)
		if err != nil {
			continue
		}
		for _, att := range e.SecretMetadata.Attachments {
			if att.SHA256 == sha {
				dupes = append(dupes, p)
			}
		}
	}
	return dupes, nil
}

// entryExists reports whether a vault entry exists at path (404 semantics).
func entryExists(v Vault, entryPath string) (bool, error) {
	_, err := v.GetEntry(entryPath)
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, err
}

// isNotFound recognizes vault not-found errors without depending on the CLI
// error package: os.ErrNotExist semantics plus a message fallback.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") || strings.Contains(msg, "does not exist")
}
