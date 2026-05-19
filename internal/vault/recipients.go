// Package vault provides recipients.txt management for multi-user encryption support.
// Recipients can be added to enable multiple parties to decrypt vault entries.
package vault

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	"github.com/danieljustus/OpenPass/internal/pathutil"
)

// Common recipients errors
var (
	ErrRecipientAlreadyExists = errors.New("recipient already exists")
	ErrRecipientNotFound      = errors.New("recipient not found")
	ErrInvalidRecipient       = errors.New("invalid recipient")
	ErrEmptyRecipientFile     = errors.New("recipients file is empty")
)

const recipientsFileName = "recipients.txt"

// RecipientsManager handles the recipients.txt file operations
type RecipientsManager struct {
	vaultDir string
}

// NewRecipientsManager creates a new recipients manager for the given vault directory
func NewRecipientsManager(vaultDir string) *RecipientsManager {
	return &RecipientsManager{vaultDir: vaultDir}
}

// validateVaultDir ensures the vault directory path stays within expected bounds.
func (rm *RecipientsManager) validateVaultDir() error {
	if pathutil.HasTraversal(rm.vaultDir) {
		return fmt.Errorf("vault directory path escapes intended directory")
	}
	return nil
}

// RecipientsFilePath returns the full path to the recipients.txt file
func (rm *RecipientsManager) RecipientsFilePath() string {
	return filepath.Join(rm.vaultDir, recipientsFileName)
}

// RecipientsFileExists checks if the recipients.txt file exists
func (rm *RecipientsManager) RecipientsFileExists() bool {
	_, err := os.Stat(rm.RecipientsFilePath())
	return err == nil
}

// LoadRecipients loads all valid recipients from the recipients.txt file.
// Lines starting with # are treated as comments and ignored.
// Empty lines are skipped.
// Returns the list of recipients and any validation errors encountered.
func (rm *RecipientsManager) LoadRecipients() ([]*age.X25519Recipient, error) {
	if err := rm.validateVaultDir(); err != nil {
		return nil, err
	}

	path := rm.RecipientsFilePath()

	// If file doesn't exist, return empty list (no additional recipients)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []*age.X25519Recipient{}, nil
	}

	file, err := os.Open(path) //#nosec G304 -- path is constructed from validated vaultDir via RecipientsFilePath()
	if err != nil {
		return nil, fmt.Errorf("open recipients file: %w", err)
	}
	defer func() { _ = file.Close() }()

	recipients := make([]*age.X25519Recipient, 0, 8)
	var lineNum int
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate and parse recipient
		recipient, err := vaultcrypto.ValidateRecipient(line)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient on line %d: %w", lineNum, err)
		}
		recipients = append(recipients, recipient)
	}

	if sErr := scanner.Err(); sErr != nil {
		return nil, fmt.Errorf("read recipients file: %w", sErr)
	}

	return recipients, nil
}

// LoadRecipientStrings loads all recipient strings from the file without validation.
// Used for listing and management operations.
func (rm *RecipientsManager) LoadRecipientStrings() ([]string, error) {
	if err := rm.validateVaultDir(); err != nil {
		return nil, err
	}

	path := rm.RecipientsFilePath()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []string{}, nil
	}

	data, err := os.ReadFile(path) //#nosec G304 -- path is constructed from validated vaultDir via RecipientsFilePath()
	if err != nil {
		return nil, fmt.Errorf("read recipients file: %w", err)
	}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		// Preserve original line but skip empty and comments for the list
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			lines = append(lines, trimmed)
		}
	}

	return lines, nil
}

// AddRecipient adds a new recipient to the recipients.txt file.
// Validates the recipient format before adding.
// Returns ErrRecipientAlreadyExists if the recipient is already in the file.
func (rm *RecipientsManager) AddRecipient(recipientStr string) error {
	if err := rm.validateVaultDir(); err != nil {
		return err
	}

	// Validate the recipient format
	recipient, err := vaultcrypto.ValidateRecipient(recipientStr)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRecipient, err)
	}

	path := rm.RecipientsFilePath()

	// Check if recipient already exists
	existing, err := rm.LoadRecipientStrings()
	if err != nil {
		return err
	}

	recipientStr = recipient.String() // Normalize the format
	for _, r := range existing {
		if r == recipientStr {
			return ErrRecipientAlreadyExists
		}
	}

	// Create file if it doesn't exist, or append to existing
	flags := os.O_APPEND | os.O_WRONLY | os.O_CREATE
	file, err := os.OpenFile(path, flags, 0o600) //#nosec G304 -- path is constructed from validated vaultDir via RecipientsFilePath()
	if err != nil {
		return fmt.Errorf("open recipients file for writing: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Add newline if file is not empty and doesn't end with newline
	if len(existing) > 0 {
		stat, err := file.Stat()
		if err != nil {
			return fmt.Errorf("stat recipients file: %w", err)
		}
		if stat.Size() > 0 {
			// Check if file ends with newline
			buf := make([]byte, 1)
			_, err := file.ReadAt(buf, stat.Size()-1)
			if err == nil && buf[0] != '\n' {
				if _, err := file.WriteString("\n"); err != nil {
					return fmt.Errorf("write newline: %w", err)
				}
			}
		}
	}

	// Write the new recipient
	if _, err := file.WriteString(recipientStr + "\n"); err != nil {
		return fmt.Errorf("write recipient: %w", err)
	}

	return nil
}

// RemoveRecipient removes a recipient from the recipients.txt file.
// Returns ErrRecipientNotFound if the recipient is not in the file.
func (rm *RecipientsManager) RemoveRecipient(recipientStr string) error {
	if err := rm.validateVaultDir(); err != nil {
		return err
	}

	// Normalize the recipient string for comparison
	recipient, err := vaultcrypto.ValidateRecipient(recipientStr)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRecipient, err)
	}
	recipientStr = recipient.String()

	path := rm.RecipientsFilePath()

	// Check if file exists
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return ErrRecipientNotFound
	}

	// Read all lines
	data, err := os.ReadFile(path) //#nosec G304 -- path is constructed from validated vaultDir via RecipientsFilePath()
	if err != nil {
		return fmt.Errorf("read recipients file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	newLines := make([]string, 0, len(lines))
	found := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Keep comments, empty lines, and non-matching recipients
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			newLines = append(newLines, line)
			continue
		}

		// Parse and compare
		r, err := vaultcrypto.ValidateRecipient(trimmed)
		if err != nil {
			// Keep invalid lines (they might be comments or other metadata)
			newLines = append(newLines, line)
			continue
		}

		if r.String() == recipientStr {
			found = true
			// Skip this line (remove it)
			continue
		}
		newLines = append(newLines, line)
	}

	if !found {
		return ErrRecipientNotFound
	}

	// Write back
	output := strings.Join(newLines, "\n")
	// Symlink-hardened write: prevents writing through symlinks
	if err := SafeWriteFile(path, []byte(output), 0o600); err != nil {
		return fmt.Errorf("write recipients file: %w", err)
	}

	return nil
}

// ListRecipients returns a list of all recipients with their line numbers.
// Useful for displaying to users.
func (rm *RecipientsManager) ListRecipients() ([]RecipientInfo, error) {
	if err := rm.validateVaultDir(); err != nil {
		return nil, err
	}

	path := rm.RecipientsFilePath()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []RecipientInfo{}, nil
	}

	data, err := os.ReadFile(path) //#nosec G304 -- path is constructed from validated vaultDir via RecipientsFilePath()
	if err != nil {
		return nil, fmt.Errorf("read recipients file: %w", err)
	}

	recipients := make([]RecipientInfo, 0, 8)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		info := RecipientInfo{
			LineNumber: lineNum,
			RawString:  trimmed,
		}

		// Try to validate
		if recipient, err := vaultcrypto.ValidateRecipient(trimmed); err == nil {
			info.Valid = true
			info.Normalized = recipient.String()
		} else {
			info.Valid = false
			info.Error = err.Error()
		}

		recipients = append(recipients, info)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan recipients file: %w", err)
	}

	return recipients, nil
}

// RecipientInfo contains information about a recipient entry
type RecipientInfo struct {
	RawString  string
	Normalized string
	Error      string
	LineNumber int
	Valid      bool
}

// GetAllRecipientsForEncryption returns all recipients that should be used for encryption.
// This includes the vault's own recipient plus all recipients from the recipients.txt file.
func (v *Vault) GetAllRecipientsForEncryption() ([]*age.X25519Recipient, error) {
	if v.Identity == nil {
		return nil, ErrNilIdentity
	}

	// Start with the vault's own recipient
	allRecipients := []*age.X25519Recipient{v.Identity.Recipient()}

	// Load additional recipients from file
	rm := NewRecipientsManager(v.Dir)
	additionalRecipients, err := rm.LoadRecipients()
	if err != nil {
		return nil, fmt.Errorf("load additional recipients: %w", err)
	}

	// Add unique additional recipients
	seen := map[string]bool{v.Identity.Recipient().String(): true}
	for _, r := range additionalRecipients {
		if !seen[r.String()] {
			allRecipients = append(allRecipients, r)
			seen[r.String()] = true
		}
	}

	return allRecipients, nil
}

// WriteEntryWithRecipients encrypts and writes an entry to the vault,
// encrypting for all recipients including those in recipients.txt
func WriteEntryWithRecipients(vaultDir, path string, entry *Entry, identity *age.X25519Identity) error {
	if entry == nil {
		return errors.New("nil entry")
	}
	if identity == nil {
		return errors.New("nil identity")
	}

	if err := validateEntryPath(vaultDir, path); err != nil {
		return err
	}

	// Load vault to access recipients
	v := &Vault{Dir: vaultDir, Identity: identity}
	recipients, err := v.GetAllRecipientsForEncryption()
	if err != nil {
		return fmt.Errorf("get recipients: %w", err)
	}

	cfg, err := loadVaultConfig(vaultDir)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	copyEntry := cloneEntry(entry)
	if copyEntry.Metadata.Created.IsZero() {
		copyEntry.Metadata.Created = now
	}
	copyEntry.Metadata.Updated = now
	copyEntry.Metadata.Version++
	if copyEntry.Data == nil {
		copyEntry.Data = map[string]any{}
	}
	if copyEntry.PendingWrite != nil {
		record := *copyEntry.PendingWrite
		record.Timestamp = now
		copyEntry.Metadata.WriteHistory = append(copyEntry.Metadata.WriteHistory, record)
		copyEntry.PendingWrite = nil
	}

	if isPseudonymizeEnabled(cfg) {
		copyEntry.Path = path
	}

	plaintext, err := json.Marshal(copyEntry)
	if err != nil {
		return err
	}

	// Encrypt for all recipients
	ciphertext, err := vaultcrypto.EncryptWithRecipients(plaintext, recipients...)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	filePath := entryStoragePath(vaultDir, path, identity, cfg)
	// Symlink-hardened mkdir: validates each component to prevent following symlinks
	if err := SafeMkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return err
	}
	// Symlink-hardened write: O_NOFOLLOW + fstat verification prevents writing through symlinks
	if err := SafeWriteFile(filePath, ciphertext, 0o600); err != nil {
		return err
	}
	if err := queueManifestUpdate(vaultDir, path, ciphertext, identity); err != nil {
		return err
	}
	return nil
}

// MergeEntryWithRecipients merges partial data into an existing entry, encrypting for all recipients
func MergeEntryWithRecipients(vaultDir, path string, partialData map[string]any, identity *age.X25519Identity) (*Entry, error) {
	entry, err := ReadEntry(vaultDir, path, identity)
	if err != nil {
		return nil, err
	}
	if entry.Data == nil {
		entry.Data = map[string]any{}
	}
	mergeMaps(entry.Data, partialData)
	// Tag injection: assess password strength when password is updated
	tagEntryForWeakPassword(entry, partialData)
	if err := WriteEntryWithRecipients(vaultDir, path, entry, identity); err != nil {
		return nil, err
	}
	return ReadEntry(vaultDir, path, identity)
}

// tagEntryForWeakPassword checks if the password in partialData is weak and
// adds/removes the "weak-password" tag accordingly. Only acts when partialData
// contains a "password" key, since other field changes don't affect password strength.
func tagEntryForWeakPassword(entry *Entry, partialData map[string]any) {
	pwd, ok := partialData["password"]
	if !ok {
		return
	}
	pwdStr, ok := pwd.(string)
	if !ok {
		return
	}
	if pwdStr == "" {
		// Password was cleared — remove stale tag if present.
		entry.RemoveTag(TagWeakPassword)
		return
	}
	s := vaultcrypto.AssessPasswordStrength(pwdStr)
	if s.Weak {
		entry.AddTag(TagWeakPassword)
	} else {
		entry.RemoveTag(TagWeakPassword)
	}
}
