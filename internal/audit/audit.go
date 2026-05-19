// Package audit provides audit logging for MCP tool calls.
package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	vaultcrypto "github.com/danieljustus/OpenPass/internal/crypto"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

const (
	defaultDirName         = ".openpass"
	defaultFileNamePattern = "audit-%s.log"
	hmacKeyFileName        = "audit-hmac-key"
	hmacKeySize            = 32
	hexHMACSize            = sha256.Size * 2 // 64 hex chars
)

// Environment variable names for audit configuration
const (
	envMaxSizeMB  = "OPENPASS_AUDIT_MAX_SIZE_MB"
	envMaxBackups = "OPENPASS_AUDIT_MAX_BACKUPS"
	envMaxAgeDays = "OPENPASS_AUDIT_MAX_AGE_DAYS"
)

// Config holds the configuration for audit log rotation.
type Config struct {
	MaxFileSize int64
	MaxBackups  int
	MaxAgeDays  int
}

// config holds the parsed audit configuration.
var config = parseAuditConfig(nil)

// SetConfig overrides the global audit configuration with values from config.yaml.
// Environment variables still take precedence over config file values.
func SetConfig(cfg *Config) {
	config = parseAuditConfig(cfg)
}

// ReloadConfig re-parses configuration from environment variables.
// Exported for testing purposes.
func ReloadConfig() {
	config = parseAuditConfig(nil)
}

// GetConfig returns the current audit configuration.
func GetConfig() Config {
	return config
}

func parseAuditConfig(base *Config) Config {
	cfg := Config{
		MaxFileSize: 100 * 1024 * 1024,
		MaxBackups:  5,
		MaxAgeDays:  30,
	}

	if base != nil {
		cfg.MaxFileSize = base.MaxFileSize
		cfg.MaxBackups = base.MaxBackups
		cfg.MaxAgeDays = base.MaxAgeDays
	}

	if val := os.Getenv(envMaxSizeMB); val != "" {
		if mb, err := strconv.ParseInt(val, 10, 64); err == nil && mb >= 0 {
			cfg.MaxFileSize = mb * 1024 * 1024
		}
	}

	if val := os.Getenv(envMaxBackups); val != "" {
		if backups, err := strconv.Atoi(val); err == nil && backups >= 0 {
			cfg.MaxBackups = backups
		}
	}

	if val := os.Getenv(envMaxAgeDays); val != "" {
		if days, err := strconv.Atoi(val); err == nil && days >= 0 {
			cfg.MaxAgeDays = days
		}
	}

	return cfg
}

// HealthStatus represents the health status of audit logging.
type HealthStatus struct {
	LogFilePath     string `json:"log_file_path"`
	LogFileAge      string `json:"log_file_age"`
	LastEntryTime   string `json:"last_entry_time,omitempty"`
	Agent           string `json:"agent"`
	TotalAuditSize  int64  `json:"total_audit_size_bytes"`
	LogFileSize     int64  `json:"log_file_size_bytes"`
	ErrorCount      int    `json:"error_count_last_100"`
	LastEntryOK     *bool  `json:"last_entry_ok,omitempty"`
	OK              bool   `json:"ok"`
	WriteAccessible bool   `json:"write_accessible"`
	NeedsRotation   bool   `json:"needs_rotation"`
	NeedsRetention  bool   `json:"needs_retention"`
}

// ErrorInfo represents a redacted error from audit logs.
type ErrorInfo struct {
	Timestamp string `json:"ts"`
	Action    string `json:"action"`
	Reason    string `json:"reason,omitempty"`
	OK        bool   `json:"ok"`
}

type LogEntry struct {
	Timestamp   string `json:"ts"`
	Agent       string `json:"agent"`
	Action      string `json:"action"`
	Path        string `json:"path,omitempty"`
	Field       string `json:"field,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ShareID     string `json:"share_id,omitempty"`
	FromAgent   string `json:"from_agent,omitempty"`
	ToAgent     string `json:"to_agent,omitempty"`
	ShareAction string `json:"share_action,omitempty"`
	DurMs       int64  `json:"dur_ms,omitempty"`
	TokenID     string `json:"token_id,omitempty"`
	RequestID   string `json:"req_id,omitempty"`
	SessionID   string `json:"sess_id,omitempty"`
	HMAC        string `json:"hmac,omitempty"`
	OK          bool   `json:"ok"`
}

// VerifyResult reports the outcome of audit log integrity verification.
type VerifyResult struct {
	Valid       bool
	Total       int
	Verified    int
	Legacy      int
	Tampered    int
	FirstBadIdx int
}

type Logger struct {
	agentName string
	path      string
	file      *os.File
	mu        sync.Mutex
	hmacKey   []byte
	prevHMAC  []byte
}

func New(agentName string, vaultDir string) (*Logger, error) {
	if strings.Contains(agentName, "/") || strings.Contains(agentName, "\\") || agentName == ".." || agentName == "." {
		return nil, errors.New("agent name must not contain path separators or traversal patterns")
	}
	if strings.Contains(agentName, "..") {
		return nil, errors.New("agent name must not contain path traversal patterns")
	}

	var auditDir string
	if vaultDir != "" {
		cleanVaultDir := filepath.Clean(vaultDir)
		info, err := os.Stat(cleanVaultDir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("vault directory does not exist: %s", cleanVaultDir)
		}
		auditDir = cleanVaultDir
	} else {
		home := os.Getenv("HOME")
		if home == "" {
			resolved, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			home = resolved
		}
		cleanHome := filepath.Clean(home)
		auditDir = filepath.Join(cleanHome, defaultDirName)
	}

	cleanAuditDir := filepath.Clean(auditDir)
	if err := os.MkdirAll(cleanAuditDir, 0o700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	path := filepath.Join(cleanAuditDir, fmt.Sprintf(defaultFileNamePattern, agentName))
	cleanPath := filepath.Clean(path)
	if !strings.HasPrefix(cleanPath, cleanAuditDir+string(filepath.Separator)) && cleanPath != cleanAuditDir {
		return nil, errors.New("agent name resulted in path outside audit directory")
	}

	file, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // path is validated above
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	ks := NewKeystore(cleanAuditDir, vaultpkg.CurrentSearchIdentity())
	hmacKey, err := ks.LoadOrCreateHMACKey()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("load hmac key: %w", err)
	}

	l := &Logger{
		file:      file,
		agentName: agentName,
		path:      cleanPath,
		hmacKey:   hmacKey,
	}

	if rotErr := l.rotateIfNeeded(); rotErr != nil {
		_ = l.Close()
		return nil, fmt.Errorf("check rotation: %w", rotErr)
	}

	prevHMAC, err := l.readLastHMAC()
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("read last hmac: %w", err)
	}
	l.prevHMAC = prevHMAC

	return l, nil
}

func (l *Logger) LogEntry(entry LogEntry) error {
	if l == nil || l.file == nil {
		return nil
	}

	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.hmacKey) > 0 {
		entry.HMAC = computeHMAC(l.hmacKey, l.prevHMAC, entry)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		return err
	}

	if entry.HMAC != "" {
		if prevBytes, derr := hex.DecodeString(entry.HMAC); derr == nil {
			l.prevHMAC = prevBytes
		}
	}

	if err := l.file.Sync(); err != nil {
		return err
	}

	return nil
}

func (l *Logger) rotateIfNeeded() error {
	if l == nil || l.file == nil {
		return nil
	}

	info, err := l.file.Stat()
	if err != nil {
		return err
	}

	needsRotation := info.Size() >= config.MaxFileSize

	if !needsRotation {
		age := time.Since(info.ModTime())
		maxFileAge := time.Duration(config.MaxAgeDays) * 24 * time.Hour
		needsRotation = age >= maxFileAge
	}

	if !needsRotation {
		return nil
	}

	_ = l.file.Close()

	rotatePath := l.path + ".rotated." + time.Now().UTC().Format("20060102-150405")
	if renameErr := os.Rename(l.path, rotatePath); renameErr != nil {
		reopenedFile, reopenErr := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if reopenErr != nil {
			return fmt.Errorf("rename and reopen: rename=%w reopen=%w", renameErr, reopenErr)
		}
		l.file = reopenedFile
		return fmt.Errorf("rotate log: %w", renameErr)
	}

	l.file, err = os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("reopen after rotation: %w", err)
	}

	return nil
}

// EnforceRetention removes old rotated files based on retention policy:
// - Removes oldest files if count exceeds MaxBackups
// - Removes files older than MaxAgeDays
func (l *Logger) EnforceRetention() error {
	if l == nil {
		return errors.New("logger is nil")
	}

	auditDir := filepath.Dir(l.path)
	pattern := filepath.Join(auditDir, fmt.Sprintf(defaultFileNamePattern, l.agentName)+".rotated.*")

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob rotated files: %w", err)
	}

	var rotatedFiles []os.FileInfo
	now := time.Now()
	maxAge := time.Duration(config.MaxAgeDays) * 24 * time.Hour

	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		rotatedFiles = append(rotatedFiles, info)
	}

	if len(rotatedFiles) == 0 {
		return nil
	}

	// Sort by modification time, oldest first
	for i := 0; i < len(rotatedFiles)-1; i++ {
		for j := i + 1; j < len(rotatedFiles); j++ {
			if rotatedFiles[i].ModTime().After(rotatedFiles[j].ModTime()) {
				rotatedFiles[i], rotatedFiles[j] = rotatedFiles[j], rotatedFiles[i]
			}
		}
	}

	// Check max backups policy - keep at most MaxBackups files
	backupsToDelete := len(rotatedFiles) - config.MaxBackups
	if backupsToDelete > 0 {
		for i := 0; i < backupsToDelete; i++ {
			info := rotatedFiles[i]
			path := filepath.Join(auditDir, info.Name())
			if err := os.Remove(path); err != nil {
				continue
			}
		}
		rotatedFiles = rotatedFiles[backupsToDelete:]
	}

	// Check max age policy - remove files older than MaxAgeDays
	for _, info := range rotatedFiles {
		age := now.Sub(info.ModTime())
		if age >= maxAge {
			path := filepath.Join(auditDir, info.Name())
			if err := os.Remove(path); err != nil {
				continue
			}
		}
	}

	return nil
}

// HealthCheck returns the health status of the audit logger.
func (l *Logger) HealthCheck() (*HealthStatus, error) {
	if l == nil || l.file == nil {
		return &HealthStatus{OK: false}, errors.New("logger not initialized")
	}

	status := &HealthStatus{
		OK:          true,
		Agent:       l.agentName,
		LogFilePath: l.path,
	}

	info, err := l.file.Stat()
	if err != nil {
		status.OK = false
		status.WriteAccessible = false
		return status, fmt.Errorf("stat log file: %w", err)
	}

	status.LogFileSize = info.Size()
	status.LogFileAge = time.Since(info.ModTime()).Round(time.Second).String()
	status.WriteAccessible = info.Mode().Perm()&0200 != 0

	maxFileAge := time.Duration(config.MaxAgeDays) * 24 * time.Hour
	if info.Size() >= config.MaxFileSize || status.LogFileAge >= maxFileAge.String() {
		status.NeedsRotation = true
	}

	// Check total audit size across all files in directory
	auditDir := filepath.Dir(l.path)
	pattern := filepath.Join(auditDir, fmt.Sprintf(defaultFileNamePattern, l.agentName)+"*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		// Log error but continue with what we have
		fmt.Fprintf(os.Stderr, "failed to glob audit files: %v\n", err)
	}
	for _, path := range matches {
		if info, statErr := os.Stat(path); statErr == nil {
			status.TotalAuditSize += info.Size()
		}
	}
	if status.TotalAuditSize >= config.MaxFileSize {
		status.NeedsRetention = true
	}

	// Read last 100 entries to get error count and last entry
	last100, err := l.lastNEntries(100)
	if err == nil {
		for _, entry := range last100 {
			if !entry.OK {
				status.ErrorCount++
			}
			status.LastEntryTime = entry.Timestamp
			ok := entry.OK
			status.LastEntryOK = &ok
		}
	}

	return status, nil
}

func (l *Logger) lastNEntries(n int) ([]LogEntry, error) {
	if l == nil || l.file == nil {
		return nil, errors.New("logger not initialized")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	_, err := l.file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}

	info, err := l.file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := info.Size()
	if fileSize == 0 {
		return nil, nil
	}

	// Read file content into memory for parsing (avoids bad file descriptor with O_APPEND)
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, err
	}

	var entries []LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Split(scanLines)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			entries = append(entries, entry)
			if len(entries) > n {
				entries = entries[len(entries)-n:]
			}
		}
	}

	return entries, nil
}

func scanLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := strings.Index(string(data), "\n"); i >= 0 {
		return i + 1, data[0:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// GetErrors returns redacted error entries from the audit log.
func (l *Logger) GetErrors(limit int) ([]ErrorInfo, error) {
	entries, err := l.lastNEntries(limit)
	if err != nil {
		return nil, err
	}

	var errors []ErrorInfo
	for _, entry := range entries {
		if !entry.OK {
			errors = append(errors, ErrorInfo{
				Timestamp: entry.Timestamp,
				Action:    entry.Action,
				Reason:    entry.Reason,
				OK:        entry.OK,
			})
		}
	}

	return errors, nil
}

func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.file.Close()
	vaultcrypto.Wipe(l.hmacKey)
	vaultcrypto.Wipe(l.prevHMAC)
	l.hmacKey = nil
	l.prevHMAC = nil
	return err
}

func (l *Logger) readLastHMAC() ([]byte, error) {
	if l == nil || l.file == nil {
		return nil, nil
	}

	info, err := l.file.Stat()
	if err != nil {
		return nil, nil
	}
	if info.Size() == 0 {
		return nil, nil
	}

	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, nil
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lastLine := lines[len(lines)-1]
	if lastLine == "" && len(lines) > 1 {
		lastLine = lines[len(lines)-2]
	}

	var lastEntry LogEntry
	if err := json.Unmarshal([]byte(lastLine), &lastEntry); err != nil {
		return nil, nil
	}

	if lastEntry.HMAC != "" {
		return hex.DecodeString(lastEntry.HMAC)
	}
	return nil, nil
}

func computeHMAC(key, prevHMAC []byte, entry LogEntry) string {
	canonical := canonicalJSON(entry)
	mac := hmac.New(sha256.New, key)
	if len(prevHMAC) > 0 {
		mac.Write(prevHMAC)
	}
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalJSON(entry LogEntry) []byte {
	entry.HMAC = ""
	data, err := json.Marshal(entry)
	if err != nil {
		return nil
	}
	return data
}

func VerifyLog(logFilePath string, key []byte) (*VerifyResult, error) {
	if len(key) == 0 {
		return nil, errors.New("hmac key is empty")
	}

	data, err := os.ReadFile(logFilePath) //#nosec G304 -- logFilePath is provided by the caller and expected to be a trusted audit log path
	if err != nil {
		return nil, fmt.Errorf("read log file: %w", err)
	}

	var entries []LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	result := &VerifyResult{
		Total:       len(entries),
		Valid:       true,
		FirstBadIdx: -1,
	}

	var prevHMAC []byte
	for i, entry := range entries {
		if entry.HMAC == "" {
			result.Legacy++
			prevHMAC = nil
			continue
		}

		expectedHMAC := computeHMAC(key, prevHMAC, entry)
		entryHMACBytes, decodeErr := hex.DecodeString(entry.HMAC)
		expectedHMACBytes, decodeExpectedErr := hex.DecodeString(expectedHMAC)
		if decodeErr != nil || decodeExpectedErr != nil || !hmac.Equal(expectedHMACBytes, entryHMACBytes) {
			result.Tampered++
			result.Valid = false
			if result.FirstBadIdx < 0 {
				result.FirstBadIdx = i
			}
		} else {
			result.Verified++
			prevHMAC = entryHMACBytes
		}
	}

	if result.Total == 0 {
		result.Valid = true
	}

	return result, nil
}

func (l *Logger) Verify() (*VerifyResult, error) {
	if l == nil {
		return nil, errors.New("logger is nil")
	}
	return VerifyLog(l.path, l.hmacKey)
}
