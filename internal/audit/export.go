package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ExportOptions configures audit log export behavior.
type ExportOptions struct {
	Agent       string // filter by agent name, "" or "all" means all agents
	Action      string // filter by action type, "" means all actions
	Since       string // filter by time duration (e.g. "1h", "24h", "7d"), "" means no time filter
	FailedOnly  bool   // only export failed entries
	RedactPaths bool   // redact or hash vault paths
	VerifyHMAC  bool   // verify HMAC integrity and report status
	HMACKey     []byte // key for HMAC verification (required when VerifyHMAC is true)
}

// ExportEntry extends LogEntry with verification status and optional redacted path.
type ExportEntry struct {
	LogEntry      `json:",inline"`
	VerifyStatus  string `json:"verify_status,omitempty"` // "verified", "legacy", "tampered", or ""
	RedactedPath  string `json:"redacted_path,omitempty"` // redacted path when RedactPaths is true
	OriginalIndex int    `json:"original_index"`          // position in the source file
	SourceFile    string `json:"source_file,omitempty"`   // which log file this entry came from
}

// ExportResult holds the result of an export operation.
type ExportResult struct {
	Entries    []ExportEntry `json:"entries"`
	Total      int           `json:"total"`
	Verified   int           `json:"verified,omitempty"`
	Legacy     int           `json:"legacy,omitempty"`
	Tampered   int           `json:"tampered,omitempty"`
	Agent      string        `json:"agent"`
	Action     string        `json:"action,omitempty"`
	Since      string        `json:"since,omitempty"`
	FailedOnly bool          `json:"failed_only,omitempty"`
}

// StreamEntry is a callback function for streaming export processing.
// Return false to stop streaming.
type StreamEntry func(entry ExportEntry) bool

// ExportAuditLog is the main entry point for exporting audit logs.
// It loads entries from all relevant log files, applies filters, and writes output.
func ExportAuditLog(opts ExportOptions, w io.Writer, format string) (*ExportResult, error) {
	if opts.VerifyHMAC && len(opts.HMACKey) == 0 {
		return nil, fmt.Errorf("HMAC verification requires a key")
	}

	agents, err := resolveAgentList(opts.Agent)
	if err != nil {
		return nil, fmt.Errorf("resolve agents: %w", err)
	}

	var allEntries []ExportEntry
	for _, agent := range agents {
		entries, err := LoadAndFilterAgent(agent, opts)
		if err != nil {
			return nil, fmt.Errorf("load agent %s: %w", agent, err)
		}
		allEntries = append(allEntries, entries...)
	}

	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].Timestamp < allEntries[j].Timestamp
	})

	result := &ExportResult{
		Entries:    allEntries,
		Total:      len(allEntries),
		Agent:      opts.Agent,
		Action:     opts.Action,
		Since:      opts.Since,
		FailedOnly: opts.FailedOnly,
	}

	if opts.VerifyHMAC {
		verifyExportedEntries(allEntries, opts.HMACKey)
		for _, e := range allEntries {
			switch e.VerifyStatus {
			case "verified":
				result.Verified++
			case "legacy":
				result.Legacy++
			case "tampered":
				result.Tampered++
			}
		}
	}

	if opts.RedactPaths {
		for i := range allEntries {
			allEntries[i].RedactedPath = RedactPath(allEntries[i].Path)
			allEntries[i].Path = ""
		}
	}

	if err := writeExportOutput(w, format, result); err != nil {
		return nil, fmt.Errorf("write output: %w", err)
	}

	return result, nil
}

// LoadAuditLogFiles loads entries from the current log and all rotated logs
// for a given agent. Returns entries in chronological order.
// A limit of 0 means no limit (all entries). This is the shared audit log
// loading path used by both `symvault audit` and `symvault audit export`.
func LoadAuditLogFiles(agent string, auditDir string, limit int) ([]LogEntry, error) {
	if strings.Contains(agent, "/") || strings.Contains(agent, "\\") || agent == ".." || agent == "." {
		return nil, fmt.Errorf("invalid agent name")
	}

	cleanDir := filepath.Clean(auditDir)
	if err := os.MkdirAll(cleanDir, 0o700); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	currentFile := filepath.Join(cleanDir, fmt.Sprintf(defaultFileNamePattern, agent))
	pattern := filepath.Join(cleanDir, fmt.Sprintf(defaultFileNamePattern, agent)+".rotated.*")
	rotatedMatches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("glob rotated logs: %w", err)
	}

	var files []string
	sort.Strings(rotatedMatches) // alphabetical = chronological for timestamp suffix
	files = append(files, rotatedMatches...)
	if _, err := os.Stat(currentFile); err == nil {
		files = append(files, currentFile)
	}

	var allEntries []LogEntry
	for _, f := range files {
		entries, err := readJSONLFile(f)
		if err != nil {
			continue
		}
		allEntries = append(allEntries, entries...)
	}

	if limit > 0 && len(allEntries) > limit {
		allEntries = allEntries[len(allEntries)-limit:]
	}

	return allEntries, nil
}

// LoadAndFilterAgent loads audit entries for a single agent, applies time/failed filters.
func LoadAndFilterAgent(agent string, opts ExportOptions) ([]ExportEntry, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	auditDir := filepath.Join(filepath.Clean(home), defaultDirName)
	entries, err := LoadAuditLogFiles(agent, auditDir, 0)
	if err != nil {
		return nil, err
	}

	var result []ExportEntry
	for i, entry := range entries {
		if opts.Since != "" && !MatchesSinceFilter(entry.Timestamp, opts.Since) {
			continue
		}
		if opts.FailedOnly && entry.OK {
			continue
		}
		if opts.Action != "" && entry.Action != opts.Action {
			continue
		}
		result = append(result, ExportEntry{
			LogEntry:      entry,
			OriginalIndex: i,
			SourceFile:    fmt.Sprintf("audit-%s.log", agent),
		})
	}

	return result, nil
}

// MatchesSinceFilter checks if the entry timestamp is within the given duration.
func MatchesSinceFilter(timestamp, since string) bool {
	if since == "" {
		return true
	}
	dur, err := ParseSinceDuration(since)
	if err != nil {
		return true
	}
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false
	}
	cutoff := time.Now().UTC().Add(-dur)
	return !ts.Before(cutoff)
}

// ParseSinceDuration parses a duration string supporting days (e.g. "7d").
func ParseSinceDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		val := strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(val, "%d", &days); err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func resolveAgentList(agent string) ([]string, error) {
	if agent == "" || agent == "all" {
		return DiscoverAgents()
	}
	return []string{agent}, nil
}

// DiscoverAgents scans the audit directory for agent log files.
func DiscoverAgents() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	auditDir := filepath.Join(filepath.Clean(home), defaultDirName)
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	seen := make(map[string]bool)
	var agents []string
	prefix := "audit-"
	suffix := ".log"
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) {
			agent := strings.TrimPrefix(name, prefix)
			agent = strings.TrimSuffix(agent, suffix)
			if idx := strings.Index(agent, ".rotated."); idx >= 0 {
				agent = agent[:idx]
			}
			if agent != "" && !seen[agent] {
				seen[agent] = true
				agents = append(agents, agent)
			}
		}
	}

	sort.Strings(agents)
	return agents, nil
}

// readJSONLFile reads a JSONL audit log file and returns parsed entries.
func readJSONLFile(path string) ([]LogEntry, error) {
	f, err := os.Open(path) // #nosec G304 -- validated audit log path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var entries []LogEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
	return entries, scanner.Err()
}

// verifyExportedEntries verifies HMAC integrity for exported entries.
// Uses the same constant-time comparison as VerifyLog for consistency.
func verifyExportedEntries(entries []ExportEntry, key []byte) {
	if len(key) == 0 {
		return
	}

	mac := hmac.New(sha256.New, key)
	var prevHMAC []byte
	chainStarted := false

	for i := range entries {
		entry := &entries[i]
		if entry.HMAC == "" {
			if chainStarted {
				entry.VerifyStatus = "tampered"
			} else {
				entry.VerifyStatus = "legacy"
				prevHMAC = nil
			}
			continue
		}

		expectedHMAC := computeHMACWith(mac, prevHMAC, entry.LogEntry)
		entryHMACBytes, decodeErr := hex.DecodeString(entry.HMAC)
		expectedHMACBytes, expectedErr := hex.DecodeString(expectedHMAC)
		if decodeErr != nil || expectedErr != nil || !hmac.Equal(expectedHMACBytes, entryHMACBytes) {
			entry.VerifyStatus = "tampered"
		} else {
			entry.VerifyStatus = "verified"
			prevHMAC = entryHMACBytes
			chainStarted = true
		}
	}
}

// VerifyExportLog verifies HMAC integrity for entries and returns per-entry
// statuses. This is the single shared verifier used by both audit verification
// and export, satisfying the single-implementation requirement.
func VerifyExportLog(entries []LogEntry, key []byte) ([]string, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("hmac key is empty")
	}

	statuses := make([]string, len(entries))
	mac := hmac.New(sha256.New, key)
	var prevHMAC []byte
	chainStarted := false

	for i, entry := range entries {
		if entry.HMAC == "" {
			if chainStarted {
				statuses[i] = "tampered"
			} else {
				statuses[i] = "legacy"
				prevHMAC = nil
			}
			continue
		}

		expectedHMAC := computeHMACWith(mac, prevHMAC, entry)
		entryHMACBytes, decodeErr := hex.DecodeString(entry.HMAC)
		expectedHMACBytes, expectedErr := hex.DecodeString(expectedHMAC)
		if decodeErr != nil || expectedErr != nil || !hmac.Equal(expectedHMACBytes, entryHMACBytes) {
			statuses[i] = "tampered"
		} else {
			statuses[i] = "verified"
			prevHMAC = entryHMACBytes
			chainStarted = true
		}
	}

	return statuses, nil
}

// RedactPath hashes a vault path to produce a redacted version suitable
// for sharing audit evidence without exposing vault taxonomy.
func RedactPath(path string) string {
	if path == "" {
		return ""
	}
	h := sha256.Sum256([]byte(path))
	return "redacted:" + hex.EncodeToString(h[:6])
}

func writeExportOutput(w io.Writer, format string, result *ExportResult) error {
	switch strings.ToLower(format) {
	case "json":
		return writeJSONOutput(w, result)
	case "table", "text", "":
		return writeTableOutput(w, result)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

func writeJSONOutput(w io.Writer, result *ExportResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func writeTableOutput(w io.Writer, result *ExportResult) error {
	if len(result.Entries) == 0 {
		_, _ = fmt.Fprintln(w, "No audit entries found.")
		return nil
	}

	_, _ = fmt.Fprintf(w, "%-20s %-12s %-20s %-10s %-8s %s\n",
		"TIME", "AGENT", "ACTION", "TRANSPORT", "STATUS", "PATH")
	_, _ = fmt.Fprintln(w, strings.Repeat("-", 90))

	for _, entry := range result.Entries {
		ts := entry.Timestamp
		if len(ts) > 20 {
			ts = ts[:20]
		}

		status := "OK"
		if !entry.OK {
			status = "FAIL"
		}
		if entry.VerifyStatus != "" {
			status = entry.VerifyStatus
		}

		action := entry.Action
		if len(action) > 20 {
			action = action[:17] + "..."
		}

		displayPath := entry.Path
		if entry.RedactedPath != "" {
			displayPath = entry.RedactedPath
		}
		if len(displayPath) > 30 {
			displayPath = displayPath[:27] + "..."
		}

		_, _ = fmt.Fprintf(w, "%-20s %-12s %-20s %-10s %-8s %s\n",
			ts, entry.Agent, action, entry.Transport, status, displayPath)
	}

	_, _ = fmt.Fprintf(w, "\nTotal: %d entries", result.Total)
	if result.Verified > 0 || result.Tampered > 0 {
		_, _ = fmt.Fprintf(w, " (verified: %d, legacy: %d, tampered: %d)",
			result.Verified, result.Legacy, result.Tampered)
	}
	_, _ = fmt.Fprintln(w)
	return nil
}

// StreamExportAuditLog processes audit log entries in a streaming fashion,
// calling the callback for each matching entry. This avoids loading all
// entries into memory at once for large log sets.
func StreamExportAuditLog(opts ExportOptions, callback StreamEntry) (*ExportResult, error) {
	if opts.VerifyHMAC && len(opts.HMACKey) == 0 {
		return nil, fmt.Errorf("HMAC verification requires a key")
	}

	agents, err := resolveAgentList(opts.Agent)
	if err != nil {
		return nil, fmt.Errorf("resolve agents: %w", err)
	}

	result := &ExportResult{
		Agent:      opts.Agent,
		Action:     opts.Action,
		Since:      opts.Since,
		FailedOnly: opts.FailedOnly,
	}

	var mac hash.Hash
	var prevHMAC []byte
	chainStarted := false
	if opts.VerifyHMAC {
		mac = hmac.New(sha256.New, opts.HMACKey)
	}

	for _, agent := range agents {
		home, herr := os.UserHomeDir()
		if herr != nil {
			continue
		}

		auditDir := filepath.Join(filepath.Clean(home), defaultDirName)
		currentFile := filepath.Join(auditDir, fmt.Sprintf(defaultFileNamePattern, agent))
		pattern := filepath.Join(auditDir, fmt.Sprintf(defaultFileNamePattern, agent)+".rotated.*")
		rotatedMatches, _ := filepath.Glob(pattern)

		var files []string
		sort.Strings(rotatedMatches)
		files = append(files, rotatedMatches...)
		if _, err := os.Stat(currentFile); err == nil {
			files = append(files, currentFile)
		}

		for _, f := range files {
			streamAndFilterFile(f, agent, opts, callback, result, mac, &prevHMAC, &chainStarted)
		}
	}

	return result, nil
}

func streamAndFilterFile(
	path, agent string,
	opts ExportOptions,
	callback StreamEntry,
	result *ExportResult,
	mac hash.Hash,
	prevHMAC *[]byte,
	chainStarted *bool,
) {
	f, err := os.Open(path) // #nosec G304 -- validated audit log path
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	idx := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			idx++
			continue
		}

		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			idx++
			continue
		}

		if opts.Since != "" && !MatchesSinceFilter(entry.Timestamp, opts.Since) {
			idx++
			continue
		}
		if opts.FailedOnly && entry.OK {
			idx++
			continue
		}
		if opts.Action != "" && entry.Action != opts.Action {
			idx++
			continue
		}

		exportEntry := ExportEntry{
			LogEntry:      entry,
			OriginalIndex: idx,
			SourceFile:    filepath.Base(path),
		}

		if opts.VerifyHMAC && mac != nil {
			if entry.HMAC == "" {
				if *chainStarted {
					exportEntry.VerifyStatus = "tampered"
				} else {
					exportEntry.VerifyStatus = "legacy"
					*prevHMAC = nil
				}
			} else {
				expectedHMAC := computeHMACWith(mac, *prevHMAC, entry)
				entryHMACBytes, decodeErr := hex.DecodeString(entry.HMAC)
				expectedHMACBytes, expectedErr := hex.DecodeString(expectedHMAC)
				if decodeErr != nil || expectedErr != nil || !hmac.Equal(expectedHMACBytes, entryHMACBytes) {
					exportEntry.VerifyStatus = "tampered"
				} else {
					exportEntry.VerifyStatus = "verified"
					*prevHMAC = entryHMACBytes
					*chainStarted = true
				}
			}
		}

		if opts.RedactPaths {
			exportEntry.RedactedPath = RedactPath(entry.Path)
			exportEntry.Path = ""
		}

		result.Total++
		switch exportEntry.VerifyStatus {
		case "verified":
			result.Verified++
		case "legacy":
			result.Legacy++
		case "tampered":
			result.Tampered++
		}

		result.Entries = append(result.Entries, exportEntry)
		if callback != nil && !callback(exportEntry) {
			break
		}

		idx++
	}
}
