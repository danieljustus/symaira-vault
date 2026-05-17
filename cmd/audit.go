package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/audit"
)

var (
	auditTail   int
	auditJSON   bool
	auditAgent  string
	auditSince  string
	auditFailed bool
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View MCP audit logs",
	Long: `View audit logs of MCP tool invocations.

By default shows the last 20 entries. Use --tail to change the number of entries.
Use --json for machine-readable output. Use --agent to filter by agent name.
Use --since to filter by time (e.g. "1h", "24h", "7d").`,
	Example: `  # Last 20 audit entries
  openpass audit

  # Last 100 entries, JSON format
  openpass audit --tail 100 --output json

  # Failed invocations in the last day from a specific agent
  openpass audit --agent claude-code --since 24h --failed`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		entries, err := loadAuditEntries(auditAgent, auditTail)
		if err != nil {
			return err
		}

		entries = filterAuditEntries(entries, auditSince, auditFailed)

		if wantJSONOutput(auditJSON) {
			return outputAuditJSON(cmd, entries)
		}

		return outputAuditTable(cmd, entries)
	},
}

func auditLogPath(agent string) (string, error) {
	if strings.Contains(agent, "/") || strings.Contains(agent, "\\") || agent == ".." || agent == "." {
		return "", fmt.Errorf("invalid agent name")
	}
	if strings.Contains(agent, "..") {
		return "", fmt.Errorf("invalid agent name")
	}

	home := os.Getenv("HOME")
	if home == "" {
		resolved, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		home = resolved
	}

	cleanHome := filepath.Clean(home)
	auditDir := filepath.Join(cleanHome, ".openpass")
	cleanAuditDir := filepath.Clean(auditDir)
	if !strings.HasPrefix(cleanAuditDir, cleanHome+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid audit directory path")
	}

	path := filepath.Join(cleanAuditDir, fmt.Sprintf("audit-%s.log", agent))
	cleanPath := filepath.Clean(path)
	if !strings.HasPrefix(cleanPath, cleanAuditDir+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid audit log path")
	}

	return cleanPath, nil
}

func loadAuditEntries(agent string, limit int) ([]audit.LogEntry, error) {
	path, err := auditLogPath(agent)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path) // #nosec // path is validated in auditLogPath
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot open audit log: %w", err)
	}
	defer func() { _ = f.Close() }()

	var entries []audit.LogEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry audit.LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	return entries, nil
}

func filterAuditEntries(entries []audit.LogEntry, since string, failedOnly bool) []audit.LogEntry {
	var cutoff time.Time
	if since != "" {
		dur, err := parseSinceDuration(since)
		if err == nil {
			cutoff = time.Now().UTC().Add(-dur)
		}
	}

	var filtered []audit.LogEntry
	for _, entry := range entries {
		if failedOnly && entry.OK {
			continue
		}
		if !cutoff.IsZero() {
			ts, err := time.Parse(time.RFC3339, entry.Timestamp)
			if err != nil || ts.Before(cutoff) {
				continue
			}
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func parseSinceDuration(s string) (time.Duration, error) {
	// Handle days
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

func outputAuditJSON(cmd *cobra.Command, entries []audit.LogEntry) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func outputAuditTable(cmd *cobra.Command, entries []audit.LogEntry) error {
	if len(entries) == 0 {
		cmd.Println("No audit entries found.")
		return nil
	}

	cmd.Printf("%-20s %-12s %-20s %-10s %-8s %s\n", "TIME", "AGENT", "ACTION", "TRANSPORT", "STATUS", "PATH")
	cmd.Println(strings.Repeat("-", 90))

	for _, entry := range entries {
		ts := entry.Timestamp
		if len(ts) > 20 {
			ts = ts[:20]
		}

		status := "OK"
		if !entry.OK {
			status = "FAIL"
		}

		action := entry.Action
		if len(action) > 20 {
			action = action[:17] + "..."
		}

		path := entry.Path
		if len(path) > 30 {
			path = path[:27] + "..."
		}

		cmd.Printf("%-20s %-12s %-20s %-10s %-8s %s\n", ts, entry.Agent, action, entry.Transport, status, path)
	}

	cmd.Printf("\nTotal: %d entries\n", len(entries))
	return nil
}

func init() {
	auditCmd.Flags().IntVarP(&auditTail, "tail", "n", 20, "Number of entries to show")
	auditCmd.Flags().BoolVarP(&auditJSON, "json", "j", false, "Output as JSON (deprecated: use --output=json)")
	auditCmd.Flags().StringVarP(&auditAgent, "agent", "a", "default", "Agent name to filter by")
	auditCmd.Flags().StringVarP(&auditSince, "since", "s", "", "Show entries since duration (e.g. 1h, 24h, 7d)")
	auditCmd.Flags().BoolVar(&auditFailed, "failed", false, "Show only failed entries")
	rootCmd.AddCommand(auditCmd)
}
