package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/audit"
)

type auditFlags struct {
	since  string
	format string
	limit  int
}

var agentAuditFlags auditFlags

var agentAuditCmd = &cobra.Command{
	Use:   "audit <name>",
	Short: "Show audit log for an agent",
	Long: `Display recent audit events for a specific agent.

Reads from the agent's dedicated audit log at ~/.openpass/audit-<name>.log
and displays entries in table or JSON format.`,
	Args: cobra.ExactArgs(1),
	Example: `  # Show last 50 audit entries for an agent
  openpass agent audit my-agent

  # Show entries from the last 24 hours
  openpass agent audit my-agent --since 24h

  # Output as JSON
  openpass agent audit my-agent --format json

  # Show last 100 entries
  openpass agent audit my-agent --limit 100`,
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := args[0]

		vaultDir := cli.GetVaultDir()
		logPath := filepath.Join(vaultDir, fmt.Sprintf("audit-%s.log", sanitizeAgentName(agentName)))

		entries, err := ReadAuditLog(logPath, agentAuditFlags.limit)
		if err != nil {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "No audit log found for agent %q at %s\n", agentName, logPath)
				return nil
			}
			return fmt.Errorf("read audit log: %w", err)
		}

		if len(entries) == 0 {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "No audit entries found for agent %q.\n", agentName)
			return nil
		}

		entries = SinceFilter(entries, agentAuditFlags.since)

		if len(entries) == 0 {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "No audit entries match the filter criteria.\n")
			return nil
		}

		switch agentAuditFlags.format {
		case "json":
			return printAuditJSON(cmd, entries)
		default:
			printAuditTable(cmd, entries)
			return nil
		}
	},
}

func ReadAuditLog(path string, limit int) ([]audit.LogEntry, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
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

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if limit > 0 && len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	return entries, nil
}

// sanitizeAgentName replaces path separators in agent names to prevent
// directory traversal when constructing audit log file paths.
func sanitizeAgentName(name string) string {
	return strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(name)
}

func SinceFilter(entries []audit.LogEntry, since string) []audit.LogEntry {
	if since == "" {
		return entries
	}

	d, err := ParseHumanDuration(since)
	if err != nil {
		return entries
	}

	cutoff := time.Now().UTC().Add(-d)
	var filtered []audit.LogEntry
	for _, e := range entries {
		ts, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil {
			continue
		}
		if ts.After(cutoff) || ts.Equal(cutoff) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func printAuditTable(cmd *cobra.Command, entries []audit.LogEntry) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-26s %-20s %-8s %s\n", "TIMESTAMP", "ACTION", "OK", "DETAILS")
	for _, e := range entries {
		ok := "✓"
		if !e.OK {
			ok = "✗"
		}
		detail := e.Path
		if e.Field != "" {
			detail += ":" + e.Field
		}
		if e.Reason != "" {
			if detail != "" {
				detail += " "
			}
			detail += e.Reason
		}
		if detail == "" {
			detail = "-"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-26s %-20s %-8s %s\n", e.Timestamp, e.Action, ok, detail)
	}
}

func printAuditJSON(cmd *cobra.Command, entries []audit.LogEntry) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func init() {
	agentAuditCmd.Flags().StringVar(&agentAuditFlags.since, "since", "", "Show entries since duration (e.g. 24h, 7d)")
	agentAuditCmd.Flags().StringVar(&agentAuditFlags.format, "format", "table", "Output format (table, json)")
	agentAuditCmd.Flags().IntVar(&agentAuditFlags.limit, "limit", 50, "Maximum number of entries to show")
	agentCmd.AddCommand(agentAuditCmd)
}
