package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/danieljustus/OpenPass/internal/audit"
)

type auditEvent struct {
	Timestamp string `json:"ts"`
	Tool      string `json:"tool"`
	Path      string `json:"path,omitempty"`
	Status    string `json:"status"`
	Code      string `json:"code,omitempty"`
}

// sanitizeAgentName replaces path separators in agent names to prevent
// directory traversal when constructing audit log file paths.
func sanitizeAgentName(name string) string {
	return strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(name)
}

func (s *Server) handleAuditSelf(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	_ = ctx

	limit := 50
	if v := req.GetFloat("limit", 50); v > 0 {
		limit = int(math.Min(v, 100))
	}

	auditPath := filepath.Join(s.vault.Dir, fmt.Sprintf("audit-%s.log", sanitizeAgentName(s.agent.Name)))

	f, err := os.Open(auditPath) //nolint:gosec G304 — path is filepath.Join(vaultDir, "audit-"+agentName+".log")
	if err != nil {
		if os.IsNotExist(err) {
			return NewToolResultText("[]"), nil
		}
		return NewToolResultError(fmt.Sprintf("cannot read audit log: %v", err)), nil
	}
	defer func() { _ = f.Close() }()

	var events []auditEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry audit.LogEntry
		if unmarshalErr := json.Unmarshal([]byte(line), &entry); unmarshalErr != nil {
			continue
		}
		event := auditEvent{
			Timestamp: entry.Timestamp,
			Tool:      entry.Action,
			Path:      entry.Path,
		}
		if entry.OK {
			event.Status = "ok"
		} else {
			event.Status = "error"
		}
		if entry.Reason != "" {
			event.Code = entry.Reason
		}
		events = append(events, event)
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return NewToolResultError(fmt.Sprintf("error reading audit log: %v", scanErr)), nil
	}

	start := 0
	if len(events) > limit {
		start = len(events) - limit
	}
	events = events[start:]

	resultJSON, err := json.Marshal(events)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(resultJSON)), nil
}
