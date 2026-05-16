package mcp

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-tty"
)

// RiskLevel represents the sensitivity level of a tool operation.
type RiskLevel int

const (
	RiskLevelLow      RiskLevel = 0
	RiskLevelMedium   RiskLevel = 1
	RiskLevelHigh     RiskLevel = 2
	RiskLevelCritical RiskLevel = 3
)

// String returns a human-readable label for the risk level.
func (r RiskLevel) String() string {
	switch r {
	case RiskLevelLow:
		return "LOW"
	case RiskLevelMedium:
		return "MEDIUM"
	case RiskLevelHigh:
		return "HIGH"
	case RiskLevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Indicator returns a visual indicator for the risk level.
func (r RiskLevel) Indicator() string {
	switch r {
	case RiskLevelLow:
		return "🟢"
	case RiskLevelMedium:
		return "🟡"
	case RiskLevelHigh:
		return "🟠"
	case RiskLevelCritical:
		return "🔴"
	default:
		return "⚪"
	}
}

// CanRemember returns true if this risk level allows the "remember" option.
func (r RiskLevel) CanRemember() bool {
	return r < RiskLevelCritical
}

// ttyDevice abstracts a TTY for testability.
type ttyDevice interface {
	ReadString() (string, error)
	Input() *os.File
	Output() *os.File
	Raw() (func(), error)
	Close() error
}

type ttyWrapper struct {
	*tty.TTY
}

func (w *ttyWrapper) Raw() (func(), error) {
	restore, err := w.TTY.Raw()
	if err != nil {
		return nil, err
	}
	return func() { _ = restore() }, nil
}

var openTTYDevice = func() (ttyDevice, error) {
	dev, err := tty.Open()
	if err != nil {
		return nil, err
	}
	return &ttyWrapper{TTY: dev}, nil
}

// ApprovalRequest represents a request for user approval of a sensitive operation.
// It carries context information for rendering the approval dialog.
type ApprovalRequest struct {
	Operation string
	Details   string
	Timeout   time.Duration

	// AgentName is the name of the requesting agent.
	AgentName string
	// WorkingDir is the agent's working directory.
	WorkingDir string
	// GitBranch is the current git branch.
	GitBranch string
	// ProjectType is the detected project type (e.g., "Go", "Node.js").
	ProjectType string
	// RiskLevel classifies the sensitivity of the operation.
	RiskLevel RiskLevel
	// SecretsAccessed tracks how many secrets have been accessed this session.
	SecretsAccessed int
	// CanRemember indicates whether the "remember" option is offered.
	CanRemember bool
}

// ApprovalResult represents the outcome of an approval request
type ApprovalResult struct {
	Error      error
	Approved   bool
	Remembered bool
}

// defaultTimeout is the default timeout for approval requests (30 seconds)
const defaultTimeout = 30 * time.Second

// IsTTYPresent checks if a TTY is available for reading and writing.
// Uses go-tty for cross-platform support (works on Unix and Windows).
func IsTTYPresent() bool {
	tt, err := openTTYDevice()
	if err != nil {
		return false
	}
	_ = tt.Close()
	return true
}

// RequestApproval prompts the user via TTY for approval of a sensitive operation.
// It displays the operation details and waits for user input (y/yes to approve).
// The prompt times out after the specified duration (defaults to 30 seconds).
// If TTY is not available, the operation is denied with an error.
func RequestApproval(req ApprovalRequest) ApprovalResult {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	tt, err := openTTYDevice()
	if err != nil {
		return ApprovalResult{
			Approved: false,
			Error:    fmt.Errorf("approval required but no TTY available (running non-interactively)"),
		}
	}
	defer func() { _ = tt.Close() }()

	restore, err := tt.Raw()
	if err != nil {
		return ApprovalResult{
			Approved: false,
			Error:    fmt.Errorf("failed to set terminal raw mode: %w", err),
		}
	}

	prompt := buildPrompt(req)
	if _, writeErr := tt.Output().WriteString(prompt); writeErr != nil {
		restore()
		return ApprovalResult{
			Approved: false,
			Error:    fmt.Errorf("failed to write to terminal: %w", writeErr),
		}
	}

	response, readErr := readTTYResponse(tt, timeout)
	if readErr != nil {
		restore()
		if isTimeoutError(readErr) {
			return ApprovalResult{
				Approved: false,
				Error:    fmt.Errorf("approval timed out after %v", timeout),
			}
		}
		return ApprovalResult{
			Approved: false,
			Error:    fmt.Errorf("failed to read from terminal: %w", readErr),
		}
	}
	restore()

	approved := parseApprovalResponse(response)
	remembered := req.CanRemember && parseRememberResponse(response)

	if approved || remembered {
		_, _ = fmt.Fprintln(tt.Output(), "yes")
	} else {
		_, _ = fmt.Fprintln(tt.Output(), "no")
	}

	return ApprovalResult{
		Approved:   approved || remembered,
		Remembered: remembered,
		Error:      nil,
	}
}

// buildPrompt creates the approval prompt string with full context display
func buildPrompt(req ApprovalRequest) string {
	var sb strings.Builder

	boxWidth := 68

	sb.WriteString("\n")
	sb.WriteString("╔" + strings.Repeat("═", boxWidth) + "╗\n")
	sb.WriteString("║" + centerText("MCP OPERATION APPROVAL REQUIRED", boxWidth) + "║\n")
	sb.WriteString("╠" + strings.Repeat("═", boxWidth) + "╣\n")

	if req.AgentName != "" {
		fmt.Fprintf(&sb, "║ Agent:     %-*s ║\n", boxWidth-12, truncate(req.AgentName, boxWidth-12))
	}

	riskStr := req.RiskLevel.Indicator() + " " + req.RiskLevel.String()
	fmt.Fprintf(&sb, "║ Risk:      %-*s ║\n", boxWidth-12, truncate(riskStr, boxWidth-12))

	if req.WorkingDir != "" {
		fmt.Fprintf(&sb, "║ Directory: %-*s ║\n", boxWidth-12, truncate(req.WorkingDir, boxWidth-12))
	}

	if req.GitBranch != "" {
		fmt.Fprintf(&sb, "║ Git:       %-*s ║\n", boxWidth-12, truncate(req.GitBranch, boxWidth-12))
	}

	if req.ProjectType != "" {
		fmt.Fprintf(&sb, "║ Project:   %-*s ║\n", boxWidth-12, truncate(req.ProjectType, boxWidth-12))
	}

	fmt.Fprintf(&sb, "║ Secrets:   %-*s ║\n", boxWidth-12,
		truncate(fmt.Sprintf("%d accessed this session", req.SecretsAccessed), boxWidth-12))

	sb.WriteString("║" + strings.Repeat("─", boxWidth) + "║\n")

	if req.Operation != "" {
		fmt.Fprintf(&sb, "║ Operation: %-*s ║\n", boxWidth-12, truncate(req.Operation, boxWidth-12))
	}

	if req.Details != "" {
		fmt.Fprintf(&sb, "║ Details:   %-*s ║\n", boxWidth-12, truncate(req.Details, boxWidth-12))
	}

	sb.WriteString("╚" + strings.Repeat("═", boxWidth) + "╝\n")

	if req.CanRemember {
		sb.WriteString("\nApprove this operation? (y/n/r, r=remember for session): ")
	} else {
		sb.WriteString("\nApprove this operation? (y/n): ")
	}

	return sb.String()
}

func centerText(text string, width int) string {
	if len(text) >= width {
		return text[:width]
	}
	padding := width - len(text)
	left := padding / 2
	right := padding - left
	return strings.Repeat(" ", left) + text + strings.Repeat(" ", right)
}

func readTTYResponse(tt ttyDevice, timeout time.Duration) (string, error) {
	input := tt.Input()
	if input != nil {
		if err := input.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", err
		}
		defer func() {
			_ = input.SetReadDeadline(time.Time{})
		}()
	}

	return tt.ReadString()
}

func isTimeoutError(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var timeoutErr interface {
		Timeout() bool
	}
	return errors.As(err, &timeoutErr) && timeoutErr.Timeout()
}

// parseApprovalResponse determines if the user approved the operation
// Accepts "y", "yes" (case insensitive) as approval
// Everything else is considered a denial
func parseApprovalResponse(response string) bool {
	lowerResponse := strings.ToLower(strings.TrimSpace(response))
	return lowerResponse == "y" || lowerResponse == "yes" || lowerResponse == "r" || lowerResponse == "remember"
}

// parseRememberResponse determines if the user opted to remember the approval
// for the current session. Accepts "r", "remember" (case insensitive).
func parseRememberResponse(response string) bool {
	lowerResponse := strings.ToLower(strings.TrimSpace(response))
	return lowerResponse == "r" || lowerResponse == "remember"
}

// truncate truncates a string to the specified maximum length
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
