package wizard

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/OpenPass/internal/mcp/install"
)

type agentEntry struct {
	agentType install.AgentType
	name      string
	detected  bool
	selected  bool
	transport string // "stdio" | "http"
	scope     string
	readOnly  bool
}

// AgentsStep lets the user choose which AI agents to configure.
type AgentsStep struct {
	entries []*agentEntry
	cursor  int
	done    bool
}

func NewAgentsStep() *AgentsStep {
	detected := install.DetectAllAgents()
	var entries []*agentEntry
	for _, at := range install.SupportedAgents() {
		def, err := install.GetAgentDefinition(at)
		if err != nil {
			continue
		}
		e := &agentEntry{
			agentType: at,
			name:      def.DisplayName,
			transport: "stdio",
			scope:     "*",
			readOnly:  true,
		}
		if r, ok := detected[at]; ok && r.Detected {
			e.detected = true
		}
		entries = append(entries, e)
	}
	return &AgentsStep{entries: entries}
}

func (s *AgentsStep) Title() string                 { return "AI Agents" }
func (s *AgentsStep) ShouldShow(_ WizardState) bool { return true }
func (s *AgentsStep) Init() tea.Cmd                 { return nil }

func (s *AgentsStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
		case keyDown, "j":
			if s.cursor < len(s.entries) { // len = "Skip" option
				s.cursor++
			}
		case " ":
			if s.cursor < len(s.entries) {
				s.entries[s.cursor].selected = !s.entries[s.cursor].selected
			}
		case keyEnter:
			if s.cursor == len(s.entries) || s.selectedCount() == 0 {
				// "Skip" or nothing selected.
				s.done = true
				return s, stepDoneCmd()
			}
			s.done = true
			return s, stepDoneCmd()
		}
	}
	return s, nil
}

func (s *AgentsStep) selectedCount() int {
	n := 0
	for _, e := range s.entries {
		if e.selected {
			n++
		}
	}
	return n
}

func (s *AgentsStep) View() string {
	lines := []string{
		titleStyle.Render("AI agent configuration (MCP)"),
		"",
		"Select agents to configure. Detected agents are marked with ✓.",
		"",
	}

	for i, e := range s.entries {
		cursor := "  "
		if i == s.cursor {
			cursor = focusedStyle.Render("▸ ")
		}
		check := "[ ]"
		if e.selected {
			check = successStyle.Render("[✓]")
		}
		detected := ""
		if e.detected {
			detected = dimStyle.Render(" (detected)")
		}
		lines = append(lines, fmt.Sprintf("%s%s %s%s", cursor, check, e.name, detected))
	}

	// "Skip" option at bottom.
	skipCursor := "  "
	if s.cursor == len(s.entries) {
		skipCursor = focusedStyle.Render("▸ ")
	}
	lines = append(lines, skipCursor+dimStyle.Render("[ ] Skip — configure manually later"))
	lines = append(lines, "", helpStyle.Render("↑/↓ navigate · Space to toggle · Enter to confirm"))
	return strings.Join(lines, "\n")
}

// Selections returns the chosen agents with default transport/scope.
func (s *AgentsStep) Selections() []AgentSelection {
	var result []AgentSelection
	for _, e := range s.entries {
		if !e.selected {
			continue
		}
		result = append(result, AgentSelection{
			AgentType: string(e.agentType),
			Transport: e.transport,
			Scope:     e.scope,
			ReadOnly:  e.readOnly,
		})
	}
	return result
}
