package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

const (
	LatestSupportedProtocolVersion = "2025-11-25"
	DefaultHTTPProtocolVersion     = "2025-03-26"
)

var supportedProtocolVersions = []string{
	"2025-11-25",
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

// InitializeParams represents the parameters of an initialize request
type InitializeParams struct {
	ClientInfo      *ClientInfo     `json:"clientInfo"`
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities"`
}

// ClientInfo represents information about the MCP client
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeResult represents the result of an initialize request
type InitializeResult struct {
	Capabilities    *ServerCapabilities `json:"capabilities"`
	ServerInfo      *ServerInfo         `json:"serverInfo"`
	ProtocolVersion string              `json:"protocolVersion"`
	Instructions    string              `json:"instructions,omitempty"`
}

// serverInstructions is surfaced to every client in the initialize response so
// agents can self-discover the "consume a secret without seeing it" pattern
// instead of dead-ending on a redacted reference (issue #667). It intentionally
// does not vary per agent/profile — it describes the pattern, not this agent's
// specific permissions, which the agent learns from tool availability and from
// the per-field "usage" hints in get_entry/get_entry_value responses.
const serverInstructions = `SymVault redacts secret values by default: get_entry and get_entry_value ` +
	`return a reference (a "handle", e.g. op://path/field) instead of the plaintext, plus a per-field ` +
	`"usage" hint. Do not try to resolve that reference yourself — you are not meant to see the value.

To consume a secret without seeing it:
  - run_command / execute_with_secret: pass "path.field" (not the op:// handle) as an env map value, ` +
	`e.g. {"env": {"GH_TOKEN": "github.token"}}. SymVault resolves and injects it; only the child ` +
	`process sees the value.
  - copy_to_clipboard / autotype: for interactive, human-facing use.
  - request_credential: ask the user to supply or confirm a credential directly.

If a tool call is denied (run_denied / not in allowed_tools), the error names the exact profile fix — ` +
	`read it before giving up. See docs/agent-integration.md for the full recipe and a runner-profile example.`

// ServerCapabilities represents the capabilities of the MCP server
type ServerCapabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
	Logging   *LoggingCapability   `json:"logging,omitempty"`
}

// ToolsCapability represents tools support
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability represents resources support
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability represents prompts support
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// LoggingCapability represents logging support
type LoggingCapability struct{}

// ServerInfo represents information about the MCP server
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ProtocolHandler handles MCP protocol messages
type ProtocolHandler struct {
	tools         *Server
	serverName    string
	serverVersion string
	mu            sync.RWMutex
	initialized   bool
}

// NewProtocolHandler creates a new MCP protocol handler
func NewProtocolHandler(serverName, serverVersion string, tools *Server) *ProtocolHandler {
	return &ProtocolHandler{
		serverName:    serverName,
		serverVersion: serverVersion,
		tools:         tools,
	}
}

// HandleMessage handles incoming JSON-RPC messages
func (h *ProtocolHandler) HandleMessage(ctx context.Context, msg *transport.Message) (*transport.Message, error) {
	if msg.IsResponse() {
		return nil, nil
	}

	switch msg.Method {
	case "initialize":
		return h.handleInitialize(ctx, msg)
	case "initialized", "notifications/initialized":
		return h.handleInitialized(ctx, msg)
	case "ping":
		return h.handlePing(ctx, msg)
	case "tools/list":
		return h.handleToolsList(ctx, msg)
	case "tools/call":
		return h.handleToolsCall(ctx, msg)
	case "prompts/list":
		return h.handlePromptsList(ctx, msg)
	case "prompts/get":
		return h.handlePromptsGet(ctx, msg)
	default:
		if msg.IsNotification() {
			return nil, nil
		}
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeMethodNotFound, fmt.Sprintf("Method not found: %s", msg.Method), nil), nil
	}
}

func (h *ProtocolHandler) handleInitialize(_ context.Context, msg *transport.Message) (*transport.Message, error) {
	var params InitializeParams
	if err := msg.ParseParams(&params); err != nil {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeInvalidParams, "Invalid params", err.Error()), nil
	}

	supportedVersion := negotiateProtocolVersion(params.ProtocolVersion)

	result := &InitializeResult{
		ProtocolVersion: supportedVersion,
		Capabilities: &ServerCapabilities{
			Tools: &ToolsCapability{
				ListChanged: false,
			},
			Prompts: &PromptsCapability{
				ListChanged: false,
			},
		},
		ServerInfo: &ServerInfo{
			Name:    h.serverName,
			Version: h.serverVersion,
		},
		Instructions: serverInstructions,
	}

	h.mu.Lock()
	h.initialized = true
	h.mu.Unlock()

	return transport.NewResponse(msg.ID, result)
}

func IsSupportedProtocolVersion(version string) bool {
	for _, supported := range supportedProtocolVersions {
		if version == supported {
			return true
		}
	}
	return false
}

func negotiateProtocolVersion(requested string) string {
	if requested != "" && IsSupportedProtocolVersion(requested) {
		return requested
	}
	return LatestSupportedProtocolVersion
}

func (h *ProtocolHandler) handleInitialized(ctx context.Context, msg *transport.Message) (*transport.Message, error) {
	return nil, nil
}

func (h *ProtocolHandler) handlePing(_ context.Context, msg *transport.Message) (*transport.Message, error) {
	return transport.NewResponse(msg.ID, map[string]any{})
}

func (h *ProtocolHandler) handleToolsList(_ context.Context, msg *transport.Message) (*transport.Message, error) {
	h.mu.RLock()
	initialized := h.initialized
	h.mu.RUnlock()

	if !initialized {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeServerError, "Server not initialized", nil), nil
	}

	tools := toolsListPayload(h.tools)
	if !includeAllTools(msg) {
		tools = filterLeanTools(tools)
	}

	return transport.NewResponse(msg.ID, map[string]any{
		"tools": tools,
	})
}

func (h *ProtocolHandler) Close() error {
	if h == nil || h.tools == nil {
		return nil
	}
	return h.tools.Close()
}

func (h *ProtocolHandler) handleToolsCall(ctx context.Context, msg *transport.Message) (*transport.Message, error) {
	h.mu.RLock()
	initialized := h.initialized
	h.mu.RUnlock()

	if !initialized {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeServerError, "Server not initialized", nil), nil
	}

	if h.tools == nil {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeInternalError, "vault locked: run 'symvault unlock' first", nil), nil
	}

	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := msg.ParseParams(&params); err != nil {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeInvalidParams, "Invalid params", err.Error()), nil
	}

	result, err := h.tools.executeTool(ctx, params.Name, params.Arguments)
	if err != nil {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeInternalError, err.Error(), nil), nil
	}

	return transport.NewResponse(msg.ID, result)
}

func (h *ProtocolHandler) handlePromptsList(_ context.Context, msg *transport.Message) (*transport.Message, error) {
	h.mu.RLock()
	initialized := h.initialized
	h.mu.RUnlock()

	if !initialized {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeServerError, "Server not initialized", nil), nil
	}

	return transport.NewResponse(msg.ID, map[string]any{
		"prompts": promptsListPayload(),
	})
}

func (h *ProtocolHandler) handlePromptsGet(_ context.Context, msg *transport.Message) (*transport.Message, error) {
	h.mu.RLock()
	initialized := h.initialized
	h.mu.RUnlock()

	if !initialized {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeServerError, "Server not initialized", nil), nil
	}

	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := msg.ParseParams(&params); err != nil {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeInvalidParams, "Invalid params", err.Error()), nil
	}
	if params.Name == "" {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeInvalidParams, "Missing prompt name", nil), nil
	}

	def, ok := findPromptDefinition(params.Name)
	if !ok {
		return transport.NewErrorResponse(msg.ID, transport.ErrCodeInvalidParams, fmt.Sprintf("Unknown prompt: %s", params.Name), nil), nil
	}

	if params.Arguments == nil {
		params.Arguments = map[string]string{}
	}
	for _, arg := range def.Arguments {
		if arg.Required {
			if v, ok := params.Arguments[arg.Name]; !ok || v == "" {
				return transport.NewErrorResponse(msg.ID, transport.ErrCodeInvalidParams,
					fmt.Sprintf("Missing required argument: %s", arg.Name), nil), nil
			}
		}
	}

	return transport.NewResponse(msg.ID, promptGetPayload(def, params.Arguments))
}
