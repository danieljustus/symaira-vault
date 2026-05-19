package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func TestStdioTransport_Initialize(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}
`

	in := strings.NewReader(input)
	out := &bytes.Buffer{}

	transport := NewStdioTransportWithIO(in, out)
	handler := NewProtocolHandler("openpass", "1.0.0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := transport.Start(ctx, handler.HandleMessage)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if output == "" {
		t.Fatal("expected output, got empty")
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one line of output")
	}

	var response Message
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %s", response.JSONRPC)
	}

	if response.Error != nil {
		t.Fatalf("unexpected error: %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("expected result")
	}

	var result InitializeResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}

	if result.ProtocolVersion != "2024-11-05" {
		t.Errorf("expected protocol version 2024-11-05, got %s", result.ProtocolVersion)
	}

	if result.ServerInfo == nil {
		t.Fatal("expected server info")
	}

	if result.ServerInfo.Name != "openpass" {
		t.Errorf("expected server name 'openpass', got %s", result.ServerInfo.Name)
	}
}

func TestStdioTransport_Ping(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":2,"method":"ping"}
`

	in := strings.NewReader(input)
	out := &bytes.Buffer{}

	transport := NewStdioTransportWithIO(in, out)
	handler := NewProtocolHandler("openpass", "1.0.0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = transport.Start(ctx, handler.HandleMessage)

	output := out.String()
	if output == "" {
		t.Fatal("expected output, got empty")
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one line of output")
	}

	var response Message
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if response.Error != nil {
		t.Fatalf("unexpected error: %v", response.Error)
	}
}

func TestStdioTransport_InvalidJSON(t *testing.T) {
	input := `not valid json
`

	in := strings.NewReader(input)
	out := &bytes.Buffer{}

	transport := NewStdioTransportWithIO(in, out)
	handler := NewProtocolHandler("openpass", "1.0.0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = transport.Start(ctx, handler.HandleMessage)

	output := out.String()
	if output == "" {
		t.Fatal("expected error output")
	}

	var response Message
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &response); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}

	if response.Error == nil {
		t.Fatal("expected error response")
	}

	if response.Error.Code != ErrCodeParseError {
		t.Errorf("expected parse error code %d, got %d", ErrCodeParseError, response.Error.Code)
	}
}

func TestNewRequest(t *testing.T) {
	tests := []struct {
		name   string
		id     any
		method string
		params any
		wantID string
	}{
		{
			name:   "string id",
			id:     "req-1",
			method: "test",
			params: map[string]string{"key": "value"},
			wantID: `"req-1"`,
		},
		{
			name:   "int id",
			id:     42,
			method: "test",
			params: nil,
			wantID: "42",
		},
		{
			name:   "nil id",
			id:     nil,
			method: "test",
			params: nil,
			wantID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := NewRequest(tt.id, tt.method, tt.params)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}

			if msg.JSONRPC != "2.0" {
				t.Errorf("jsonrpc = %s, want 2.0", msg.JSONRPC)
			}

			if msg.Method != tt.method {
				t.Errorf("method = %s, want %s", msg.Method, tt.method)
			}

			if tt.wantID != "" {
				if string(msg.ID) != tt.wantID {
					t.Errorf("id = %s, want %s", string(msg.ID), tt.wantID)
				}
			} else if msg.ID != nil {
				t.Error("expected nil id")
			}
		})
	}
}

func TestNewResponse(t *testing.T) {
	result, err := NewResponse(json.RawMessage("1"), map[string]string{"status": "ok"})
	if err != nil {
		t.Fatalf("NewResponse failed: %v", err)
	}

	if result.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %s, want 2.0", result.JSONRPC)
	}

	if string(result.ID) != "1" {
		t.Errorf("id = %s, want 1", string(result.ID))
	}
}

func TestMessageTypes(t *testing.T) {
	tests := []struct {
		name       string
		msg        Message
		isNotif    bool
		isRequest  bool
		isResponse bool
	}{
		{
			name:       "notification",
			msg:        Message{JSONRPC: "2.0", Method: "test"},
			isNotif:    true,
			isRequest:  false,
			isResponse: false,
		},
		{
			name:       "request",
			msg:        Message{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "test"},
			isNotif:    false,
			isRequest:  true,
			isResponse: false,
		},
		{
			name:       "response with result",
			msg:        Message{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: json.RawMessage(`{}`)},
			isNotif:    false,
			isRequest:  false,
			isResponse: true,
		},
		{
			name:       "response with error",
			msg:        Message{JSONRPC: "2.0", ID: json.RawMessage("1"), Error: &RPCError{Code: -1, Message: "error"}},
			isNotif:    false,
			isRequest:  false,
			isResponse: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.msg.IsNotification(); got != tt.isNotif {
				t.Errorf("IsNotification() = %v, want %v", got, tt.isNotif)
			}
			if got := tt.msg.IsRequest(); got != tt.isRequest {
				t.Errorf("IsRequest() = %v, want %v", got, tt.isRequest)
			}
			if got := tt.msg.IsResponse(); got != tt.isResponse {
				t.Errorf("IsResponse() = %v, want %v", got, tt.isResponse)
			}
		})
	}
}

func TestParseParams(t *testing.T) {
	msg := Message{
		Params: json.RawMessage(`{"name": "test", "count": 42}`),
	}

	var params struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	if err := msg.ParseParams(&params); err != nil {
		t.Fatalf("ParseParams failed: %v", err)
	}

	if params.Name != "test" {
		t.Errorf("name = %s, want test", params.Name)
	}

	if params.Count != 42 {
		t.Errorf("count = %d, want 42", params.Count)
	}
}

func TestRPCError_Error(t *testing.T) {
	err := &RPCError{
		Code:    -32700,
		Message: "Parse error",
	}

	expected := "RPC error -32700: Parse error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %s, want %s", got, expected)
	}
}

func TestCallToolRequest_GetString(t *testing.T) {
	req := CallToolRequest{
		Arguments: map[string]any{
			"name": "test-value",
		},
	}

	tests := []struct {
		key      string
		def      string
		expected string
	}{
		{"name", "default", "test-value"},
		{"nonexistent", "default", "default"},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := req.GetString(tt.key, tt.def)
			if result != tt.expected {
				t.Errorf("GetString(%q, %q) = %q, want %q", tt.key, tt.def, result, tt.expected)
			}
		})
	}
}

func TestCallToolRequest_GetString_NotString(t *testing.T) {
	req := CallToolRequest{
		Arguments: map[string]any{
			"number": float64(42),
			"bool":   true,
		},
	}

	if got := req.GetString("number", "default"); got != "default" {
		t.Errorf("GetString() for number = %q, want default", got)
	}
	if got := req.GetString("bool", "default"); got != "default" {
		t.Errorf("GetString() for bool = %q, want default", got)
	}
}

func TestCallToolRequest_GetFloat(t *testing.T) {
	req := CallToolRequest{
		Arguments: map[string]any{
			"int":     int(42),
			"int64":   int64(999),
			"int32":   int32(100),
			"float32": float32(2.5),
			"float":   float64(3.14),
			"string":  "3.14",
		},
	}

	if got := req.GetFloat("int", 0); got != 42 {
		t.Errorf("GetFloat(int) = %v, want 42", got)
	}
	if got := req.GetFloat("int64", 0); got != 999 {
		t.Errorf("GetFloat(int64) = %v, want 999", got)
	}
	if got := req.GetFloat("int32", 0); got != 100 {
		t.Errorf("GetFloat(int32) = %v, want 100", got)
	}
	if got := req.GetFloat("float32", 0); got != 2.5 {
		t.Errorf("GetFloat(float32) = %v, want 2.5", got)
	}
	if got := req.GetFloat("float", 0); got != 3.14 {
		t.Errorf("GetFloat(float) = %v, want 3.14", got)
	}
	if got := req.GetFloat("string", 0); got != 3.14 {
		t.Errorf("GetFloat(string) = %v, want 3.14", got)
	}
	if got := req.GetFloat("nonexistent", 99.0); got != 99.0 {
		t.Errorf("GetFloat(missing) = %v, want 99.0", got)
	}
}

func TestCallToolRequest_GetFloat_InvalidString(t *testing.T) {
	req := CallToolRequest{
		Arguments: map[string]any{
			"invalid": "not-a-number",
		},
	}

	if got := req.GetFloat("invalid", 99.0); got != 99.0 {
		t.Errorf("GetFloat(invalid) = %v, want 99.0 (default)", got)
	}
}

func TestCallToolRequest_GetBool(t *testing.T) {
	req := CallToolRequest{
		Arguments: map[string]any{
			"true":    true,
			"false":   false,
			"string1": "true",
			"string0": "false",
			"stringT": "T",
			"stringF": "F",
			"number":  float64(1),
		},
	}

	if got := req.GetBool("true", false); !got {
		t.Errorf("GetBool(true) = %v, want true", got)
	}
	if got := req.GetBool("false", true); got {
		t.Errorf("GetBool(false) = %v, want false", got)
	}
	if got := req.GetBool("string1", false); !got {
		t.Errorf("GetBool(string1) = %v, want true", got)
	}
	if got := req.GetBool("string0", true); got {
		t.Errorf("GetBool(string0) = %v, want false", got)
	}
	if got := req.GetBool("stringT", false); !got {
		t.Errorf("GetBool(stringT) = %v, want true", got)
	}
	if got := req.GetBool("stringF", true); got {
		t.Errorf("GetBool(stringF) = %v, want false", got)
	}
	if got := req.GetBool("nonexistent", true); !got {
		t.Errorf("GetBool(missing) = %v, want true (default)", got)
	}
}

func TestCallToolRequest_GetBool_InvalidString(t *testing.T) {
	req := CallToolRequest{
		Arguments: map[string]any{
			"invalid": "not-a-bool",
		},
	}

	if got := req.GetBool("invalid", true); !got {
		t.Errorf("GetBool(invalid) = %v, want true (default)", got)
	}
}

func TestNewTool(t *testing.T) {
	tool := NewTool("test_tool",
		WithDescription("A test tool"),
		WithString("param1", Required(), Description("First parameter")),
		WithNumber("count", DefaultNumber(10)),
		WithBoolean("verbose", DefaultBool(false)),
		Required(),
		Description("tool description"),
		DefaultNumber(5),
		DefaultBool(true),
		Default("default"),
		Enum("opt1", "opt2"),
	)

	if tool.Name != "test_tool" {
		t.Errorf("tool.Name = %q, want test_tool", tool.Name)
	}
	if tool.Description != "A test tool" {
		t.Errorf("tool.Description = %q, want 'A test tool'", tool.Description)
	}
}

func TestNewTool_NoOptions(t *testing.T) {
	tool := NewTool("minimal")
	if tool.Name != "minimal" {
		t.Errorf("tool.Name = %q, want minimal", tool.Name)
	}
}

func TestStdioTransport_Stop(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"shutdown"}
`
	in := strings.NewReader(input)
	out := &bytes.Buffer{}

	transport := NewStdioTransportWithIO(in, out)
	handler := NewProtocolHandler("openpass", "1.0.0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go func() {
		<-time.After(100 * time.Millisecond)
		_ = transport.Stop(ctx)
	}()

	_ = transport.Start(ctx, handler.HandleMessage)
}

func TestStdioTransport_StopNotRunning(t *testing.T) {
	in := strings.NewReader("")
	out := &bytes.Buffer{}

	transport := NewStdioTransportWithIO(in, out)

	err := transport.Stop(context.Background())
	if err != nil {
		t.Errorf("Stop() on non-running transport error = %v", err)
	}
}

func TestStdioTransport_StartAlreadyRunning(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
`
	in := strings.NewReader(input)
	out := &bytes.Buffer{}

	transport := NewStdioTransportWithIO(in, out)
	handler := NewProtocolHandler("openpass", "1.0.0", nil)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel1()

	go func() {
		<-time.After(50 * time.Millisecond)
		ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel2()
		_ = transport.Stop(ctx2)
	}()

	err := transport.Start(ctx1, handler.HandleMessage)
	if err != nil && err.Error() != "transport already running" {
		t.Logf("Start error (may be expected): %v", err)
	}
}

func TestAgentFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), agentContextKey, "test-agent")
	if got := AgentFromContext(ctx); got != "test-agent" {
		t.Errorf("AgentFromContext() = %q, want test-agent", got)
	}
}

func TestAgentFromContext_Empty(t *testing.T) {
	ctx := context.Background()
	if got := AgentFromContext(ctx); got != "" {
		t.Errorf("AgentFromContext() on empty context = %q, want empty", got)
	}
}

func TestAgentFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), agentContextKey, 123)
	if got := AgentFromContext(ctx); got != "" {
		t.Errorf("AgentFromContext() with wrong type = %q, want empty", got)
	}
}

func TestNewStdioTransport(t *testing.T) {
	transport := NewStdioTransport()
	if transport == nil {
		t.Fatal("NewStdioTransport() returned nil")
	}
	if transport.reader == nil {
		t.Error("NewStdioTransport() reader is nil")
	}
	if transport.writer == nil {
		t.Error("NewStdioTransport() writer is nil")
	}
}

func TestServer_ServeStdio(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	cfg := &config.Config{
		DefaultAgent: "test",
		Agents: map[string]config.AgentProfile{
			"test": {
				Name:         "test",
				AllowedPaths: []string{"*"},
				CanWrite:     config.BoolPtr(true),
				ApprovalMode: config.StrPtr("none"),
			},
		},
	}

	v := &vault.Vault{
		Dir:      dir,
		Identity: identity,
		Config:   cfg,
	}

	srv, err := New(v, "test", "stdio")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = srv.Close() }()

	err = srv.ServeStdio(context.Background())
	if err != nil {
		t.Errorf("ServeStdio() error = %v", err)
	}
}

func TestHandleList_NoPrefix(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	req := CallToolRequest{
		Arguments: map[string]any{},
	}

	result, err := srv.handleList(context.Background(), req)
	if err != nil {
		t.Fatalf("handleList() error = %v", err)
	}
	if result == nil {
		t.Fatal("handleList() returned nil result")
	}
	if result.IsError {
		t.Fatalf("handleList() returned error: %s", result.Text)
	}
}

func TestHandleList_ListError(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio", "/nonexistent/path")

	req := CallToolRequest{
		Arguments: map[string]any{"prefix": ""},
	}

	_, err := srv.handleList(context.Background(), req)
	if err == nil {
		t.Fatal("handleList() expected error for nonexistent vault dir, got nil")
	}
}

func TestNewRequest_StringID(t *testing.T) {
	msg, err := NewRequest("req-1", "test", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	if string(msg.ID) != `"req-1"` {
		t.Errorf("id = %s, want \"req-1\"", string(msg.ID))
	}
}

func TestNewRequest_IntID(t *testing.T) {
	msg, err := NewRequest(42, "test", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	if string(msg.ID) != "42" {
		t.Errorf("id = %s, want \"42\"", string(msg.ID))
	}
}

func TestNewRequest_NilID(t *testing.T) {
	msg, err := NewRequest(nil, "test", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	if msg.ID != nil {
		t.Errorf("id = %v, want nil", msg.ID)
	}
}

func TestParseParams_NilParams(t *testing.T) {
	msg := Message{}
	var params struct{}
	if err := msg.ParseParams(&params); err != nil {
		t.Fatalf("ParseParams failed: %v", err)
	}
}

func TestNewRequest_StructIDSuccess(t *testing.T) {
	msg, err := NewRequest(struct{ ID string }{ID: "abc"}, "test", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	want := `{"ID":"abc"}`
	if string(msg.ID) != want {
		t.Errorf("id = %s, want %s", string(msg.ID), want)
	}
}

func TestNewRequest_StructIDMarshalError(t *testing.T) {
	_, err := NewRequest(struct{ C chan int }{C: make(chan int)}, "test", nil)
	if err == nil {
		t.Fatal("NewRequest expected error for unmarshalable id, got nil")
	}
}

func TestNewResponse_NilResult(t *testing.T) {
	msg, err := NewResponse(json.RawMessage("1"), nil)
	if err != nil {
		t.Fatalf("NewResponse failed: %v", err)
	}
	if msg.Result != nil {
		t.Errorf("Result = %v, want nil", msg.Result)
	}
}

func TestNewResponse_MarshalError(t *testing.T) {
	_, err := NewResponse(json.RawMessage("1"), struct{ C chan int }{C: make(chan int)})
	if err == nil {
		t.Fatal("NewResponse expected error for unmarshalable result, got nil")
	}
}

func TestCallToolResultPayload_Nil(t *testing.T) {
	result := callToolResultPayload(nil)
	if result == nil {
		t.Fatal("callToolResultPayload(nil) returned nil")
	}
	content, ok := result["content"].([]map[string]any)
	if !ok {
		t.Fatal("expected content to be []map[string]any")
	}
	if len(content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(content))
	}
	if content[0]["text"] != "" {
		t.Errorf("expected empty text, got %q", content[0]["text"])
	}
}
