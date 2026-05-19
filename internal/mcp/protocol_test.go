package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/danieljustus/OpenPass/internal/config"
)

func TestProtocolHandler_Initialize(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error != nil {
		t.Fatalf("HandleMessage() returned error: %v", resp.Error)
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.ProtocolVersion != "2024-11-05" {
		t.Errorf("ProtocolVersion = %q, want 2024-11-05", result.ProtocolVersion)
	}
	if result.ServerInfo == nil {
		t.Fatal("ServerInfo is nil")
	}
	if result.ServerInfo.Name != "OpenPass" {
		t.Errorf("ServerInfo.Name = %q, want OpenPass", result.ServerInfo.Name)
	}
}

func TestProtocolHandler_Initialize_UnsupportedVersion(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2023-11-01",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}

	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.ProtocolVersion != LatestSupportedProtocolVersion {
		t.Errorf("ProtocolVersion = %q, want %q", result.ProtocolVersion, LatestSupportedProtocolVersion)
	}
}

func TestProtocolHandler_Initialized(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	msg := &Message{
		JSONRPC: "2.0",
		Method:  "initialized",
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp != nil {
		t.Error("initialized notification should return nil response")
	}
}

func TestProtocolHandler_Ping(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "ping",
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error != nil {
		t.Fatalf("HandleMessage() returned error: %v", resp.Error)
	}
}

func TestProtocolHandler_ToolsList_NotInitialized(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "tools/list",
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error == nil {
		t.Fatal("Expected error for tools/list before initialization")
	}
	if resp.Error.Code != ErrCodeServerError {
		t.Errorf("Error code = %d, want %d", resp.Error.Code, ErrCodeServerError)
	}
}

func TestProtocolHandler_ToolsList_Success(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	initMsg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}
	_, err := handler.HandleMessage(context.Background(), initMsg)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}

	listMsg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "tools/list",
		Params:  json.RawMessage(`{"include_all_tools":true}`),
	}

	resp, err := handler.HandleMessage(context.Background(), listMsg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error != nil {
		t.Fatalf("HandleMessage() returned error: %v", resp.Error)
	}

	var result struct {
		Tools []map[string]any `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(result.Tools) == 0 {
		t.Fatal("Expected tools, got empty list")
	}

	names := make(map[string]bool, len(result.Tools))
	for _, tool := range result.Tools {
		name, _ := tool["name"].(string)
		names[name] = true
	}
	if !names["generate_totp"] {
		t.Fatalf("tools/list missing generate_totp: %#v", names)
	}
}

func TestProtocolHandler_ToolsCall_NotInitialized(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "list_entries", "arguments": {}}`),
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error == nil {
		t.Fatal("Expected error for tools/call before initialization")
	}
	if resp.Error.Code != ErrCodeServerError {
		t.Errorf("Error code = %d, want %d", resp.Error.Code, ErrCodeServerError)
	}
}

func TestProtocolHandler_ToolsCall_InvalidParams(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	initMsg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}
	_, err := handler.HandleMessage(context.Background(), initMsg)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "tools/call",
		Params:  json.RawMessage(`not valid json`),
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error == nil {
		t.Fatal("Expected error for invalid params")
	}
}

func TestProtocolHandler_ToolsCall_NilTools(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	initMsg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}
	_, err := handler.HandleMessage(context.Background(), initMsg)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "list_entries", "arguments": {}}`),
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error == nil {
		t.Fatal("Expected error for nil tools")
	}
	if resp.Error.Code != ErrCodeInternalError {
		t.Errorf("Error code = %d, want %d", resp.Error.Code, ErrCodeInternalError)
	}
}

func TestProtocolHandler_UnknownMethod(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "unknown/method",
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error == nil {
		t.Fatal("Expected error for unknown method")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("Error code = %d, want %d", resp.Error.Code, ErrCodeMethodNotFound)
	}
}

func TestProtocolHandler_ConcurrentInitialize(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = handler.HandleMessage(context.Background(), msg)
			select {
			case <-done:
			default:
			}
		}()
	}

	_, _ = handler.HandleMessage(context.Background(), msg)
	close(done)
}

func TestProtocolHandler_Close(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)
	if err := handler.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProtocolHandler_Close_NilTools(t *testing.T) {
	handler := NewProtocolHandler("OpenPass", "1.0.0", nil)
	handler.tools = nil
	if err := handler.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestProtocolHandler_Close_Error(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio")
	handler := NewProtocolHandler("OpenPass", "1.0.0", srv)

	_ = srv.auditLog.Close()

	err := handler.Close()
	if err == nil {
		t.Fatal("Close() expected error, got nil")
	}
}

func TestProtocolHandler_ToolsCall_Success(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio")
	handler := NewProtocolHandler("OpenPass", "1.0.0", srv)

	initMsg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}
	_, err := handler.HandleMessage(context.Background(), initMsg)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "generate_password", "arguments": {"length": 8, "symbols": "false"}}`),
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error != nil {
		t.Fatalf("HandleMessage() returned error: %v", resp.Error)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	content, ok := result["content"].([]any)
	if !ok {
		t.Fatalf("result content has unexpected type %T", result["content"])
	}
	if len(content) == 0 {
		t.Fatal("expected content in result")
	}

	if result["isError"] == true {
		t.Error("expected isError to be false")
	}
}

func TestProtocolHandler_ToolsCall_ExecuteError(t *testing.T) {
	srv := newTestServer(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     config.BoolPtr(false),
		ApprovalMode: config.StrPtr("none"),
	}, "stdio")
	handler := NewProtocolHandler("OpenPass", "1.0.0", srv)

	initMsg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}
	_, err := handler.HandleMessage(context.Background(), initMsg)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name": "get_entry", "arguments": {"path": "nonexistent"}}`),
	}

	resp, err := handler.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage() error = %v", err)
	}
	if resp == nil {
		t.Fatal("HandleMessage() returned nil response")
	}
	if resp.Error == nil {
		t.Fatal("Expected error response for tool execution failure")
	}
	if resp.Error.Code != ErrCodeInternalError {
		t.Errorf("Error code = %d, want %d", resp.Error.Code, ErrCodeInternalError)
	}
}
