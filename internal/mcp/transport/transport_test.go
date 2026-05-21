package transport

import (
	"encoding/json"
	"testing"
)

func TestNewRequest(t *testing.T) {
	msg, err := NewRequest(1, "test_method", map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if msg.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", msg.JSONRPC, "2.0")
	}
	if msg.Method != "test_method" {
		t.Errorf("Method = %q, want %q", msg.Method, "test_method")
	}
}

func TestNewResponse(t *testing.T) {
	id := json.RawMessage(`1`)
	msg, err := NewResponse(id, map[string]any{"result": "ok"})
	if err != nil {
		t.Fatalf("NewResponse() error = %v", err)
	}
	if msg.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", msg.JSONRPC, "2.0")
	}
	if msg.Error != nil {
		t.Errorf("unexpected error: %v", msg.Error)
	}
}

func TestMessageTypes(t *testing.T) {
	req, _ := NewRequest(1, "test", nil)
	if !req.IsRequest() {
		t.Error("expected IsRequest() = true")
	}
	if req.IsNotification() {
		t.Error("expected IsNotification() = false")
	}
	if req.IsResponse() {
		t.Error("expected IsResponse() = false")
	}

	notif := &Message{JSONRPC: "2.0", Method: "test"}
	if !notif.IsNotification() {
		t.Error("expected IsNotification() = true")
	}
	if notif.IsRequest() {
		t.Error("expected IsRequest() = false")
	}

	resp, _ := NewResponse(json.RawMessage(`1`), "ok")
	if !resp.IsResponse() {
		t.Error("expected IsResponse() = true")
	}
}

func TestParseParams(t *testing.T) {
	msg := &Message{
		JSONRPC: "2.0",
		Params:  json.RawMessage(`{"key":"value"}`),
	}
	var params map[string]string
	if err := msg.ParseParams(&params); err != nil {
		t.Fatalf("ParseParams() error = %v", err)
	}
	if params["key"] != "value" {
		t.Errorf("params[key] = %q, want %q", params["key"], "value")
	}
}

func TestParseParams_NilParams(t *testing.T) {
	msg := &Message{JSONRPC: "2.0"}
	var params map[string]string
	if err := msg.ParseParams(&params); err != nil {
		t.Fatalf("ParseParams() error = %v", err)
	}
}

func TestRPCError_Error(t *testing.T) {
	e := &RPCError{Code: -32601, Message: "Method not found"}
	if e.Error() != "RPC error -32601: Method not found" {
		t.Errorf("Error() = %q, want %q", e.Error(), "RPC error -32601: Method not found")
	}
}

func TestNewRequest_StringID(t *testing.T) {
	msg, err := NewRequest("abc", "test", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	var id string
	if err := json.Unmarshal(msg.ID, &id); err != nil {
		t.Fatalf("unmarshal id: %v", err)
	}
	if id != "abc" {
		t.Errorf("id = %q, want %q", id, "abc")
	}
}

func TestNewRequest_IntID(t *testing.T) {
	msg, err := NewRequest(42, "test", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	var id int
	if err := json.Unmarshal(msg.ID, &id); err != nil {
		t.Fatalf("unmarshal id: %v", err)
	}
	if id != 42 {
		t.Errorf("id = %d, want %d", id, 42)
	}
}

func TestNewRequest_NilID(t *testing.T) {
	msg, err := NewRequest(nil, "test", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if msg.ID != nil {
		t.Error("expected nil ID for notification")
	}
}

func TestNewResponse_NilResult(t *testing.T) {
	msg, err := NewResponse(json.RawMessage(`1`), nil)
	if err != nil {
		t.Fatalf("NewResponse() error = %v", err)
	}
	if msg.Result != nil {
		t.Error("expected nil result")
	}
}
