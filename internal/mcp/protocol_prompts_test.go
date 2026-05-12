package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func initialize(t *testing.T, h *ProtocolHandler) {
	t.Helper()
	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("0"),
		Method:  "initialize",
		Params: json.RawMessage(`{
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {"name": "test", "version": "1.0.0"}
		}`),
	}
	if _, err := h.HandleMessage(context.Background(), msg); err != nil {
		t.Fatalf("initialize: %v", err)
	}
}

func TestInitialize_AdvertisesPromptsCapability(t *testing.T) {
	h := NewProtocolHandler("OpenPass", "1.0.0", nil)
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
	resp, err := h.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	var result InitializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Capabilities == nil || result.Capabilities.Prompts == nil {
		t.Fatal("Prompts capability not advertised in initialize result")
	}
}

func TestPromptsList_NotInitializedRejected(t *testing.T) {
	h := NewProtocolHandler("OpenPass", "1.0.0", nil)
	msg := &Message{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "prompts/list"}
	resp, err := h.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if resp.Error == nil {
		t.Fatal("prompts/list before initialize should error")
	}
}

func TestPromptsList_ReturnsRegisteredPrompts(t *testing.T) {
	h := NewProtocolHandler("OpenPass", "1.0.0", nil)
	initialize(t, h)

	msg := &Message{JSONRPC: "2.0", ID: json.RawMessage("2"), Method: "prompts/list"}
	resp, err := h.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("prompts/list error: %v", resp.Error)
	}
	var got struct {
		Prompts []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Arguments   []struct {
				Name     string `json:"name"`
				Required bool   `json:"required"`
			} `json:"arguments"`
		} `json:"prompts"`
	}
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Prompts) < 4 {
		t.Fatalf("expected at least 4 prompts, got %d", len(got.Prompts))
	}
	names := map[string]bool{}
	for _, p := range got.Prompts {
		names[p.Name] = true
	}
	for _, want := range []string{"add-credential", "rotate-credential", "find-and-use", "share-credential"} {
		if !names[want] {
			t.Errorf("prompts/list missing %q", want)
		}
	}
}

func TestPromptsGet_UnknownPromptErrors(t *testing.T) {
	h := NewProtocolHandler("OpenPass", "1.0.0", nil)
	initialize(t, h)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("3"),
		Method:  "prompts/get",
		Params:  json.RawMessage(`{"name": "does-not-exist"}`),
	}
	resp, _ := h.HandleMessage(context.Background(), msg)
	if resp.Error == nil {
		t.Fatal("prompts/get for unknown name should error")
	}
}

func TestPromptsGet_MissingNameErrors(t *testing.T) {
	h := NewProtocolHandler("OpenPass", "1.0.0", nil)
	initialize(t, h)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("3"),
		Method:  "prompts/get",
		Params:  json.RawMessage(`{}`),
	}
	resp, _ := h.HandleMessage(context.Background(), msg)
	if resp.Error == nil {
		t.Fatal("prompts/get without name should error")
	}
}

func TestPromptsGet_MissingRequiredArgumentErrors(t *testing.T) {
	h := NewProtocolHandler("OpenPass", "1.0.0", nil)
	initialize(t, h)

	// rotate-credential requires `path`
	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("4"),
		Method:  "prompts/get",
		Params:  json.RawMessage(`{"name": "rotate-credential", "arguments": {}}`),
	}
	resp, _ := h.HandleMessage(context.Background(), msg)
	if resp.Error == nil {
		t.Fatal("prompts/get for rotate-credential without path should error")
	}
	if !strings.Contains(resp.Error.Message, "path") {
		t.Errorf("error message should mention missing 'path': %s", resp.Error.Message)
	}
}

func TestPromptsGet_ReturnsRenderedMessages(t *testing.T) {
	h := NewProtocolHandler("OpenPass", "1.0.0", nil)
	initialize(t, h)

	msg := &Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage("5"),
		Method:  "prompts/get",
		Params:  json.RawMessage(`{"name": "add-credential", "arguments": {"service_name": "GitHub"}}`),
	}
	resp, err := h.HandleMessage(context.Background(), msg)
	if err != nil {
		t.Fatalf("HandleMessage: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("prompts/get error: %v", resp.Error)
	}

	var got struct {
		Description string `json:"description"`
		Messages    []struct {
			Role    string `json:"role"`
			Content struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Description == "" {
		t.Error("missing description in response")
	}
	if len(got.Messages) == 0 {
		t.Fatal("no messages in response")
	}
	if got.Messages[0].Role != "user" {
		t.Errorf("first message role = %q, want user", got.Messages[0].Role)
	}
	if got.Messages[0].Content.Type != "text" {
		t.Errorf("content type = %q, want text", got.Messages[0].Content.Type)
	}
	if !strings.Contains(got.Messages[0].Content.Text, "GitHub") {
		t.Errorf("rendered text should include 'GitHub': %s", got.Messages[0].Content.Text)
	}
}
