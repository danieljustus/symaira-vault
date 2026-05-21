// Package transport implements the Model Context Protocol (MCP) transport layer for OpenPass.
package transport

import (
	"context"
	"encoding/json"
	"fmt"
)

// Message represents a JSON-RPC 2.0 message
type Message struct {
	Error   *RPCError       `json:"error,omitempty"`
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error
type RPCError struct {
	Data    any    `json:"data,omitempty"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// Error implements the error interface
func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// Transport defines the interface for MCP transports
type Transport interface {
	// Start begins the transport and blocks until Stop is called or an error occurs
	Start(ctx context.Context, handler MessageHandler) error
	// Stop gracefully shuts down the transport
	Stop(ctx context.Context) error
}

// MessageHandler is called for each incoming JSON-RPC message
// It should return the result or error to be sent back
type MessageHandler func(ctx context.Context, msg *Message) (*Message, error)

// NewRequest creates a new JSON-RPC request message
func NewRequest(id any, method string, params any) (*Message, error) {
	var idRaw json.RawMessage
	switch v := id.(type) {
	case string:
		idRaw = json.RawMessage(fmt.Sprintf("%q", v))
	case int, int32, int64:
		idRaw = json.RawMessage(fmt.Sprintf("%d", v))
	case nil:
		idRaw = nil
	default:
		var err error
		idRaw, err = json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal id: %w", err)
		}
	}

	var paramsRaw json.RawMessage
	if params != nil {
		var err error
		paramsRaw, err = json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
	}

	return &Message{
		JSONRPC: "2.0",
		ID:      idRaw,
		Method:  method,
		Params:  paramsRaw,
	}, nil
}

// NewResponse creates a new JSON-RPC response message
func NewResponse(id json.RawMessage, result any) (*Message, error) {
	var resultRaw json.RawMessage
	if result != nil {
		var err error
		resultRaw, err = json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("marshal result: %w", err)
		}
	}

	return &Message{
		JSONRPC: "2.0",
		ID:      id,
		Result:  resultRaw,
	}, nil
}

// NewErrorResponse creates a new JSON-RPC error response message
func NewErrorResponse(id json.RawMessage, code int, message string, data any) *Message {
	return &Message{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// IsNotification returns true if the message is a notification (no ID)
func (m *Message) IsNotification() bool {
	return len(m.ID) == 0
}

// IsRequest returns true if the message is a request (has method and ID)
func (m *Message) IsRequest() bool {
	return m.Method != "" && !m.IsNotification()
}

// IsResponse returns true if the message is a response (has result or error)
func (m *Message) IsResponse() bool {
	return m.Result != nil || m.Error != nil
}

// ParseParams unmarshals the params into the given target
func (m *Message) ParseParams(target any) error {
	if m.Params == nil {
		return nil
	}
	return json.Unmarshal(m.Params, target)
}

// JSON-RPC error codes
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
	ErrCodeServerError    = -32000
)

// Common errors
var (
	ErrTransportClosed = fmt.Errorf("transport closed")
)
