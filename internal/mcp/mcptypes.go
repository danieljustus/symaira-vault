// Package mcp provides core types and shared utilities for the Model Context Protocol implementation.
package mcp

import (
	"fmt"
	"strconv"
)

// CallToolRequest represents a request to call an MCP tool
type CallToolRequest struct {
	Arguments map[string]any
}

func (r CallToolRequest) RequireString(key string) (string, error) {
	v, ok := r.Arguments[key]
	if !ok {
		return "", fmt.Errorf("missing string argument %q", key)
	}
	value, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("argument %q is not a string", key)
	}
	return value, nil
}

func (r CallToolRequest) RequireFloat(key string) (float64, error) {
	v, ok := r.Arguments[key]
	if !ok {
		return 0, fmt.Errorf("missing numeric argument %q", key)
	}
	switch value := v.(type) {
	case float64:
		return value, nil
	case float32:
		return float64(value), nil
	case int:
		return float64(value), nil
	case int64:
		return float64(value), nil
	case int32:
		return float64(value), nil
	case string:
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return 0, fmt.Errorf("argument %q is not numeric: %w", key, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("argument %q is not numeric", key)
	}
}

func (r CallToolRequest) GetString(key, def string) string {
	v, ok := r.Arguments[key]
	if !ok {
		return def
	}
	value, ok := v.(string)
	if !ok {
		return def
	}
	return value
}

func (r CallToolRequest) GetFloat(key string, def float64) float64 {
	v, ok := r.Arguments[key]
	if !ok {
		return def
	}
	switch value := v.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case int32:
		return float64(value)
	case string:
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return def
		}
		return parsed
	default:
		return def
	}
}

func (r CallToolRequest) GetBool(key string, def bool) bool {
	v, ok := r.Arguments[key]
	if !ok {
		return def
	}
	switch value := v.(type) {
	case bool:
		return value
	case string:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return def
		}
		return parsed
	default:
		return def
	}
}

// CallToolResult represents the result of calling an MCP tool
type CallToolResult struct {
	Text    string
	IsError bool
}

// NewToolResultError creates a new tool result representing an error
func NewToolResultError(msg string) *CallToolResult {
	return &CallToolResult{IsError: true, Text: msg}
}

// NewToolResultText creates a new tool result containing text
func NewToolResultText(text string) *CallToolResult {
	return &CallToolResult{Text: text}
}

// Tool represents an MCP tool definition
type Tool struct {
	Name        string
	Description string
}

// ToolOption configures a Tool
type ToolOption func(*Tool)

// NewTool creates a new Tool with the given name and options
func NewTool(name string, opts ...ToolOption) Tool {
	tool := Tool{Name: name}
	for _, opt := range opts {
		if opt != nil {
			opt(&tool)
		}
	}
	return tool
}

// WithDescription sets the tool description
func WithDescription(description string) ToolOption {
	return func(t *Tool) { t.Description = description }
}

// WithString is a no-op placeholder for string parameter definitions
func WithString(_ string, opts ...ToolOption) ToolOption {
	return func(t *Tool) {
		for _, opt := range opts {
			if opt != nil {
				opt(t)
			}
		}
	}
}

// WithNumber is a no-op placeholder for number parameter definitions
func WithNumber(_ string, opts ...ToolOption) ToolOption {
	return func(t *Tool) {
		for _, opt := range opts {
			if opt != nil {
				opt(t)
			}
		}
	}
}

// WithBoolean is a no-op placeholder for boolean parameter definitions
func WithBoolean(_ string, opts ...ToolOption) ToolOption {
	return func(t *Tool) {
		for _, opt := range opts {
			if opt != nil {
				opt(t)
			}
		}
	}
}

// Required is a no-op placeholder for required parameter definitions
func Required() ToolOption {
	return func(*Tool) {}
}

// Description is a no-op placeholder for parameter descriptions
func Description(_ string) ToolOption {
	return func(*Tool) {}
}

// DefaultNumber is a no-op placeholder for default number values
func DefaultNumber(_ float64) ToolOption {
	return func(*Tool) {}
}

// DefaultBool is a no-op placeholder for default boolean values
func DefaultBool(_ bool) ToolOption {
	return func(*Tool) {}
}

// Default is a no-op placeholder for default parameter values
func Default(_ any) ToolOption {
	return func(*Tool) {}
}

// Enum is a no-op placeholder for enum parameter values
func Enum(_ ...string) ToolOption {
	return func(*Tool) {}
}
