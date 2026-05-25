package server

import (
	"context"
	"sync"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

// PreCallHook is invoked before a tool handler executes.
// It receives the current context, tool name, parsed arguments, and the server.
// It can modify and return the context to propagate values to subsequent hooks
// and the handler. If it returns a non-nil error, tool execution is aborted
// immediately and subsequent hooks are skipped.
type PreCallHook func(ctx context.Context, toolName string, args mcp.CallToolRequest, server *Server) (context.Context, error)

// PostCallHook is invoked after a tool handler executes.
// It receives the (possibly modified) context, tool name, parsed arguments,
// the tool result, and any error returned by the handler. It can modify and
// return the result and error. Returning a non-nil error from a post-call
// hook is logged but does NOT abort execution since the result has already
// been computed by the handler.
type PostCallHook func(ctx context.Context, toolName string, args mcp.CallToolRequest, result *mcp.CallToolResult, err error) (*mcp.CallToolResult, error)

// HookRegistry holds registered pre-call and post-call hooks with thread-safe
// registration and iteration.
type HookRegistry struct {
	mu        sync.RWMutex
	preHooks  []PreCallHook
	postHooks []PostCallHook
}

// NewHookRegistry creates a new empty HookRegistry.
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{}
}

// RegisterPreCallHook adds a pre-call hook to the registry.
// Registration is thread-safe.
func (r *HookRegistry) RegisterPreCallHook(hook PreCallHook) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preHooks = append(r.preHooks, hook)
}

// RegisterPostCallHook adds a post-call hook to the registry.
// Registration is thread-safe.
func (r *HookRegistry) RegisterPostCallHook(hook PostCallHook) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.postHooks = append(r.postHooks, hook)
}

// PreCallHooks returns a snapshot of all registered pre-call hooks.
func (r *HookRegistry) PreCallHooks() []PreCallHook {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	hooks := make([]PreCallHook, len(r.preHooks))
	copy(hooks, r.preHooks)
	return hooks
}

// PostCallHooks returns a snapshot of all registered post-call hooks.
func (r *HookRegistry) PostCallHooks() []PostCallHook {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	hooks := make([]PostCallHook, len(r.postHooks))
	copy(hooks, r.postHooks)
	return hooks
}

// Len returns the total number of registered hooks (pre + post).
func (r *HookRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.preHooks) + len(r.postHooks)
}
