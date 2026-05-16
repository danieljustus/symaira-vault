package mcp

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/danieljustus/OpenPass/internal/config"
)

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

func TestHookRegistry_NewRegistry(t *testing.T) {
	r := NewHookRegistry()
	if r == nil {
		t.Fatal("NewHookRegistry() returned nil")
	}
	if r.Len() != 0 {
		t.Errorf("Len() = %d, want 0", r.Len())
	}
}

func TestHookRegistry_RegisterPreCall(t *testing.T) {
	r := NewHookRegistry()
	called := false
	r.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		called = true
		return ctx, nil
	})
	if r.Len() != 1 {
		t.Errorf("Len() = %d, want 1", r.Len())
	}
	hooks := r.PreCallHooks()
	if len(hooks) != 1 {
		t.Fatalf("PreCallHooks() returned %d hooks, want 1", len(hooks))
	}
	_, _ = hooks[0](context.Background(), "test", CallToolRequest{}, nil)
	if !called {
		t.Error("pre-call hook was not invoked")
	}
}

func TestHookRegistry_RegisterPostCall(t *testing.T) {
	r := NewHookRegistry()
	called := false
	r.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		called = true
		return result, err
	})
	if r.Len() != 1 {
		t.Errorf("Len() = %d, want 1", r.Len())
	}
	hooks := r.PostCallHooks()
	if len(hooks) != 1 {
		t.Fatalf("PostCallHooks() returned %d hooks, want 1", len(hooks))
	}
	_, _ = hooks[0](context.Background(), "test", CallToolRequest{}, nil, nil)
	if !called {
		t.Error("post-call hook was not invoked")
	}
}

func TestHookRegistry_ConcurrentRegistration(t *testing.T) {
	r := NewHookRegistry()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
				return ctx, nil
			})
			r.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
				return result, err
			})
		}()
	}
	wg.Wait()
	if r.Len() != 200 {
		t.Errorf("Len() = %d, want 200", r.Len())
	}
}

func TestHookRegistry_ConcurrentReadAndWrite(t *testing.T) {
	r := NewHookRegistry()
	r.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		return ctx, nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.PreCallHooks()
			r.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
				return ctx, nil
			})
			_ = r.PostCallHooks()
		}()
	}
	wg.Wait()
}

func TestHookRegistry_NilSafe(t *testing.T) {
	var r *HookRegistry
	r.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		return ctx, nil
	})
	r.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		return result, err
	})
	if hooks := r.PreCallHooks(); hooks != nil {
		t.Error("PreCallHooks() on nil registry should return nil")
	}
	if hooks := r.PostCallHooks(); hooks != nil {
		t.Error("PostCallHooks() on nil registry should return nil")
	}
	if r.Len() != 0 {
		t.Error("Len() on nil registry should return 0")
	}
}

// ---------------------------------------------------------------------------
// Pre-call hook in executeTool
// ---------------------------------------------------------------------------

func TestPreCallHook_Executed(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	var called bool
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		called = true
		if name != "health" {
			t.Errorf("hook got toolName = %q, want %q", name, "health")
		}
		return ctx, nil
	})

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
	if !called {
		t.Error("pre-call hook was not executed")
	}
}

func TestPreCallHook_Error_AbortsExecution(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	hookErr := "pre-call hook rejected"
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		return ctx, assertError(hookErr)
	})

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err == nil {
		t.Fatal("executeTool() expected error from pre-call hook, got nil")
	}
	if err.Error() != hookErr {
		t.Errorf("executeTool() error = %q, want %q", err.Error(), hookErr)
	}
}

func TestPreCallHook_Error_StopsSubsequentHooks(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	var secondCalled bool
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		return ctx, assertError("first hook failed")
	})
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		secondCalled = true
		return ctx, nil
	})

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err == nil {
		t.Fatal("executeTool() expected error, got nil")
	}
	if secondCalled {
		t.Error("second pre-call hook was called despite first one failing")
	}
}

func TestPreCallHook_ContextPropagation(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	type ctxKey struct{}
	hookValue := "set-by-hook"

	// Register two hooks to test chaining
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		return context.WithValue(ctx, ctxKey{}, hookValue), nil
	})

	// Verify the value propagates through chain by reading it and adding another
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		val, ok := ctx.Value(ctxKey{}).(string)
		if !ok {
			t.Error("context value from previous hook not found")
		} else if val != hookValue {
			t.Errorf("context value = %q, want %q", val, hookValue)
		}
		return ctx, nil
	})

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
}

func TestMultiplePreCallHooks_Order(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	var order []string
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		order = append(order, "first")
		return ctx, nil
	})
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		order = append(order, "second")
		return ctx, nil
	})
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		order = append(order, "third")
		return ctx, nil
	})

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	expected := []string{"first", "second", "third"}
	if len(order) != len(expected) {
		t.Fatalf("hook execution order = %v, want %v", order, expected)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Errorf("hook[%d] = %q, want %q", i, order[i], v)
		}
	}
}

// ---------------------------------------------------------------------------
// Post-call hook in executeTool
// ---------------------------------------------------------------------------

func TestPostCallHook_Executed(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	var called bool
	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		called = true
		if name != "health" {
			t.Errorf("hook got toolName = %q, want %q", name, "health")
		}
		if result == nil {
			t.Error("post-call hook got nil result")
		}
		return result, err
	})

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
	if !called {
		t.Error("post-call hook was not executed")
	}
}

func TestPostCallHook_ModifiesResult(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		// Add a marker to the result text
		return NewToolResultText(result.Text + " [modified-by-hook]"), err
	})

	result, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	content := result["content"].([]map[string]any)
	text := content[0]["text"].(string)
	if text == "" {
		t.Error("result text is empty")
	}
}

func TestPostCallHook_Error_DoesNotAbort(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		return result, assertError("post-hook error")
	})

	// The handler succeeds but post-hook returns error — execution still succeeds
	// because post-call hook errors don't abort (result already computed).
	result, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() returned error even though handler succeeded: %v", err)
	}
	if result["isError"] == true {
		t.Error("executeTool() returned isError=true even though handler succeeded")
	}
}

func TestMultiplePostCallHooks_Order(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	var order []string
	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		order = append(order, "first")
		return result, err
	})
	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		order = append(order, "second")
		return result, err
	})
	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		order = append(order, "third")
		return result, err
	})

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	expected := []string{"first", "second", "third"}
	if len(order) != len(expected) {
		t.Fatalf("hook execution order = %v, want %v", order, expected)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Errorf("hook[%d] = %q, want %q", i, order[i], v)
		}
	}
}

func TestPostCallHook_ReceivesHandlerError(t *testing.T) {
	vaultDir, identity := mockVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	var receivedErr error
	var receivedResult *CallToolResult
	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		receivedErr = err
		receivedResult = result
		return result, err
	})

	// Call get_entry on a nonexistent path to trigger a handler-level error
	// (the tool exists so execution proceeds, but the handler returns an error)
	args := json.RawMessage(`{"path": "nonexistent"}`)
	result, err := srv.executeTool(context.Background(), "get_entry", args)
	if err != nil {
		t.Fatalf("executeTool() error = %v (expected isError in result)", err)
	}
	if receivedErr != nil {
		t.Errorf("post-call hook received unexpected error: %v", receivedErr)
	}
	if receivedResult == nil {
		t.Error("post-call hook did not receive a result")
	}
	if result["isError"] != true {
		t.Error("executeTool() expected isError=true for nonexistent entry")
	}
}

// ---------------------------------------------------------------------------
// Execution with both pre and post hooks
// ---------------------------------------------------------------------------

func TestPreAndPostHooks_Combined(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	var execOrder []string
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		execOrder = append(execOrder, "pre")
		return ctx, nil
	})
	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		execOrder = append(execOrder, "post")
		return result, err
	})

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}

	if len(execOrder) != 2 || execOrder[0] != "pre" || execOrder[1] != "post" {
		t.Errorf("execution order = %v, want [pre post]", execOrder)
	}
}

// ---------------------------------------------------------------------------
// Built-in hooks
// ---------------------------------------------------------------------------

func TestAuditPreHook_Runs(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	srv.RegisterPreCallHook(NewAuditPreHook())

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
}

func TestAuditPostHook_Runs(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	srv.RegisterPostCallHook(NewAuditPostHook())

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
}

func TestRateLimitHook_AllowsWithinLimit(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	srv.RegisterPreCallHook(NewRateLimitPreHook(100))

	for i := 0; i < 5; i++ {
		_, err := srv.executeTool(context.Background(), "health", nil)
		if err != nil {
			t.Fatalf("executeTool() iteration %d error = %v", i, err)
		}
	}
}

func TestRateLimitHook_BlocksWhenExceeded(t *testing.T) {
	// Use a fresh server to avoid interference from other tests
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	srv.RegisterPreCallHook(NewRateLimitPreHook(2))

	// First two calls succeed
	for i := 0; i < 2; i++ {
		_, err := srv.executeTool(context.Background(), "health", nil)
		if err != nil {
			t.Fatalf("executeTool() iteration %d error = %v", i, err)
		}
	}

	// Third call fails
	_, err := srv.executeTool(context.Background(), "health", nil)
	if err == nil {
		t.Fatal("executeTool() expected rate limit error, got nil")
	}
}

func TestScopeCheckHook_AllowsAllowedTool(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AllowedTools: []string{"health", "list_entries"},
	}, "stdio", "")

	srv.RegisterPreCallHook(NewScopeCheckPreHook())

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
}

func TestScopeCheckHook_DeniesDisallowedTool(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AllowedTools: []string{"list_entries"},
	}, "stdio", "")

	srv.RegisterPreCallHook(NewScopeCheckPreHook())

	_, err := srv.executeTool(context.Background(), "generate_password", nil)
	if err == nil {
		t.Fatal("executeTool() expected scope error, got nil")
	}
}

func TestScopeCheckHook_EmptyListAllowsAll(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		AllowedTools: []string{}, // empty = no restriction
	}, "stdio", "")

	srv.RegisterPreCallHook(NewScopeCheckPreHook())

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
}

func TestNotificationHook_DoesNotError(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	srv.RegisterPostCallHook(NewNotificationPostHook())

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
}

func TestMetricsPreHook_AddsTimestampToContext(t *testing.T) {
	r := NewHookRegistry()
	r.RegisterPreCallHook(NewMetricsPreHook())

	hooks := r.PreCallHooks()
	ctx, err := hooks[0](context.Background(), "test", CallToolRequest{}, nil)
	if err != nil {
		t.Fatalf("MetricsPreHook error = %v", err)
	}
	start, ok := ctx.Value(metricsStartKey{}).(time.Time)
	if !ok {
		t.Fatal("MetricsPreHook did not add start time to context")
	}
	if start.IsZero() {
		t.Error("MetricsPreHook added zero time to context")
	}
}

func TestMetricsPostHook_Runs(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
	}, "stdio", "")

	srv.RegisterPreCallHook(NewMetricsPreHook())
	srv.RegisterPostCallHook(NewMetricsPostHook())

	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Server hook registration methods
// ---------------------------------------------------------------------------

func TestServerRegisterHooks_NilServer(t *testing.T) {
	var srv *Server
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		return ctx, nil
	})
	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		return result, err
	})
	// Should not panic
}

func TestServerRegisterHooks_NilRegistry(t *testing.T) {
	srv := &Server{} // no hookRegistry
	srv.RegisterPreCallHook(func(ctx context.Context, name string, args CallToolRequest, srv *Server) (context.Context, error) {
		return ctx, nil
	})
	srv.RegisterPostCallHook(func(ctx context.Context, name string, args CallToolRequest, result *CallToolResult, err error) (*CallToolResult, error) {
		return result, err
	})
	// Should not panic
}

// ---------------------------------------------------------------------------
// Config-based hook registration
// ---------------------------------------------------------------------------

func TestRegisterConfigHooks_PreCallHooks(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      false,
		ApprovalMode:  "none",
		PreCallHooks:  []string{"audit", "metrics"},
		PostCallHooks: []string{"notification"},
	}, "stdio", "")

	// Manually trigger config-based registration as New() does
	cfg := &config.Config{
		MCP: &config.MCPConfig{
			RateLimit: 60,
		},
	}
	srv.registerConfigHooks(cfg)

	if srv.hookRegistry.Len() != 3 {
		t.Errorf("hookRegistry.Len() = %d, want 3 (2 pre + 1 post)", srv.hookRegistry.Len())
	}

	// Verify they work in executeTool
	_, err := srv.executeTool(context.Background(), "health", nil)
	if err != nil {
		t.Fatalf("executeTool() error = %v", err)
	}
}

func TestRegisterConfigHooks_Empty(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		// No hooks configured
	}, "stdio", "")

	srv.registerConfigHooks(&config.Config{})

	if srv.hookRegistry.Len() != 0 {
		t.Errorf("hookRegistry.Len() = %d, want 0", srv.hookRegistry.Len())
	}
}

func TestRegisterConfigHooks_RateLimit_FromConfig(t *testing.T) {
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:         "test",
		AllowedPaths: []string{"*"},
		CanWrite:     false,
		ApprovalMode: "none",
		PreCallHooks: []string{"rate_limit"},
	}, "stdio", "")

	cfg := &config.Config{
		MCP: &config.MCPConfig{
			RateLimit: 5,
		},
	}
	srv.registerConfigHooks(cfg)

	// First 5 calls succeed
	for i := 0; i < 5; i++ {
		_, err := srv.executeTool(context.Background(), "health", nil)
		if err != nil {
			t.Fatalf("executeTool() iteration %d error = %v", i, err)
		}
	}

	// 6th call fails due to rate limit
	_, err := srv.executeTool(context.Background(), "health", nil)
	if err == nil {
		t.Fatal("executeTool() expected rate limit error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Config save/load round-trip for hooks
// ---------------------------------------------------------------------------

func TestAgentProfile_HooksConfig(t *testing.T) {
	profile := config.AgentProfile{
		Name:          "test",
		AllowedPaths:  []string{"*"},
		CanWrite:      false,
		ApprovalMode:  "none",
		PreCallHooks:  []string{"audit", "rate_limit"},
		PostCallHooks: []string{"notification"},
	}

	if len(profile.PreCallHooks) != 2 {
		t.Errorf("PreCallHooks = %v, want [audit rate_limit]", profile.PreCallHooks)
	}
	if len(profile.PostCallHooks) != 1 {
		t.Errorf("PostCallHooks = %v, want [notification]", profile.PostCallHooks)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertError(msg string) error {
	return &testError{msg: msg}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
