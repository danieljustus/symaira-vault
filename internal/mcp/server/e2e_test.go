package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/danieljustus/symaira-vault/internal/mcp/auth"
	transport "github.com/danieljustus/symaira-vault/internal/mcp/transport"
)

func pollWithTimeout(t *testing.T, condition func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *safeBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Reset()
}

func TestE2E_Stdio_Initialize(t *testing.T) {
	pr, pw := io.Pipe()
	out := &safeBuffer{}
	st := transport.NewStdioTransportWithIO(pr, out)
	handler := NewProtocolHandler("symaira", "1.0.0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = st.Start(ctx, handler.HandleMessage)
	}()

	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}` + "\n"
	mustPipeWrite(t, pw, initReq)

	var response transport.Message
	pollWithTimeout(t, func() bool {
		data := out.String()
		if data == "" {
			return false
		}
		lines := strings.Split(strings.TrimSpace(data), "\n")
		for _, line := range lines {
			if err := json.Unmarshal([]byte(line), &response); err == nil && response.ID != nil {
				return true
			}
		}
		return false
	}, "expected initialize response")

	if response.Error != nil {
		t.Fatalf("initialize returned error: %v", response.Error)
	}
	if response.Result == nil {
		t.Fatal("expected result in initialize response")
	}

	out.Reset()
	mustPipeWrite(t, pw, `{"jsonrpc":"2.0","method":"initialized"}`+"\n")
	time.Sleep(50 * time.Millisecond)

	out.Reset()
	listReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n"
	mustPipeWrite(t, pw, listReq)

	pollWithTimeout(t, func() bool {
		data := out.String()
		if data == "" {
			return false
		}
		lines := strings.Split(strings.TrimSpace(data), "\n")
		for _, line := range lines {
			if err := json.Unmarshal([]byte(line), &response); err == nil && response.ID != nil {
				return true
			}
		}
		return false
	}, "expected tools/list response")

	if response.Error != nil {
		t.Fatalf("tools/list returned error: %v", response.Error)
	}

	mustPipeClose(t, pw)
	cancel()
}

func TestE2E_HTTP_Initialize(t *testing.T) {
	token := "test-secret-token"
	agentName := "test-agent"

	handler := newHTTPMCPTestHandler()

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest("POST", server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`))
	req.Header.Set("X-Symaira-Agent", agentName)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	req = httptest.NewRequest("POST", server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without agent header, got %d", rec.Code)
	}

	req = httptest.NewRequest("POST", server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Symaira-Agent", agentName)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid auth, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	var response transport.Message
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("initialize returned error: %v", response.Error)
	}
	if response.Result == nil {
		t.Fatal("expected result in initialize response")
	}
}

func TestE2E_Stdio_Ping(t *testing.T) {
	pr, pw := io.Pipe()
	out := &safeBuffer{}
	st := transport.NewStdioTransportWithIO(pr, out)
	handler := NewProtocolHandler("symaira", "1.0.0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = st.Start(ctx, handler.HandleMessage)
	}()

	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}` + "\n"
	mustPipeWrite(t, pw, initReq)

	var response transport.Message
	pollWithTimeout(t, func() bool {
		data := out.String()
		if data == "" {
			return false
		}
		lines := strings.Split(strings.TrimSpace(data), "\n")
		for _, line := range lines {
			if err := json.Unmarshal([]byte(line), &response); err == nil && response.ID != nil {
				return true
			}
		}
		return false
	}, "expected initialize response")

	out.Reset()
	mustPipeWrite(t, pw, `{"jsonrpc":"2.0","method":"initialized"}`+"\n")
	time.Sleep(50 * time.Millisecond)

	out.Reset()
	pingReq := `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"
	mustPipeWrite(t, pw, pingReq)

	pollWithTimeout(t, func() bool {
		data := out.String()
		if data == "" {
			return false
		}
		lines := strings.Split(strings.TrimSpace(data), "\n")
		for _, line := range lines {
			if err := json.Unmarshal([]byte(line), &response); err == nil && response.ID != nil {
				return true
			}
		}
		return false
	}, "expected ping response")

	if response.Error != nil {
		t.Fatalf("ping returned error: %v", response.Error)
	}
	if response.Result == nil {
		t.Fatal("expected result in ping response")
	}

	mustPipeClose(t, pw)
	cancel()
}

func TestE2E_HTTP_Ping(t *testing.T) {
	token := "test-secret-token"
	agentName := "test-agent"

	handler := newHTTPMCPTestHandler()

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest("POST", server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Symaira-Agent", agentName)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	var response transport.Message
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if response.Error != nil {
		t.Fatalf("ping returned error: %v", response.Error)
	}
	if response.Result == nil {
		t.Fatal("expected result in ping response")
	}
}

func TestE2E_Stdio_InvalidJSON(t *testing.T) {
	pr, pw := io.Pipe()
	out := &safeBuffer{}
	st := transport.NewStdioTransportWithIO(pr, out)
	handler := NewProtocolHandler("symaira", "1.0.0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = st.Start(ctx, handler.HandleMessage)
	}()

	mustPipeWrite(t, pw, `{invalid json}`+"\n")

	var response transport.Message
	pollWithTimeout(t, func() bool {
		data := out.String()
		if data == "" {
			return false
		}
		lines := strings.Split(strings.TrimSpace(data), "\n")
		for _, line := range lines {
			if err := json.Unmarshal([]byte(line), &response); err == nil && response.Error != nil {
				return true
			}
		}
		return false
	}, "expected error response for invalid JSON")

	if response.Error == nil {
		t.Fatal("expected error response")
	}
	if response.Error.Code != transport.ErrCodeParseError {
		t.Fatalf("expected parse error code %d, got %d", transport.ErrCodeParseError, response.Error.Code)
	}

	mustPipeClose(t, pw)
	cancel()
}

func testHTTPMCPError(t *testing.T, body string, wantCode int, wantErrCode int) {
	t.Helper()
	const token = "test-secret-token"
	const agentName = "test-agent"

	handler := newHTTPMCPTestHandler()
	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest("POST", server.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Symaira-Agent", agentName)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != wantCode {
		t.Fatalf("expected %d, got %d", wantCode, rec.Code)
	}

	respBody, _ := io.ReadAll(rec.Body)
	var response transport.Message
	if err := json.Unmarshal(respBody, &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if response.Error == nil {
		t.Fatal("expected error response")
	}
	if response.Error.Code != wantErrCode {
		t.Fatalf("expected error code %d, got %d", wantErrCode, response.Error.Code)
	}
}

func TestE2E_HTTP_InvalidJSON(t *testing.T) {
	testHTTPMCPError(t, `{invalid json}`, http.StatusBadRequest, transport.ErrCodeParseError)
}

func TestE2E_Stdio_UnknownMethod(t *testing.T) {
	pr, pw := io.Pipe()
	out := &safeBuffer{}
	st := transport.NewStdioTransportWithIO(pr, out)
	handler := NewProtocolHandler("symaira", "1.0.0", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		_ = st.Start(ctx, handler.HandleMessage)
	}()

	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}` + "\n"
	mustPipeWrite(t, pw, initReq)

	var response transport.Message
	pollWithTimeout(t, func() bool {
		data := out.String()
		if data == "" {
			return false
		}
		lines := strings.Split(strings.TrimSpace(data), "\n")
		for _, line := range lines {
			if err := json.Unmarshal([]byte(line), &response); err == nil && response.ID != nil {
				return true
			}
		}
		return false
	}, "expected initialize response")

	out.Reset()
	mustPipeWrite(t, pw, `{"jsonrpc":"2.0","method":"initialized"}`+"\n")
	time.Sleep(50 * time.Millisecond)

	out.Reset()
	mustPipeWrite(t, pw, `{"jsonrpc":"2.0","id":2,"method":"unknown/method"}`+"\n")

	pollWithTimeout(t, func() bool {
		data := out.String()
		if data == "" {
			return false
		}
		lines := strings.Split(strings.TrimSpace(data), "\n")
		for _, line := range lines {
			if err := json.Unmarshal([]byte(line), &response); err == nil && response.Error != nil {
				return true
			}
		}
		return false
	}, "expected error response for unknown method")

	if response.Error == nil {
		t.Fatal("expected error response")
	}
	if response.Error.Code != transport.ErrCodeMethodNotFound {
		t.Fatalf("expected method not found error code %d, got %d", transport.ErrCodeMethodNotFound, response.Error.Code)
	}

	mustPipeClose(t, pw)
	cancel()
}

func TestE2E_HTTP_UnknownMethod(t *testing.T) {
	testHTTPMCPError(t, `{"jsonrpc":"2.0","id":1,"method":"unknown/method"}`, http.StatusOK, transport.ErrCodeMethodNotFound)
}

func TestE2E_Stdio_ContextCancel(t *testing.T) {
	pr, pw := io.Pipe()
	out := &safeBuffer{}
	st := transport.NewStdioTransportWithIO(pr, out)
	handler := NewProtocolHandler("symaira", "1.0.0", nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- st.Start(ctx, handler.HandleMessage)
	}()

	time.Sleep(10 * time.Millisecond)

	mustPipeClose(t, pw)
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transport did not stop after context cancel")
	}
}

func newHTTPMCPTestHandler() http.Handler {
	const token = "test-secret-token"
	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var msg transport.Message
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(transport.NewErrorResponse(nil, transport.ErrCodeParseError, "invalid JSON", nil))
			return
		}

		handler := NewProtocolHandler("symaira", "1.0.0", nil)
		resp, err := handler.HandleMessage(r.Context(), &msg)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(transport.NewErrorResponse(msg.ID, transport.ErrCodeInternalError, err.Error(), nil))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	return auth.RateLimiterMiddleware(
		auth.NewRateLimiter(100, time.Minute),
		auth.BearerAuthMiddleware(token, nil, nil, auth.AgentHeaderMiddleware(mcpHandler)),
	)
}

func mustPipeWrite(t *testing.T, pw *io.PipeWriter, data string) {
	t.Helper()
	if _, err := pw.Write([]byte(data)); err != nil {
		t.Fatalf("pipe write failed: %v", err)
	}
}

func mustPipeClose(t *testing.T, pw *io.PipeWriter) {
	t.Helper()
	if err := pw.Close(); err != nil {
		t.Fatalf("pipe close failed: %v", err)
	}
}
