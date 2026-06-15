package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

func pollWithTimeout(t *testing.T, condition func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestBearerAuthRejects401WithoutToken(t *testing.T) {
	handler := BearerAuthMiddleware("secret-token", nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBearerAuthRejectsWhenConfiguredTokenEmpty(t *testing.T) {
	handler := BearerAuthMiddleware("", nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBearerAuthRejects401WithWrongToken(t *testing.T) {
	handler := BearerAuthMiddleware("secret-token", nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBearerAuthAcceptsValidToken(t *testing.T) {
	handler := BearerAuthMiddleware("secret-token", nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAgentHeaderRejects403WhenMissing(t *testing.T) {
	handler := AgentHeaderMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestAgentHeaderSetsContext(t *testing.T) {
	var gotAgent string
	handler := AgentHeaderMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgent = AgentFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Symaira-Agent", "claude-code")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotAgent != "claude-code" {
		t.Fatalf("agent = %q, want %q", gotAgent, "claude-code")
	}
}

func TestAgentHeaderRejectsScopedTokenAgentMismatch(t *testing.T) {
	handler := AgentHeaderMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached for mismatched token agent")
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Symaira-Agent", "opencode")
	req = req.WithContext(WithToken(req.Context(), &ScopedToken{AgentName: "claude-code"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestAgentHeaderAcceptsScopedTokenAgentMatch(t *testing.T) {
	handler := AgentHeaderMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Symaira-Agent", "claude-code")
	req = req.WithContext(WithToken(req.Context(), &ScopedToken{AgentName: "claude-code"}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAgentHeaderAllowsLegacyUnscopedToken(t *testing.T) {
	handler := BearerAuthMiddleware("legacy-secret", nil, nil, AgentHeaderMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer legacy-secret")
	req.Header.Set("X-Symaira-Agent", "opencode")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRateLimiterStartCleanupPeriodic(t *testing.T) {
	rl := NewRateLimiter(5, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rl.Allow("192.168.1.1")
	rl.Allow("192.168.1.2")

	stop := rl.StartCleanup(ctx, 30*time.Millisecond)
	defer stop()

	pollWithTimeout(t, func() bool {
		return rl.CleanupCount() >= 1
	}, 500*time.Millisecond, "expected at least 1 cleanup cycle")
}

func TestRateLimiterStartCleanupStopsOnCancel(t *testing.T) {
	rl := NewRateLimiter(5, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	_ = rl.StartCleanup(ctx, 20*time.Millisecond)
	pollWithTimeout(t, func() bool {
		return rl.CleanupCount() >= 0
	}, 100*time.Millisecond, "wait for cleanup goroutine to start")
	cancel()

	countAfterCancel := rl.CleanupCount()
	pollWithTimeout(t, func() bool {
		return rl.CleanupCount() == countAfterCancel
	}, 200*time.Millisecond, "CleanupCount should stay same after cancel")
}

func TestRateLimiterStartCleanupStopFunc(t *testing.T) {
	rl := NewRateLimiter(5, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := rl.StartCleanup(ctx, 20*time.Millisecond)
	pollWithTimeout(t, func() bool {
		return rl.CleanupCount() >= 0
	}, 100*time.Millisecond, "wait for cleanup goroutine to start")
	stop()

	countAfterStop := rl.CleanupCount()
	pollWithTimeout(t, func() bool {
		return rl.CleanupCount() == countAfterStop
	}, 200*time.Millisecond, "CleanupCount should stay same after stop")
}

func TestRateLimiterAllowNewIP(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	if !rl.Allow("192.168.1.1") {
		t.Fatal("expected first attempt to be allowed")
	}
}

func TestRateLimiterAllowWithinLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	ip := "192.168.1.2"

	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("expected attempt %d to be allowed", i+1)
		}
	}
}

func TestRateLimiterDeniesOverLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	ip := "192.168.1.3"

	if !rl.Allow(ip) {
		t.Fatal("expected first attempt to be allowed")
	}
	if !rl.Allow(ip) {
		t.Fatal("expected second attempt to be allowed")
	}
	if rl.Allow(ip) {
		t.Fatal("expected third attempt to be denied")
	}
}

func TestRateLimiterAllowAfterWindow(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond)
	ip := "192.168.1.4"

	if !rl.Allow(ip) {
		t.Fatal("expected first attempt to be allowed")
	}
	if !rl.Allow(ip) {
		t.Fatal("expected second attempt to be allowed")
	}
	if rl.Allow(ip) {
		t.Fatal("expected third attempt to be denied")
	}

	time.Sleep(60 * time.Millisecond)

	if !rl.Allow(ip) {
		t.Fatal("expected attempt after window to be allowed")
	}
}

func TestRateLimiterIndependentIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)

	if !rl.Allow("10.0.0.1") {
		t.Fatal("expected 10.0.0.1 first attempt to be allowed")
	}
	if !rl.Allow("10.0.0.1") {
		t.Fatal("expected 10.0.0.1 second attempt to be allowed")
	}
	if rl.Allow("10.0.0.1") {
		t.Fatal("expected 10.0.0.1 third attempt to be denied")
	}

	if !rl.Allow("10.0.0.2") {
		t.Fatal("expected 10.0.0.2 first attempt to be allowed")
	}
	if !rl.Allow("10.0.0.2") {
		t.Fatal("expected 10.0.0.2 second attempt to be allowed")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	rl := NewRateLimiter(5, 50*time.Millisecond)

	rl.Allow("192.168.1.10")
	rl.Allow("192.168.1.11")

	time.Sleep(60 * time.Millisecond)

	rl.Cleanup()

	if !rl.Allow("192.168.1.10") {
		t.Fatal("expected attempt after cleanup to be allowed for 192.168.1.10")
	}
	if !rl.Allow("192.168.1.11") {
		t.Fatal("expected attempt after cleanup to be allowed for 192.168.1.11")
	}
}

func TestRateLimiterEvictsAtCap(t *testing.T) {
	rl := NewRateLimiter(5, time.Hour)
	rl.SetMaxEntriesForTests(4)

	for i := 0; i < 10; i++ {
		rl.Allow(fmt.Sprintf("10.0.0.%d", i))
	}

	rl.mu.Lock()
	got := len(rl.attempts)
	rl.mu.Unlock()
	if got > 4 {
		t.Fatalf("expected len(attempts) <= 4 after cap-driven eviction, got %d", got)
	}
	if rl.EvictionCount() == 0 {
		t.Fatal("expected EvictionCount > 0")
	}
}

func TestRateLimiterEvictsExpiredFirstWhenAtCap(t *testing.T) {
	rl := NewRateLimiter(5, 5*time.Millisecond)
	rl.SetMaxEntriesForTests(3)

	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.2")
	rl.Allow("10.0.0.3")
	time.Sleep(10 * time.Millisecond) // expire all three

	// New insert at cap → evictOldestLocked should clear all expired ones.
	rl.Allow("10.0.0.4")

	rl.mu.Lock()
	got := len(rl.attempts)
	rl.mu.Unlock()
	if got > 3 {
		t.Fatalf("expected len(attempts) <= 3, got %d", got)
	}
}

func TestRateLimiterCleanupOnlyExpired(t *testing.T) {
	rl := NewRateLimiter(5, time.Hour)

	rl.Allow("192.168.1.12")
	rl.Allow("192.168.1.13")

	rl.Cleanup()

	if !rl.Allow("192.168.1.12") {
		t.Fatal("expected second attempt to be allowed for 192.168.1.12")
	}
	if !rl.Allow("192.168.1.13") {
		t.Fatal("expected second attempt to be allowed for 192.168.1.13")
	}
}

func TestRateLimiterCleanupCount(t *testing.T) {
	rl := NewRateLimiter(5, 50*time.Millisecond)

	if rl.CleanupCount() != 0 {
		t.Fatalf("expected initial cleanup count to be 0, got %d", rl.CleanupCount())
	}

	rl.Allow("192.168.1.14")
	rl.Allow("192.168.1.15")
	rl.Allow("192.168.1.16")

	time.Sleep(60 * time.Millisecond)

	rl.cleanupOnce()

	if rl.CleanupCount() != 3 {
		t.Fatalf("expected cleanup count to be 3, got %d", rl.CleanupCount())
	}
}

func TestRateLimiterClose(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	if err := rl.Close(); err != nil {
		t.Fatalf("expected Close to return nil, got %v", err)
	}
}

func TestRateLimiterMiddlewareAllowsRequest(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	handler := RateLimiterMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRateLimiterMiddlewareRateLimits(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	handler := RateLimiterMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/mcp", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

func TestRateLimiterMiddlewareDifferentIPs(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	handler := RateLimiterMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/mcp", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("10.0.0.1 request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("10.0.0.1 status = %d, want 429", rec.Code)
	}

	req2 := httptest.NewRequest("POST", "/mcp", nil)
	req2.RemoteAddr = "10.0.0.2:12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("10.0.0.2 status = %d, want 200", rec2.Code)
	}
}

func TestClientIPXForwardedFor(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")
	req.RemoteAddr = "10.0.0.1:12345"

	ip := clientIP(req, []string{"10.0.0.1"})
	if ip != "203.0.113.195" {
		t.Fatalf("clientIP = %q, want 203.0.113.195", ip)
	}
}

func TestClientIPXRealIP(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100")
	req.RemoteAddr = "10.0.0.1:12345"

	ip := clientIP(req, []string{"10.0.0.1"})
	if ip != "192.168.1.100" {
		t.Fatalf("clientIP = %q, want 192.168.1.100", ip)
	}
}

func TestClientIPRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.RemoteAddr = "192.168.1.50:54321"

	ip := clientIP(req, nil)
	if ip != "192.168.1.50" {
		t.Fatalf("clientIP = %q, want 192.168.1.50", ip)
	}
}

func TestClientIPRemoteAddrNoPort(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.RemoteAddr = "192.168.1.50"

	ip := clientIP(req, nil)
	if ip != "192.168.1.50" {
		t.Fatalf("clientIP = %q, want 192.168.1.50", ip)
	}
}

func TestClientIPUnknown(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.RemoteAddr = ""

	ip := clientIP(req, nil)
	if ip != "unknown" {
		t.Fatalf("clientIP = %q, want unknown", ip)
	}
}

func TestClientIPUntrustedProxyIgnoresXFF(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	req.RemoteAddr = "10.0.0.1:12345"

	ip := clientIP(req, []string{"192.168.1.1"})
	if ip != "10.0.0.1" {
		t.Fatalf("clientIP = %q, want 10.0.0.1 (untrusted proxy should use RemoteAddr)", ip)
	}
}

func TestClientIPTrustedProxyUsesXFF(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195, 70.41.3.18")
	req.RemoteAddr = "10.0.0.1:12345"

	ip := clientIP(req, []string{"10.0.0.1"})
	if ip != "203.0.113.195" {
		t.Fatalf("clientIP = %q, want 203.0.113.195", ip)
	}
}

func TestClientIPTrustedProxyUsesXRealIP(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100")
	req.RemoteAddr = "10.0.0.1:12345"

	ip := clientIP(req, []string{"10.0.0.1"})
	if ip != "192.168.1.100" {
		t.Fatalf("clientIP = %q, want 192.168.1.100", ip)
	}
}

func TestClientIPNoTrustedProxiesDefault(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	req.RemoteAddr = "10.0.0.1:12345"

	ip := clientIP(req, nil)
	if ip != "10.0.0.1" {
		t.Fatalf("clientIP = %q, want 10.0.0.1 (no trusted proxies should use RemoteAddr)", ip)
	}
}

func TestClientIPCIDRTrustedProxy(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	req.RemoteAddr = "10.0.0.1:12345"

	ip := clientIP(req, []string{"10.0.0.0/24"})
	if ip != "203.0.113.195" {
		t.Fatalf("clientIP = %q, want 203.0.113.195", ip)
	}
}

func TestClientIPTrustedProxyIPv6(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.195")
	req.RemoteAddr = "[::1]:12345"

	ip := clientIP(req, []string{"::1"})
	if ip != "203.0.113.195" {
		t.Fatalf("clientIP = %q, want 203.0.113.195", ip)
	}
}

func TestRateLimiterMiddlewareTrustedProxyXFF(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, "10.0.0.1")
	handler := RateLimiterMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request from "real" client via trusted proxy
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.50")
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", rec.Code)
	}

	// Second request from same real client via trusted proxy
	req2 := httptest.NewRequest("POST", "/mcp", nil)
	req2.Header.Set("X-Forwarded-For", "192.168.1.50")
	req2.RemoteAddr = "10.0.0.1:12345"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second request: status = %d, want 200", rec2.Code)
	}

	// Third request from same real client via trusted proxy should be rate limited
	req3 := httptest.NewRequest("POST", "/mcp", nil)
	req3.Header.Set("X-Forwarded-For", "192.168.1.50")
	req3.RemoteAddr = "10.0.0.1:12345"
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: status = %d, want 429", rec3.Code)
	}
}

func TestRateLimiterMiddlewareUntrustedProxySpoofedXFF(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute, "10.0.0.1")
	handler := RateLimiterMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Spoofed XFF from untrusted client — rate limit applies to RemoteAddr
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/mcp", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.50")
		req.RemoteAddr = "10.0.0.2:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	// Third request from same untrusted client should be rate limited (based on RemoteAddr)
	req3 := httptest.NewRequest("POST", "/mcp", nil)
	req3.Header.Set("X-Forwarded-For", "192.168.1.50")
	req3.RemoteAddr = "10.0.0.2:12345"
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: status = %d, want 429", rec3.Code)
	}
}

func TestRateLimiterConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter(100, time.Minute)
	ip := "192.168.1.100"

	var wg sync.WaitGroup
	allowed := make(chan bool, 200)

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- rl.Allow(ip)
		}()
	}

	wg.Wait()
	close(allowed)

	allowedCount := 0
	for a := range allowed {
		if a {
			allowedCount++
		}
	}

	if allowedCount != 100 {
		t.Fatalf("expected 100 allowed requests, got %d", allowedCount)
	}
}

func TestOriginValidationMiddleware_AllowsEmptyOrigin(t *testing.T) {
	handler := OriginValidationMiddleware("127.0.0.1:8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestOriginValidationMiddleware_AllowsSameOrigin(t *testing.T) {
	handler := OriginValidationMiddleware("127.0.0.1:8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestOriginValidationMiddleware_RejectsInvalidOrigin(t *testing.T) {
	handler := OriginValidationMiddleware("127.0.0.1:8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestOriginValidationMiddleware_AllowsLoopback(t *testing.T) {
	handler := OriginValidationMiddleware("127.0.0.1:8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Host = "localhost:8080"
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestIsAllowedOrigin(t *testing.T) {
	tests := []struct {
		name        string
		origin      string
		requestHost string
		serverAddr  string
		expected    bool
	}{
		{"empty origin", "", "localhost:8080", "127.0.0.1:8080", false},
		{"same host", "http://localhost:8080", "localhost:8080", "127.0.0.1:8080", true},
		{"same as bind", "http://127.0.0.1:8080", "localhost:8080", "127.0.0.1:8080", true},
		{"loopback to loopback", "http://127.0.0.1:8080", "127.0.0.1:8080", "127.0.0.1:8080", true},
		{"localhost to loopback", "http://localhost:8080", "127.0.0.1:8080", "127.0.0.1:8080", true},
		{"invalid origin", "not-a-url", "localhost:8080", "127.0.0.1:8080", false},
		{"missing scheme", "localhost:8080", "localhost:8080", "127.0.0.1:8080", false},
		{"external origin", "http://evil.com", "localhost:8080", "127.0.0.1:8080", false},
		{"ipv6 loopback", "http://[::1]:8080", "[::1]:8080", "127.0.0.1:8080", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAllowedOrigin(tt.origin, tt.requestHost, tt.serverAddr)
			if result != tt.expected {
				t.Errorf("isAllowedOrigin(%q, %q, %q) = %v, want %v", tt.origin, tt.requestHost, tt.serverAddr, result, tt.expected)
			}
		})
	}
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1:8080", "127.0.0.1"},
		{"localhost:8080", "localhost"},
		{"127.0.0.1", "127.0.0.1"},
		{"localhost", "localhost"},
		{"[::1]:8080", "::1"},
		{"", ""},
		{"  ", ""},
		{"[2001:db8::1]:8080", "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mcp.StripPort(tt.input)
			if result != tt.expected {
				t.Errorf("mcp.StripPort(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host     string
		expected bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"[::1]", true},
		{"::1", true},
		{"192.168.1.1", false},
		{"0.0.0.0", false},
		{"", false},
		{"example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			result := mcp.IsLoopbackHost(tt.host)
			if result != tt.expected {
				t.Errorf("mcp.IsLoopbackHost(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

func TestLogAuthFailure_NilLogger(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp", nil)
	logAuthFailure(nil, req, "test", "detail")
}

func TestBearerAuthMissingBearerPrefix(t *testing.T) {
	handler := BearerAuthMiddleware("secret-token", nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Basic secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBearerAuthScopedTokenAccepted(t *testing.T) {
	dir := t.TempDir()
	regPath := TokenRegistryFilePath(dir)
	reg := NewTokenRegistry(regPath)
	st, raw, err := reg.Create("test-scoped", []string{"get_entry"}, "test-agent", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	_ = st

	handler := BearerAuthMiddleware("", reg, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := TokenFromContext(r.Context())
		if !ok {
			t.Fatal("TokenFromContext returned false, expected scoped token in context")
		}
		if tok.ID == "" {
			t.Fatal("token ID should not be empty")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestBearerAuthLegacyTokenWinsOverRegistry(t *testing.T) {
	dir := t.TempDir()
	regPath := TokenRegistryFilePath(dir)
	reg := NewTokenRegistry(regPath)
	_, scopedRaw, err := reg.Create("scoped", []string{"get_entry"}, "", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	handler := BearerAuthMiddleware("legacy-secret", reg, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasToken := TokenFromContext(r.Context())
		if hasToken {
			t.Error("legacy token should not inject scoped token into context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer legacy-secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	_ = scopedRaw
}

func TestBearerAuthScopedTokenExpired(t *testing.T) {
	dir := t.TempDir()
	regPath := TokenRegistryFilePath(dir)
	reg := NewTokenRegistry(regPath)
	_, raw, err := reg.Create("short-lived", []string{"*"}, "", 1*time.Nanosecond)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	handler := BearerAuthMiddleware("", reg, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached for expired token")
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBearerAuthScopedTokenRevoked(t *testing.T) {
	dir := t.TempDir()
	regPath := TokenRegistryFilePath(dir)
	reg := NewTokenRegistry(regPath)
	st, raw, err := reg.Create("revoke-me", []string{"*"}, "", 0)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !reg.Revoke(st.ID) {
		t.Fatal("Revoke() failed")
	}

	handler := BearerAuthMiddleware("", reg, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached for revoked token")
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBearerAuthNilRegistryBackwardCompat(t *testing.T) {
	handler := BearerAuthMiddleware("my-token", nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer my-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestBearerAuthNoTokenFullyMissing(t *testing.T) {
	handler := BearerAuthMiddleware("", nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached")
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBearerAuthScopedTokenUnknownHash(t *testing.T) {
	dir := t.TempDir()
	regPath := TokenRegistryFilePath(dir)
	reg := NewTokenRegistry(regPath)
	_, _, err := reg.Create("known", []string{"*"}, "", 1*time.Hour)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	handler := BearerAuthMiddleware("", reg, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached for unknown token")
	}))

	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer not-a-known-token-at-all")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestWithTokenAndTokenFromContextRoundtrip(t *testing.T) {
	tok := &ScopedToken{
		ID:           "tok-roundtrip",
		Label:        "test",
		Hash:         sha256Hex("test-me"),
		Prefix:       "test",
		AllowedTools: []string{"get_entry"},
	}
	ctx := WithToken(context.Background(), tok)

	got, ok := TokenFromContext(ctx)
	if !ok {
		t.Fatal("TokenFromContext returned false")
	}
	if got.ID != tok.ID {
		t.Fatalf("ID = %q, want %q", got.ID, tok.ID)
	}
	if got.Label != tok.Label {
		t.Fatalf("Label = %q, want %q", got.Label, tok.Label)
	}
}

func TestTokenFromContextEmpty(t *testing.T) {
	tok, ok := TokenFromContext(context.Background())
	if ok {
		t.Fatal("TokenFromContext should return false for empty context")
	}
	if tok != nil {
		t.Fatal("TokenFromContext should return nil for empty context")
	}
}
