package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/danieljustus/OpenPass/internal/audit"
)

type contextKey string

const agentContextKey contextKey = "openpass-agent"

const tokenContextKey contextKey = "openpass-scoped-token"

func WithToken(ctx context.Context, token *ScopedToken) context.Context {
	return context.WithValue(ctx, tokenContextKey, token)
}

func TokenFromContext(ctx context.Context) (*ScopedToken, bool) {
	t, ok := ctx.Value(tokenContextKey).(*ScopedToken)
	return t, ok
}

// MaxRateLimiterEntries caps the rate-limiter's in-memory state to prevent
// memory exhaustion from many distinct source IPs (e.g. spoofed traffic).
// When the cap is reached, the oldest tracked entries are evicted.
const MaxRateLimiterEntries = 10000

type RateLimiter struct {
	attempts       map[string]*rateLimitEntry
	mu             sync.Mutex
	limit          int
	window         time.Duration
	maxEntries     int
	cleanupCount   int64
	evictionCount  int64
	log            *slog.Logger
	trustedProxies []string
}

type rateLimitEntry struct {
	resetAt time.Time
	count   int
}

func NewRateLimiter(limit int, dur time.Duration, trustedProxies ...string) *RateLimiter {
	return &RateLimiter{
		attempts:       make(map[string]*rateLimitEntry),
		limit:          limit,
		window:         dur,
		maxEntries:     MaxRateLimiterEntries,
		trustedProxies: trustedProxies,
	}
}

// SetMaxEntriesForTests overrides the eviction cap; intended only for tests.
func (rl *RateLimiter) SetMaxEntriesForTests(maxEntries int) {
	rl.mu.Lock()
	rl.maxEntries = maxEntries
	rl.mu.Unlock()
}

// EvictionCount returns how many entries have been forcibly evicted to honor
// the size cap. Useful for monitoring potential memory-DoS attempts.
func (rl *RateLimiter) EvictionCount() int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.evictionCount
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, ok := rl.attempts[ip]
	if !ok || now.After(entry.resetAt) {
		if rl.maxEntries > 0 && len(rl.attempts) >= rl.maxEntries {
			rl.evictOldestLocked(now)
		}
		rl.attempts[ip] = &rateLimitEntry{
			count:   1,
			resetAt: now.Add(rl.window),
		}
		return true
	}

	if entry.count >= rl.limit {
		return false
	}

	entry.count++
	return true
}

// evictOldestLocked drops expired entries first; if still over the cap,
// evicts the entry with the oldest resetAt. Caller must hold rl.mu.
func (rl *RateLimiter) evictOldestLocked(now time.Time) {
	for ip, e := range rl.attempts {
		if now.After(e.resetAt) {
			delete(rl.attempts, ip)
			rl.evictionCount++
			if len(rl.attempts) < rl.maxEntries {
				return
			}
		}
	}
	if len(rl.attempts) < rl.maxEntries {
		return
	}
	var oldestIP string
	var oldestReset time.Time
	first := true
	for ip, e := range rl.attempts {
		if first || e.resetAt.Before(oldestReset) {
			oldestIP = ip
			oldestReset = e.resetAt
			first = false
		}
	}
	if oldestIP != "" {
		delete(rl.attempts, oldestIP)
		rl.evictionCount++
	}
}

func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, entry := range rl.attempts {
		if now.After(entry.resetAt) {
			delete(rl.attempts, ip)
		}
	}
}

// StartCleanup starts a background goroutine that periodically calls Cleanup.
// It cleans up expired rate limit entries every interval duration until the context is canceled.
// Returns a cancellable stop function.
func (rl *RateLimiter) StartCleanup(ctx context.Context, interval time.Duration) func() {
	stopCh := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.cleanupOnce()
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() { close(stopCh) }
}

// cleanupOnce performs a single cleanup cycle, for testing and internal use.
func (rl *RateLimiter) cleanupOnce() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	var cleaned int
	for ip, entry := range rl.attempts {
		if now.After(entry.resetAt) {
			delete(rl.attempts, ip)
			cleaned++
		}
	}
	rl.cleanupCount += int64(cleaned)
	if cleaned > 0 && rl.log != nil {
		rl.log.Debug("rate limiter cleaned expired entries", "count", cleaned)
	}
}

// CleanupCount returns the total number of entries cleaned up since startup.
func (rl *RateLimiter) CleanupCount() int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.cleanupCount
}

func (rl *RateLimiter) Close() error {
	return nil
}

func RateLimiterMiddleware(rl *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(clientIP(r, rl.trustedProxies)) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func logAuthFailure(logger *audit.Logger, r *http.Request, reason, detail string) {
	if logger == nil {
		return
	}
	if err := logger.LogEntry(audit.LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Agent:     r.Header.Get("X-OpenPass-Agent"),
		Action:    "auth_failure",
		Transport: "http",
		Reason:    reason + ": " + detail,
		Path:      r.URL.Path,
		OK:        false,
	}); err != nil {
		slog.Default().Warn("audit log write failed", "err", err)
	}
}

func clientIP(r *http.Request, trustedProxies []string) string {
	if isTrustedProxy(r.RemoteAddr, trustedProxies) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx != -1 {
				xff = xff[:idx]
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}
	if ra := r.RemoteAddr; ra != "" {
		host, _, err := net.SplitHostPort(ra)
		if err == nil && host != "" {
			return host
		}
		return ra
	}
	return "unknown"
}

func isTrustedProxy(remoteAddr string, trustedProxies []string) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if host == "" {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, p := range trustedProxies {
		if strings.Contains(p, "/") {
			prefix, err := netip.ParsePrefix(p)
			if err == nil && prefix.Contains(addr) {
				return true
			}
		} else {
			trustedAddr, err := netip.ParseAddr(p)
			if err == nil && trustedAddr == addr {
				return true
			}
		}
	}
	return false
}

func BearerAuthMiddleware(legacyToken string, registry *TokenRegistry, auditLog *audit.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			logAuthFailure(auditLog, r, "missing_bearer", "authorization header missing or malformed")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		provided := strings.TrimPrefix(auth, "Bearer ")

		if legacyToken != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(legacyToken)) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		if registry != nil {
			hash := sha256Hex(provided)
			tok, ok := registry.Get(hash)
			if ok {
				ctx := WithToken(r.Context(), tok)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			registry.mu.RLock()
			t, exists := registry.entries[hash]
			registry.mu.RUnlock()
			if exists && t != nil {
				if t.Revoked {
					logAuthFailure(auditLog, r, "token_revoked", "token has been revoked")
				} else if t.IsExpired() {
					logAuthFailure(auditLog, r, "token_expired", "token has expired")
				}
			}
		}

		if legacyToken == "" && registry == nil {
			logAuthFailure(auditLog, r, "missing_token", "token not configured")
		} else {
			logAuthFailure(auditLog, r, "invalid_token", "token mismatch")
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func AgentHeaderMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent := r.Header.Get("X-OpenPass-Agent")
		if agent == "" {
			http.Error(w, "forbidden: missing X-OpenPass-Agent header", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), agentContextKey, agent)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func OriginValidationMiddleware(serverAddr string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" && !isAllowedOrigin(origin, r.Host, serverAddr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(NewErrorResponse(nil, ErrCodeInvalidRequest, "invalid Origin header", nil))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isAllowedOrigin(origin string, requestHost string, serverAddr string) bool {
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Scheme == "" || originURL.Host == "" {
		return false
	}

	originHost := strings.ToLower(originURL.Hostname())
	reqHost := strings.ToLower(stripPort(requestHost))
	bindHost := strings.ToLower(stripPort(serverAddr))

	if originHost == reqHost {
		return true
	}
	if bindHost != "" && originHost == bindHost {
		return true
	}
	return isLoopbackHost(originHost) && (isLoopbackHost(reqHost) || isLoopbackHost(bindHost))
}

func AgentFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(agentContextKey).(string); ok {
		return v
	}
	return ""
}
