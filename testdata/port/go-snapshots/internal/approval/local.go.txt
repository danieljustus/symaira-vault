package approval

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// Local API paths are authenticated with the vault-directory ownership proof
// and are accepted only from a loopback connection. They are deliberately
// separate from the enrolled-device API: the CLI is not a trusted device.
const (
	PathLocalApprovals      = "/api/v1/local/approvals"
	PathLocalApprovalAction = "/api/v1/local/approvals/"
)

// LocalHTTPHandler exposes the live queue to the local CLI without duplicating
// queue state in the CLI process.
type LocalHTTPHandler struct {
	queue      *Queue
	secret     []byte
	isLoopback func(string) bool
}

// NewLocalHTTPHandler creates a loopback-only, vault-proof-authenticated API.
func NewLocalHTTPHandler(queue *Queue, secret []byte, isLoopback func(string) bool) *LocalHTTPHandler {
	return &LocalHTTPHandler{queue: queue, secret: secret, isLoopback: isLoopback}
}

func (h *LocalHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if h.isLoopback == nil || !h.isLoopback(host) {
		writeApprovalError(w, http.StatusForbidden, "local approval API requires a loopback connection")
		return
	}
	if !verifyEnrollProof(h.secret, r.Header.Get(HeaderEnrollTimestamp), r.Header.Get(HeaderEnrollProof), time.Now()) {
		writeApprovalError(w, http.StatusUnauthorized, "missing or invalid proof of vault-directory ownership")
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == PathLocalApprovals:
		writeApprovalJSON(w, http.StatusOK, map[string]any{"requests": h.queue.Pending()})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, PathLocalApprovalAction):
		h.decide(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *LocalHTTPHandler) decide(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, PathLocalApprovalAction)
	id = strings.TrimSuffix(id, "/")
	var out Outcome
	var err error
	switch {
	case strings.HasSuffix(id, "/approve"):
		out, err = h.queue.Approve(strings.TrimSuffix(id, "/approve"), "local-cli")
	case strings.HasSuffix(id, "/deny"):
		out, err = h.queue.Deny(strings.TrimSuffix(id, "/deny"), "local-cli")
	default:
		writeApprovalError(w, http.StatusNotFound, "unknown approval action")
		return
	}
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, ErrNotFound) {
			status = http.StatusNotFound
		}
		writeApprovalError(w, status, err.Error())
		return
	}
	writeApprovalJSON(w, http.StatusOK, map[string]any{"outcome": out})
}
