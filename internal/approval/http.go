// Package approval provides the HTTP transport for the pending-approval
// queue: an enrolled approval device (mobile client) lists pending agent
// requests and approves/denies them. Requests are authenticated with a
// pairing token from the device enrolment, so only a paired device can
// decide.
package approval

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/pairing"
)

// HTTP paths served by the approval transport.
const (
	PathApprovals      = "/api/v1/approvals"
	PathApprovalAction = "/api/v1/approvals/"
)

// tokenValidator is the minimal pairing-token surface the handler needs.
type tokenValidator interface {
	Validate(token string) (string, bool)
}

// HTTPHandler exposes the approval queue over HTTP for enrolled devices.
type HTTPHandler struct {
	queue  *Queue
	tokens tokenValidator
}

// NewHTTPHandler creates the approval API handler. tokens validates device
// pairing tokens (nil disables the device auth gate for tests/embedders).
func NewHTTPHandler(queue *Queue, tokens tokenValidator) *HTTPHandler {
	return &HTTPHandler{queue: queue, tokens: tokens}
}

// ServeHTTP dispatches the approval API endpoints.
func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == PathApprovals:
		h.list(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(path, PathApprovalAction):
		h.decide(w, r)
	default:
		http.NotFound(w, r)
	}
}

// deviceFromRequest validates the bearer token and returns the paired device
// id, or an empty string when unauthorized.
func (h *HTTPHandler) deviceFromRequest(r *http.Request) string {
	if h.tokens == nil {
		return "test-device"
	}
	authz := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authz, "Bearer ")
	if token == "" || token == authz {
		return ""
	}
	deviceID, ok := h.tokens.Validate(token)
	if !ok {
		return ""
	}
	return deviceID
}

func (h *HTTPHandler) list(w http.ResponseWriter, r *http.Request) {
	if h.deviceFromRequest(r) == "" {
		writeApprovalError(w, http.StatusUnauthorized, "unauthorized: valid device token required")
		return
	}
	entries := h.queue.Pending()
	writeApprovalJSON(w, http.StatusOK, map[string]any{
		"requests": entries,
	})
}

func (h *HTTPHandler) decide(w http.ResponseWriter, r *http.Request) {
	deviceID := h.deviceFromRequest(r)
	if deviceID == "" {
		writeApprovalError(w, http.StatusUnauthorized, "unauthorized: valid device token required")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, PathApprovalAction)
	id = strings.TrimSuffix(id, "/")
	if id == "" {
		writeApprovalError(w, http.StatusBadRequest, "missing approval request id")
		return
	}

	var out Outcome
	var err error
	switch {
	case strings.HasSuffix(id, "/approve"):
		base := strings.TrimSuffix(id, "/approve")
		out, err = h.queue.Approve(base, deviceID)
	case strings.HasSuffix(id, "/deny"):
		base := strings.TrimSuffix(id, "/deny")
		out, err = h.queue.Deny(base, deviceID)
	default:
		writeApprovalError(w, http.StatusNotFound, "unknown approval action")
		return
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeApprovalError(w, http.StatusNotFound, err.Error())
			return
		}
		writeApprovalError(w, http.StatusConflict, err.Error())
		return
	}
	writeApprovalJSON(w, http.StatusOK, map[string]any{
		"outcome": out,
	})
}

func writeApprovalJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errchkjson // response payloads are fixed structs/maps; best-effort write
	_ = json.NewEncoder(w).Encode(payload)
}

func writeApprovalError(w http.ResponseWriter, status int, message string) {
	writeApprovalJSON(w, status, map[string]any{"error": message})
}

// pairingTokenStore adapts *pairing.TokenStore to tokenValidator.
type pairingTokenStore struct{ store *pairing.TokenStore }

// NewPairingTokenValidator wraps a pairing token store as a validator.
func NewPairingTokenValidator(store *pairing.TokenStore) tokenValidator {
	if store == nil {
		return nil
	}
	return &pairingTokenStore{store: store}
}

func (p *pairingTokenStore) Validate(token string) (string, bool) {
	return p.store.Validate(token)
}
