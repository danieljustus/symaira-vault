package approval

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/danieljustus/symaira-vault/internal/pairing"
)

// HTTP paths for device enrollment.
const (
	// PathDeviceEnrollCode mints a short-lived pairing code. Localhost-only:
	// it is how "symvault device approval-pair" asks the already-running
	// server for a code to embed in the pairing QR code.
	PathDeviceEnrollCode = "/api/v1/devices/enroll-code"
	// PathDeviceEnroll exchanges a pairing code for a long-lived device
	// session bearer token. Reachable from the LAN, like PathApprovals.
	PathDeviceEnroll = "/api/v1/devices/enroll"
)

// loopbackChecker is the minimal surface EnrollCodeHTTPHandler needs to
// decide whether a request's remote address is loopback. Satisfied by
// internal/mcp.IsLoopbackHost; abstracted here purely to avoid importing
// net/http-adjacent packages, not for testability beyond the default.
type loopbackChecker func(host string) bool

// EnrollCodeHTTPHandler mints short-lived device-pairing codes for
// PathDeviceEnrollCode. It must only ever be reachable from loopback — the
// caller (cmd/mcp/serve_deps.go) is responsible for constructing it with a
// fingerprint computed once at server startup, since a nil/empty fingerprint
// means TLS isn't configured and pairing must be refused rather than handing
// out a code that can't be safely used.
type EnrollCodeHTTPHandler struct {
	codes       *pairing.TokenStore
	fingerprint string
	isLoopback  loopbackChecker
}

// NewEnrollCodeHTTPHandler creates the local-only pairing-code minting
// handler. fingerprint is the SHA-256 fingerprint of the server's current
// TLS certificate (see internal/mcp/serverbootstrap.CertFingerprint); an
// empty fingerprint means TLS isn't available and every mint request is
// refused, since a device pairing without a pinned fingerprint would have no
// trust anchor.
func NewEnrollCodeHTTPHandler(codes *pairing.TokenStore, fingerprint string, isLoopback func(host string) bool) *EnrollCodeHTTPHandler {
	return &EnrollCodeHTTPHandler{codes: codes, fingerprint: fingerprint, isLoopback: isLoopback}
}

func (h *EnrollCodeHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if h.isLoopback == nil || !h.isLoopback(host) {
		writeApprovalError(w, http.StatusForbidden, "device pairing codes can only be minted from localhost")
		return
	}
	if h.fingerprint == "" {
		writeApprovalError(w, http.StatusServiceUnavailable, "TLS is not configured; device pairing requires TLS")
		return
	}
	token, err := pairing.GenerateToken()
	if err != nil {
		writeApprovalError(w, http.StatusInternalServerError, "generate pairing code")
		return
	}
	if err := h.codes.Store(token, ""); err != nil {
		writeApprovalError(w, http.StatusInternalServerError, "store pairing code")
		return
	}
	writeApprovalJSON(w, http.StatusOK, map[string]any{
		"code":        token.String(),
		"expires_at":  time.Now().UTC().Add(pairing.TokenTTL),
		"fingerprint": h.fingerprint,
	})
}

// EnrollHTTPHandler exchanges a pairing code minted by EnrollCodeHTTPHandler
// for a long-lived device session bearer token, via PathDeviceEnroll.
type EnrollHTTPHandler struct {
	codes    *pairing.TokenStore
	sessions *pairing.DeviceSessionStore
}

// NewEnrollHTTPHandler creates the device-enrollment handler. sessions
// should be the same DeviceSessionStore instance the approval HTTP handler
// validates bearer tokens against, so an enrolled device can use its token
// immediately.
func NewEnrollHTTPHandler(codes *pairing.TokenStore, sessions *pairing.DeviceSessionStore) *EnrollHTTPHandler {
	return &EnrollHTTPHandler{codes: codes, sessions: sessions}
}

type enrollRequest struct {
	Code       string `json:"code"`
	DeviceName string `json:"device_name"`
	PublicKey  string `json:"public_key"`
}

func (h *EnrollHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeApprovalError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	req.Code = strings.TrimSpace(req.Code)
	if req.Code == "" {
		writeApprovalError(w, http.StatusBadRequest, "missing pairing code")
		return
	}
	if _, ok := h.codes.Validate(req.Code); !ok {
		writeApprovalError(w, http.StatusUnauthorized, "invalid or expired pairing code")
		return
	}
	deviceID, err := generateDeviceID()
	if err != nil {
		writeApprovalError(w, http.StatusInternalServerError, "generate device id")
		return
	}
	token, err := h.sessions.Enroll(deviceID, req.DeviceName, req.PublicKey)
	if err != nil {
		writeApprovalError(w, http.StatusInternalServerError, "enroll device")
		return
	}
	writeApprovalJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"device_id":  deviceID,
		"expires_at": time.Now().UTC().Add(pairing.DefaultSessionTTL),
	})
}

func generateDeviceID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate device id: %w", err)
	}
	return "dev-" + hex.EncodeToString(b), nil
}
