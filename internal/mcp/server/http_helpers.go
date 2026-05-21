package server

import (
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"strings"

	transport "github.com/danieljustus/OpenPass/internal/mcp/transport"
)

// IsLoopbackBind reports whether bind is a loopback address.
func IsLoopbackBind(bind string) bool {
	host := strings.TrimSpace(bind)
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// WriteMCPHTTPError writes a JSON-RPC error response to w.
func WriteMCPHTTPError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	//nolint:errchkjson // Best-effort error response write; no recovery path if encoding fails
	_ = json.NewEncoder(w).Encode(transport.NewErrorResponse(id, code, message, nil))
}

// IsJSONContentType reports whether contentType is application/json.
func IsJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/json"
}

// AcceptsMCPHTTPResponse reports whether the Accept header values include
// both application/json and text/event-stream.
func AcceptsMCPHTTPResponse(values []string) bool {
	acceptsJSON := false
	acceptsSSE := false
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			switch mediaType {
			case "*/*", "application/*", "application/json":
				acceptsJSON = true
			case "text/event-stream":
				acceptsSSE = true
			}
		}
	}
	return acceptsJSON && acceptsSSE
}
