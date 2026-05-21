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

// stripPort strips the port from a host:port string.
func stripPort(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	if strings.Count(hostport, ":") == 1 {
		if host, _, ok := strings.Cut(hostport, ":"); ok {
			return host
		}
	}
	return strings.Trim(hostport, "[]")
}

// isLoopbackHost reports whether host is a loopback host.
func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
