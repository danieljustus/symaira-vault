package serverbootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func writeJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	buf, ok := bufferPool.Get().(*bytes.Buffer)
	if !ok {
		return
	}
	buf.Reset()
	defer func() {
		buf.Reset()
		bufferPool.Put(buf)
	}()
	//nolint:errchkjson
	_ = json.NewEncoder(buf).Encode(data)
	_, _ = w.Write(buf.Bytes())
}

func handleOAuthProtectedResource(bind string, port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := fmt.Sprintf("http://%s:%d", bind, port)
		writeJSON(w, http.StatusOK, map[string]any{
			"resource":                 addr + "/mcp",
			"bearer_methods_supported": []string{"header"},
			"resource_name":            "OpenPass MCP Server",
		})
	}
}

func handleOAuthAuthorizationServer(bind string, port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := fmt.Sprintf("http://%s:%d", bind, port)
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                addr,
			"authorization_endpoint":                addr + "/mcp/oauth/authorize",
			"token_endpoint":                        addr + "/mcp/oauth/token",
			"registration_endpoint":                 addr + "/oauth/register",
			"response_types_supported":              []string{"code"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		})
	}
}
