//go:build metrics

package serverbootstrap

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/mcp/auth"
	"github.com/danieljustus/symaira-vault/internal/mcp/server"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// registerMetricsEndpoint registers the /metrics endpoint on the given mux.
// When built with the metrics tag, it serves Prometheus metrics with
// configurable bearer auth for non-loopback binds.
func registerMetricsEndpoint(mux *http.ServeMux, v *vaultpkg.Vault, bind string, legacyToken string, tokenRegistry *auth.TokenRegistry, authAuditLog *audit.Logger) {
	h := promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{})
	metricsAuthRequired := true
	if v != nil && v.Config != nil && v.Config.MCP != nil {
		metricsAuthRequired = v.Config.MCP.MetricsAuthRequired
	}
	if !server.IsLoopbackBind(bind) && metricsAuthRequired {
		mux.Handle("/metrics", auth.BearerAuthMiddleware(legacyToken, tokenRegistry, authAuditLog, h))
	} else {
		mux.Handle("/metrics", h)
	}
}
