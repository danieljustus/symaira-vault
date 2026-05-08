// Package metrics provides Prometheus metrics for OpenPass MCP server.
//
// It instruments MCP tool calls, authentication denials, approval outcomes,
// and vault operations with counters and histograms suitable for monitoring
// and alerting in production deployments.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Version is the application version, injected at build time.
var Version = "dev"

var registry = prometheus.NewRegistry()

func init() {
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

var (
	mcpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openpass",
			Subsystem: "mcp",
			Name:      "requests_total",
			Help:      "Total number of MCP tool requests.",
		},
		[]string{"tool", "agent", "status"},
	)

	mcpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openpass",
			Subsystem: "mcp",
			Name:      "request_duration_seconds",
			Help:      "Duration of MCP tool requests in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"tool", "agent"},
	)
)

var (
	mcpAuthDenialsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openpass",
			Subsystem: "mcp",
			Name:      "auth_denials_total",
			Help:      "Total number of MCP authentication/authorization denials.",
		},
		[]string{"reason", "agent"},
	)
)

var (
	mcpApprovalsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openpass",
			Subsystem: "mcp",
			Name:      "approvals_total",
			Help:      "Total number of MCP approval outcomes.",
		},
		[]string{"agent", "outcome"},
	)
)

var (
	vaultOperationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openpass",
			Subsystem: "vault",
			Name:      "operations_total",
			Help:      "Total number of vault operations.",
		},
		[]string{"operation", "status"},
	)
)

var (
	vaultEntriesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "openpass",
			Subsystem: "vault",
			Name:      "entries_total",
			Help:      "Total number of entries in the vault.",
		},
		[]string{"vault"},
	)

	vaultOperationDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openpass",
			Subsystem: "vault",
			Name:      "operation_duration_seconds",
			Help:      "Duration of vault operations in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"op"},
	)

	sessionCacheEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openpass",
			Subsystem: "session",
			Name:      "cache_events_total",
			Help:      "Total number of session cache events.",
		},
		[]string{"event"},
	)

	identityCacheEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openpass",
			Subsystem: "session",
			Name:      "identity_cache_events_total",
			Help:      "Total number of identity cache events.",
		},
		[]string{"event"},
	)

	updateCheckTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "openpass",
			Subsystem: "update",
			Name:      "check_total",
			Help:      "Total number of update check results.",
		},
		[]string{"result"},
	)

	policyEvalDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "openpass",
			Subsystem: "policy",
			Name:      "eval_duration_seconds",
			Help:      "Duration of policy evaluations in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{},
	)
)

func init() {
	registry.MustRegister(
		mcpRequestsTotal,
		mcpRequestDuration,
		mcpAuthDenialsTotal,
		mcpApprovalsTotal,
		vaultOperationsTotal,
		vaultEntriesTotal,
		vaultOperationDurationSeconds,
		sessionCacheEventsTotal,
		identityCacheEventsTotal,
		updateCheckTotal,
		policyEvalDurationSeconds,
	)
}

// RecordMCPRequest records an MCP tool request with its duration.
// status should be "success" or "error".
func RecordMCPRequest(tool, agent, status string, duration time.Duration) {
	mcpRequestsTotal.WithLabelValues(tool, agent, status).Inc()
	mcpRequestDuration.WithLabelValues(tool, agent).Observe(duration.Seconds())
}

// RecordAuthDenial records an authentication or authorization denial.
// reason should describe why access was denied (e.g., "scope_denied", "write_denied").
func RecordAuthDenial(reason, agent string) {
	mcpAuthDenialsTotal.WithLabelValues(reason, agent).Inc()
}

// RecordApproval records an approval outcome for a write operation.
// outcome should be "granted" or "denied".
func RecordApproval(agent, outcome string) {
	mcpApprovalsTotal.WithLabelValues(agent, outcome).Inc()
}

// RecordVaultOperation records a vault operation.
// operation describes the action (e.g., "read", "write", "delete").
// status should be "success" or "error".
func RecordVaultOperation(operation, status string) {
	vaultOperationsTotal.WithLabelValues(operation, status).Inc()
}

// RecordVaultEntryCount sets the total number of entries in the vault.
func RecordVaultEntryCount(vaultDir string, count int) {
	vaultEntriesTotal.WithLabelValues(vaultDir).Set(float64(count))
}

// RecordVaultOperationDuration records the duration of a vault operation.
// op should be one of: "open", "decrypt", "encrypt", "search", "list".
func RecordVaultOperationDuration(op string, duration time.Duration) {
	vaultOperationDurationSeconds.WithLabelValues(op).Observe(duration.Seconds())
}

// RecordSessionCacheEvent records a session cache event.
// event should be one of: "hit", "miss", "refresh", "evict", "keyring_unavailable".
func RecordSessionCacheEvent(event string) {
	sessionCacheEventsTotal.WithLabelValues(event).Inc()
}

// RecordIdentityCacheEvent records an identity cache event.
// event should be one of: "hit", "miss", "refresh", "evict".
func RecordIdentityCacheEvent(event string) {
	identityCacheEventsTotal.WithLabelValues(event).Inc()
}

// RecordUpdateCheck records an update check result.
// result should be one of: "up_to_date", "update_available", "error", "cache_hit".
func RecordUpdateCheck(result string) {
	updateCheckTotal.WithLabelValues(result).Inc()
}

// RecordPolicyEvalDuration records the duration of a policy evaluation.
func RecordPolicyEvalDuration(duration time.Duration) {
	policyEvalDurationSeconds.WithLabelValues().Observe(duration.Seconds())
}

// Registry returns the Prometheus registry used by OpenPass.
// Use this with promhttp.HandlerFor to serve metrics over HTTP.
func Registry() *prometheus.Registry {
	return registry
}
