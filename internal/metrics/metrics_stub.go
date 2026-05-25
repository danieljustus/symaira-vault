//go:build !metrics

// Package metrics provides observability instrumentation (Prometheus metrics and
// OpenTelemetry tracing) for Symaira Vault. When compiled without the "metrics" build
// tag, all functions are no-ops.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var stubReg = prometheus.NewRegistry()

// RecordMCPRequest is a no-op when metrics are not compiled in.
func RecordMCPRequest(_, _, _ string, _ time.Duration) {}

// RecordAuthDenial is a no-op when metrics are not compiled in.
func RecordAuthDenial(_, _ string) {}

// RecordApproval is a no-op when metrics are not compiled in.
func RecordApproval(_, _ string) {}

// RecordVaultOperation is a no-op when metrics are not compiled in.
func RecordVaultOperation(_, _ string) {}

// RecordVaultEntryCount is a no-op when metrics are not compiled in.
func RecordVaultEntryCount(_ string, _ int) {}

// RecordVaultOperationDuration is a no-op when metrics are not compiled in.
func RecordVaultOperationDuration(_ string, _ time.Duration) {}

// RecordSessionCacheEvent is a no-op when metrics are not compiled in.
func RecordSessionCacheEvent(_ string) {}

// RecordIdentityCacheEvent is a no-op when metrics are not compiled in.
func RecordIdentityCacheEvent(_ string) {}

// RecordUpdateCheck is a no-op when metrics are not compiled in.
func RecordUpdateCheck(_ string) {}

// RecordPolicyEvalDuration is a no-op when metrics are not compiled in.
func RecordPolicyEvalDuration(_ time.Duration) {}

// Registry returns a fresh empty Prometheus registry.
// Without the metrics build tag, no collectors are registered
// and no Symaira Vault metrics are recorded.
func Registry() *prometheus.Registry {
	return stubReg
}
