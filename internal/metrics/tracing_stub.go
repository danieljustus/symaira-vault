//go:build !metrics

package metrics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

var noopTracer = noop.NewTracerProvider().Tracer("symaira")

// InitTracing returns a no-op shutdown function when metrics are not compiled in.
func InitTracing(_, _ string) (func(context.Context) error, error) {
	return func(_ context.Context) error { return nil }, nil
}

// Tracer returns a no-op tracer.
func Tracer() trace.Tracer {
	return noopTracer
}

// HashEntryPath hashes an entry path for privacy-preserving trace attributes.
func HashEntryPath(path string) string {
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:8])
}

// StartSpan starts a no-op span.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return noopTracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// SpanFromContext returns a no-op span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
