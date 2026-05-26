//go:build metrics

package metrics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

var tracer trace.Tracer

// InitTracing initializes OpenTelemetry tracing with an OTLP HTTP exporter.
// If endpoint is empty, tracing is disabled and a no-op tracer is used.
// The endpoint is read from SYMVAULT_OTLP_ENDPOINT (or OPENPASS_OTLP_ENDPOINT
// as fallback) if not provided.
func InitTracing(endpoint, serviceName string) (func(context.Context) error, error) {
	if endpoint == "" {
		endpoint = os.Getenv("SYMVAULT_OTLP_ENDPOINT")
		if endpoint == "" {
			endpoint = os.Getenv("OPENPASS_OTLP_ENDPOINT")
		}
	}
	if endpoint == "" {
		tracer = otel.GetTracerProvider().Tracer("symvault")
		return func(_ context.Context) error { return nil }, nil
	}

	if serviceName == "" {
		serviceName = "symvault"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		// Use HTTP/protobuf by default (OTLP standard)
		// The endpoint is the base URL; the exporter appends /v1/traces
	)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(Version),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create trace resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	tracer = tp.Tracer("symvault")

	shutdown := func(ctx context.Context) error {
		return tp.Shutdown(ctx)
	}

	return shutdown, nil
}

// Tracer returns the Symaira Vault tracer. If tracing is not initialized, returns a no-op tracer.
func Tracer() trace.Tracer {
	if tracer == nil {
		return otel.GetTracerProvider().Tracer("symvault")
	}
	return tracer
}

// HashEntryPath hashes an entry path for privacy-preserving trace attributes.
func HashEntryPath(path string) string {
	h := sha256.Sum256([]byte(path))
	return hex.EncodeToString(h[:8])
}

// StartSpan starts a new span with the given name and attributes.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, trace.WithAttributes(attrs...))
}

// SpanFromContext returns the current span from context, or nil if none.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
