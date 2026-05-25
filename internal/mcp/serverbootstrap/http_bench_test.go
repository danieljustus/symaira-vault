package serverbootstrap

import (
	"bytes"
	"encoding/json"
	"testing"
)

// BenchmarkJSONEncodeDirect measures allocations from encoding a typical MCP
// response directly to an io.Writer (the pre-optimization pattern).
func BenchmarkJSONEncodeDirect(b *testing.B) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "symaira",
				"version": "1.0.0",
			},
		},
	}
	var buf bytes.Buffer

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = json.NewEncoder(&buf).Encode(payload)
	}
}

// BenchmarkJSONEncodePooled measures allocations from encoding the same
// payload using the pooled buffer (the optimized pattern).
func BenchmarkJSONEncodePooled(b *testing.B) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "symaira",
				"version": "1.0.0",
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := bufferPool.Get().(*bytes.Buffer)
		buf.Reset()
		_ = json.NewEncoder(buf).Encode(payload)
		buf.Reset()
		bufferPool.Put(buf)
	}
}
