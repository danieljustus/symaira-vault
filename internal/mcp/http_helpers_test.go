package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"", true},
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", false},
		{"192.168.1.1", false},
		{"example.com", false},
	}
	for _, tc := range cases {
		got := IsLoopbackBind(tc.input)
		if got != tc.want {
			t.Errorf("IsLoopbackBind(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestWriteMCPHTTPError(t *testing.T) {
	w := httptest.NewRecorder()
	id := json.RawMessage(`1`)
	WriteMCPHTTPError(w, http.StatusBadRequest, id, -32600, "invalid request")

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, ok := body["error"]; !ok {
		t.Error("expected 'error' field in response body")
	}
}

func TestIsJSONContentType(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"text/plain", false},
		{"text/event-stream", false},
		{"", false},
		{"not-a-media-type!!!", false},
	}
	for _, tc := range cases {
		got := IsJSONContentType(tc.input)
		if got != tc.want {
			t.Errorf("IsJSONContentType(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestAcceptsMCPHTTPResponse(t *testing.T) {
	cases := []struct {
		name   string
		values []string
		want   bool
	}{
		{
			"both json and sse",
			[]string{"application/json", "text/event-stream"},
			true,
		},
		{
			"combined in one header",
			[]string{"application/json, text/event-stream"},
			true,
		},
		{
			"wildcard covers json",
			[]string{"*/*", "text/event-stream"},
			true,
		},
		{
			"missing sse",
			[]string{"application/json"},
			false,
		},
		{
			"missing json",
			[]string{"text/event-stream"},
			false,
		},
		{
			"empty",
			[]string{},
			false,
		},
		{
			"application wildcard covers json",
			[]string{"application/*", "text/event-stream"},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AcceptsMCPHTTPResponse(tc.values)
			if got != tc.want {
				t.Errorf("AcceptsMCPHTTPResponse(%v) = %v, want %v", tc.values, got, tc.want)
			}
		})
	}
}
