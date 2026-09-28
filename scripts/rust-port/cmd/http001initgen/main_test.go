package main

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMainWritesSourceBoundFixture(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../.."))
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldDir); err != nil {
			t.Error(err)
		}
	}()
	oldArgs, oldCommandLine := os.Args, flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}()
	output := filepath.Join(t.TempDir(), "http-initialize.json")
	flag.CommandLine = flag.NewFlagSet("http001initgen", flag.ExitOnError)
	os.Args = []string{"http001initgen", "--output", output}
	main()
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var got fixture
	if err := json.Unmarshal(contents, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Cases) < 25 {
		t.Fatalf("generated %d oracle cases, want at least 25", len(got.Cases))
	}
	for _, name := range []string{"initialize", "authenticated_prompts_list_after_initialize"} {
		found := false
		for _, testCase := range got.Cases {
			if testCase.Name == name {
				found = true
				if name == "authenticated_prompts_list_after_initialize" && !testCase.Response.ConnectionReused {
					t.Fatalf("%s did not record HTTP keep-alive reuse", name)
				}
				break
			}
		}
		if !found {
			t.Fatalf("generated fixture omits %q", name)
		}
	}
}

func TestDoRequestRecordsKeepAliveReuse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Allow", "POST")
		w.Header().Set("MCP-Protocol-Version", "2025-11-25")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	client := server.Client()
	req := request{
		Method:          http.MethodGet,
		Path:            "/mcp",
		Host:            "fixture.test",
		Origin:          "http://127.0.0.1",
		ContentType:     "application/json",
		Accept:          "text/event-stream",
		ProtocolVersion: "2025-11-25",
		Agent:           "default",
		TokenName:       "fixture",
		Authenticated:   true,
		BodyRepeat:      4,
		HeaderRepeat:    3,
	}
	addr := strings.TrimPrefix(server.URL, "http://")
	if usesRawRequest(req) {
		t.Fatal("ordinary request unexpectedly selected raw-wire transport")
	}
	first := doRequest(client, addr, "fixture-token", map[string]string{"fixture": "scoped-token"}, req)
	second := doRequest(client, addr, "fixture-token", map[string]string{"fixture": "scoped-token"}, req)
	if first.ConnectionReused {
		t.Fatal("first request unexpectedly reused a connection")
	}
	if !second.ConnectionReused {
		t.Fatal("second request did not reuse the keep-alive connection")
	}
	for _, response := range []response{first, second} {
		if response.Status != http.StatusMethodNotAllowed || response.Body != "ok" {
			t.Fatalf("captured response = %+v", response)
		}
		if response.Headers["Content-Type"] != "application/json" || response.Headers["Allow"] != "POST" {
			t.Fatalf("captured response headers = %#v", response.Headers)
		}
		if len(response.AbsentHeader) != 0 {
			t.Fatalf("unexpected absent headers: %#v", response.AbsentHeader)
		}
	}
}

func TestDoRawRequestCapturesHTTP10AndDuplicateFraming(t *testing.T) {
	type seen struct {
		protocol string
		host     string
		path     string
		origin   string
		auth     []string
		body     string
	}
	seenRequests := make(chan seen, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		seenRequests <- seen{
			protocol: r.Proto,
			host:     r.Host,
			path:     r.URL.RequestURI(),
			origin:   r.Header.Get("Origin"),
			auth:     r.Header.Values("Authorization"),
			body:     string(body),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Allow", "POST")
		w.Header().Set("MCP-Protocol-Version", "2025-11-25")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("raw"))
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	req := request{
		Method:                 http.MethodPost,
		Path:                   "/mcp",
		Host:                   "fixture.test",
		Origin:                 "http://127.0.0.1",
		ContentType:            "application/json",
		Accept:                 "application/json, text/event-stream",
		ProtocolVersion:        "2025-11-25",
		Agent:                  "default",
		TokenName:              "fixture",
		Authenticated:          true,
		BodyRepeat:             5,
		HTTPVersion:            "HTTP/1.0",
		RequestLineRepeat:      5,
		DuplicateAuthorization: true,
	}
	if !usesRawRequest(req) {
		t.Fatal("raw-wire request unexpectedly selected HTTP client transport")
	}
	got := doRawRequest(addr, "fixture-token", map[string]string{"fixture": "scoped-token"}, req)
	if got.Status != http.StatusAccepted || got.Body != "raw" || got.ConnectionReused {
		t.Fatalf("captured raw response = %+v", got)
	}
	if got.Headers["Content-Type"] != "application/json" || got.Headers["Allow"] != "POST" {
		t.Fatalf("captured raw response headers = %#v", got.Headers)
	}
	observed := <-seenRequests
	if observed.protocol != "HTTP/1.0" || observed.host != "fixture.test" || observed.path != "/mcp?x=xxxxx" {
		t.Fatalf("raw request framing = %+v", observed)
	}
	if observed.origin != "http://127.0.0.1" || strings.Join(observed.auth, ",") != "Bearer scoped-token,Bearer invalid-second-value" || observed.body != "xxxxx" {
		t.Fatalf("raw request headers/body = %+v", observed)
	}

	badLength := request{
		Method:                 http.MethodPost,
		Path:                   "/mcp",
		Host:                   "fixture.test",
		ContentType:            "application/json",
		Accept:                 "application/json",
		ProtocolVersion:        "2025-11-25",
		Agent:                  "default",
		DuplicateContentLength: true,
	}
	got = doRawRequest(addr, "", nil, badLength)
	if got.Status != http.StatusBadRequest {
		t.Fatalf("duplicate Content-Length status = %d, want 400", got.Status)
	}
}
