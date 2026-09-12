package approval

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLocalHTTPHandlerListAndDecide(t *testing.T) {
	q := NewQueue()
	id, err := q.Enqueue(Request{AgentName: "agent", Path: "work/file", Write: true, Reason: "write"})
	if err != nil {
		t.Fatal(err)
	}
	h := NewLocalHTTPHandler(q, []byte("test-secret"), func(host string) bool { return host == "127.0.0.1" })

	list := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, PathLocalApprovals, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	now := time.Now().UTC()
	req.Header.Set(HeaderEnrollTimestamp, now.Format(time.RFC3339))
	req.Header.Set(HeaderEnrollProof, EnrollProof([]byte("test-secret"), now))
	h.ServeHTTP(list, req)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), id) || strings.Contains(list.Body.String(), "test-secret") {
		t.Fatalf("list response = %d %s", list.Code, list.Body.String())
	}

	decide := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, PathLocalApprovalAction+id+"/approve", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	now = time.Now().UTC()
	req.Header.Set(HeaderEnrollTimestamp, now.Format(time.RFC3339))
	req.Header.Set(HeaderEnrollProof, EnrollProof([]byte("test-secret"), now))
	h.ServeHTTP(decide, req)
	if decide.Code != http.StatusOK || !strings.Contains(decide.Body.String(), `"approved"`) {
		t.Fatalf("decide response = %d %s", decide.Code, decide.Body.String())
	}
	if _, err := q.Approve(id, "second"); err == nil {
		t.Fatal("repeated decision unexpectedly succeeded")
	}
}

func TestLocalHTTPHandlerRejectsRemoteAndBadProof(t *testing.T) {
	q := NewQueue()
	_, _ = q.Enqueue(Request{AgentName: "agent", Path: "work/file"})
	h := NewLocalHTTPHandler(q, []byte("test-secret"), func(host string) bool { return host == "127.0.0.1" })
	for _, tc := range []struct {
		name   string
		remote string
		proof  bool
		want   int
	}{
		{name: "remote", remote: "192.0.2.1:1", proof: true, want: http.StatusForbidden},
		{name: "bad proof", remote: "127.0.0.1:1", proof: false, want: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, PathLocalApprovals, nil)
			req.RemoteAddr = tc.remote
			if tc.proof {
				now := time.Now().UTC()
				req.Header.Set(HeaderEnrollTimestamp, now.Format(time.RFC3339))
				req.Header.Set(HeaderEnrollProof, EnrollProof([]byte("test-secret"), now))
			} else {
				req.Header.Set(HeaderEnrollTimestamp, time.Now().UTC().Format(time.RFC3339))
				req.Header.Set(HeaderEnrollProof, "invalid")
			}
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

func TestLocalHTTPHandlerDenyAndErrorStatuses(t *testing.T) {
	q := NewQueue()
	id, err := q.Enqueue(Request{AgentName: "agent", Path: "read/file"})
	if err != nil {
		t.Fatal(err)
	}
	h := NewLocalHTTPHandler(q, []byte("test-secret"), func(host string) bool { return host == "127.0.0.1" })
	request := func(method, path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		now := time.Now().UTC()
		req.Header.Set(HeaderEnrollTimestamp, now.Format(time.RFC3339))
		req.Header.Set(HeaderEnrollProof, EnrollProof([]byte("test-secret"), now))
		h.ServeHTTP(rr, req)
		return rr
	}
	if rr := request(http.MethodPost, PathLocalApprovalAction+id+"/deny"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"denied"`) {
		t.Fatalf("deny response = %d %s", rr.Code, rr.Body.String())
	}
	for _, tc := range []struct {
		name, method, path string
		want               int
	}{
		{"invalid id", http.MethodPost, PathLocalApprovalAction + "not-an-id/approve", http.StatusNotFound},
		{"unknown action", http.MethodPost, PathLocalApprovalAction + id + "/later", http.StatusNotFound},
		{"wrong method", http.MethodPut, PathLocalApprovals, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rr := request(tc.method, tc.path); rr.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

func TestLocalHTTPHandlerEmptyQueueAndExpiry(t *testing.T) {
	q := NewQueueWithTTL(5 * time.Millisecond)
	h := NewLocalHTTPHandler(q, []byte("test-secret"), func(host string) bool { return host == "127.0.0.1" })
	id, err := q.Enqueue(Request{AgentName: "agent", Path: "read/file"})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(15 * time.Millisecond)
	now := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, PathLocalApprovals, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(HeaderEnrollTimestamp, now.Format(time.RFC3339))
	req.Header.Set(HeaderEnrollProof, EnrollProof([]byte("test-secret"), now))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"requests":[]}` {
		t.Fatalf("expired list response = %d %s", rr.Code, rr.Body.String())
	}

	q2 := NewQueue()
	h2 := NewLocalHTTPHandler(q2, []byte("test-secret"), func(host string) bool { return host == "127.0.0.1" })
	now = time.Now().UTC()
	req = httptest.NewRequest(http.MethodPost, PathLocalApprovalAction+id+"/approve", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set(HeaderEnrollTimestamp, now.Format(time.RFC3339))
	req.Header.Set(HeaderEnrollProof, EnrollProof([]byte("test-secret"), now))
	rr = httptest.NewRecorder()
	h2.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown queue id status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}
