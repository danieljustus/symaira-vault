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
