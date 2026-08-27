package approval

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeTokens implements tokenValidator for tests.
type fakeTokens struct{ valid map[string]string }

func (f *fakeTokens) Validate(token string) (string, bool) {
	id, ok := f.valid[token]
	return id, ok
}

func TestListRequiresDeviceToken(t *testing.T) {
	q := NewQueue()
	h := NewHTTPHandler(q, &fakeTokens{valid: map[string]string{"tok-1": "device-1"}})

	req := httptest.NewRequest(http.MethodGet, PathApprovals, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestListReturnsPending(t *testing.T) {
	q := NewQueue()
	h := NewHTTPHandler(q, &fakeTokens{valid: map[string]string{"tok-1": "device-1"}})
	if _, err := q.Enqueue(Request{AgentName: "agent-a", Path: "work/creds", Write: true, Reason: "test"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, PathApprovals, nil)
	req.Header.Set("Authorization", "Bearer tok-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Requests []Entry `json:"requests"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Requests) != 1 || resp.Requests[0].AgentName != "agent-a" {
		t.Fatalf("requests = %+v", resp.Requests)
	}
	if resp.Requests[0].Path != "work/creds" {
		t.Fatalf("path = %q", resp.Requests[0].Path)
	}
}

func TestApproveWakesAndRecordsDevice(t *testing.T) {
	q := NewQueue()
	h := NewHTTPHandler(q, &fakeTokens{valid: map[string]string{"tok-1": "device-1"}})
	id, _ := q.Enqueue(Request{AgentName: "agent-a", Path: "p", Write: true})

	req := httptest.NewRequest(http.MethodPost, PathApprovalAction+id+"/approve", nil)
	req.Header.Set("Authorization", "Bearer tok-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Outcome Outcome `json:"outcome"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Outcome.Status != StatusApproved {
		t.Fatalf("outcome = %s", resp.Outcome.Status)
	}
	if resp.Outcome.DecidedBy != "device-1" {
		t.Fatalf("decided_by = %q", resp.Outcome.DecidedBy)
	}
}

func TestDenyRecordsDevice(t *testing.T) {
	q := NewQueue()
	h := NewHTTPHandler(q, &fakeTokens{valid: map[string]string{"tok-1": "device-1"}})
	id, _ := q.Enqueue(Request{AgentName: "agent-a", Path: "p", Write: true})

	req := httptest.NewRequest(http.MethodPost, PathApprovalAction+id+"/deny", nil)
	req.Header.Set("Authorization", "Bearer tok-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Outcome Outcome `json:"outcome"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Outcome.Status != StatusDenied || resp.Outcome.DecidedBy != "device-1" {
		t.Fatalf("outcome = %+v", resp.Outcome)
	}
}

func TestUnknownActionAndMissingID(t *testing.T) {
	q := NewQueue()
	h := NewHTTPHandler(q, &fakeTokens{valid: map[string]string{"tok-1": "device-1"}})

	req := httptest.NewRequest(http.MethodPost, PathApprovalAction+"nonexistent/approve", nil)
	req.Header.Set("Authorization", "Bearer tok-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, PathApprovalAction, nil)
	req2.Header.Set("Authorization", "Bearer tok-1")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing id)", rec2.Code)
	}
}

func TestDoubleDecisionConflict(t *testing.T) {
	q := NewQueue()
	h := NewHTTPHandler(q, &fakeTokens{valid: map[string]string{"tok-1": "device-1"}})
	id, _ := q.Enqueue(Request{AgentName: "agent-a", Path: "p", Write: true})

	decide := func() int {
		req := httptest.NewRequest(http.MethodPost, PathApprovalAction+id+"/approve", nil)
		req.Header.Set("Authorization", "Bearer tok-1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := decide(); code != http.StatusOK {
		t.Fatalf("first = %d", code)
	}
	if code := decide(); code != http.StatusConflict {
		t.Fatalf("second = %d, want 409", code)
	}
}

func TestRejectsMalformedAuthorization(t *testing.T) {
	q := NewQueue()
	h := NewHTTPHandler(q, &fakeTokens{valid: map[string]string{"tok-1": "device-1"}})
	id, _ := q.Enqueue(Request{AgentName: "a", Path: "p", Write: true})

	// "Bearer" without a token must be rejected.
	req := httptest.NewRequest(http.MethodPost, PathApprovalAction+id+"/approve", nil)
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body: %s)", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}
