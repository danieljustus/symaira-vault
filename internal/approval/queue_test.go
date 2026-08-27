package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEnqueueListPending(t *testing.T) {
	q := NewQueue()
	id, err := q.Enqueue(Request{AgentName: "agent-a", Path: "work/creds", Write: true})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if id == "" {
		t.Fatal("empty id")
	}
	entries := q.Pending()
	if len(entries) != 1 || entries[0].ID != id || entries[0].Status != StatusPending {
		t.Fatalf("pending = %+v", entries)
	}
}

func TestApproveWakesWaiter(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue(Request{AgentName: "a", Path: "p", Write: true})

	done := make(chan Outcome, 1)
	go func() {
		out, err := q.Wait(context.Background(), id)
		if err != nil {
			done <- Outcome{Status: StatusExpired}
			return
		}
		done <- out
	}()

	time.Sleep(50 * time.Millisecond)
	out, err := q.Approve(id, "device-1")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if out.Status != StatusApproved {
		t.Fatalf("outcome = %s", out.Status)
	}
	select {
	case got := <-done:
		if got.Status != StatusApproved {
			t.Fatalf("waiter outcome = %s", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter not woken")
	}
}

func TestDenyWakesWaiter(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue(Request{AgentName: "a", Path: "p", Write: true})
	done := make(chan Outcome, 1)
	go func() {
		out, _ := q.Wait(context.Background(), id)
		done <- out
	}()
	time.Sleep(50 * time.Millisecond)
	if _, err := q.Deny(id, "device-1"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	select {
	case got := <-done:
		if got.Status != StatusDenied {
			t.Fatalf("waiter outcome = %s", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter not woken")
	}
}

func TestWaitContextCancel(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue(Request{AgentName: "a", Path: "p", Write: true})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := q.Wait(ctx, id)
	if err == nil {
		t.Fatal("expected context error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("wait did not respect context deadline")
	}
	// The request must still be pending and decidable after the waiter left.
	if _, err := q.Approve(id, "device-1"); err != nil {
		t.Fatalf("approve after waiter cancel: %v", err)
	}
}

func TestReapExpired(t *testing.T) {
	q := NewQueueWithTTL(50 * time.Millisecond)
	id, _ := q.Enqueue(Request{AgentName: "a", Path: "p", Write: true})

	done := make(chan Outcome, 1)
	go func() {
		out, err := q.Wait(context.Background(), id)
		if err != nil {
			done <- Outcome{Status: StatusExpired}
			return
		}
		done <- out
	}()

	time.Sleep(150 * time.Millisecond)
	n := q.ReapExpired()
	if n != 1 {
		t.Fatalf("reaped = %d, want 1", n)
	}
	select {
	case got := <-done:
		if got.Status != StatusExpired {
			t.Fatalf("waiter outcome = %s", got.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expired waiter not woken")
	}
	e, err := q.Get(id)
	if err != nil || e.Status != StatusExpired {
		t.Fatalf("entry = %+v err %v", e, err)
	}
}

func TestDecideTwiceFails(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue(Request{AgentName: "a", Path: "p", Write: true})
	if _, err := q.Approve(id, "d1"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if _, err := q.Deny(id, "d2"); err == nil {
		t.Fatal("second decision should fail")
	}
}

func TestNotFound(t *testing.T) {
	q := NewQueue()
	if _, err := q.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := q.Approve("nope", "d"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestListOrderPendingFirst(t *testing.T) {
	q := NewQueue()
	first, _ := q.Enqueue(Request{AgentName: "a", Path: "p1", Write: true})
	second, _ := q.Enqueue(Request{AgentName: "a", Path: "p2", Write: true})
	if _, err := q.Approve(first, "d"); err != nil {
		t.Fatal(err)
	}
	entries := q.List()
	if len(entries) != 2 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].ID != second || entries[0].Status != StatusPending {
		t.Fatalf("first entry = %+v, want pending second", entries[0])
	}
	if entries[1].ID != first || entries[1].Status != StatusApproved {
		t.Fatalf("second entry = %+v", entries[1])
	}
}

func TestNotifyOnChange(t *testing.T) {
	q := NewQueue()
	ch := q.Notify()
	id, _ := q.Enqueue(Request{AgentName: "a", Path: "p", Write: true})
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no notify on enqueue")
	}
	// Drain; the next event is the decision.
	select {
	case <-ch:
	default:
	}
	if _, err := q.Approve(id, "d"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("no notify on decision")
	}
}

func TestCloseExpiresPending(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue(Request{AgentName: "a", Path: "p", Write: true})
	q.Close()
	e, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if e.Status != StatusExpired {
		t.Fatalf("status = %s", e.Status)
	}
	if _, err := q.Enqueue(Request{AgentName: "b", Path: "q", Write: true}); !errors.Is(err, ErrClosed) {
		t.Fatalf("enqueue after close err = %v", err)
	}
}
