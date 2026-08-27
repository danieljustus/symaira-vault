package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
)

// approvalAuthorizer builds an authorizer in prompt mode with an approval
// queue attached.
func approvalAuthorizer(t *testing.T) (Authorizer, *approval.Queue) {
	t.Helper()
	q := approval.NewQueue()
	auth := NewAuthorizer(
		AuthorizerConfig{
			AgentName:    "test-agent",
			AllowedPaths: []string{"*"},
			CanWrite:     true,
			ApprovalMode: "prompt",
		},
		WithApprovalQueue(q),
	)
	return auth, q
}

func TestPromptWithApprovalQueueBlocksAndApproves(t *testing.T) {
	auth, q := approvalAuthorizer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- auth.Authorize(ctx, "work/creds", true, false)
	}()

	// Wait for the request to be enqueued.
	var id string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending := q.Pending()
		if len(pending) == 1 {
			id = pending[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no pending approval request appeared")
	}

	if _, err := q.Approve(id, "device-1"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Authorize after approval: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorize did not unblock after approval")
	}
}

func TestPromptWithApprovalQueueDenies(t *testing.T) {
	auth, q := approvalAuthorizer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- auth.Authorize(ctx, "work/creds", true, false)
	}()

	var id string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pending := q.Pending()
		if len(pending) == 1 {
			id = pending[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no pending approval request appeared")
	}

	if _, err := q.Deny(id, "device-1"); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Authorize should fail after denial")
		}
		if !strings.Contains(err.Error(), "denied") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorize did not unblock after denial")
	}
}

func TestPromptWithApprovalQueueExpires(t *testing.T) {
	q := approval.NewQueueWithTTL(100 * time.Millisecond)
	auth := NewAuthorizer(
		AuthorizerConfig{
			AgentName:    "test-agent",
			AllowedPaths: []string{"*"},
			CanWrite:     true,
			ApprovalMode: "prompt",
		},
		WithApprovalQueue(q),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- auth.Authorize(ctx, "work/creds", true, false)
	}()

	// Wait for enqueue, then reap the expiry.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(q.Pending()) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	q.ReapExpired()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Authorize should fail after expiry")
		}
		if !strings.Contains(err.Error(), "expired") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorize did not unblock after expiry")
	}
}

func TestPromptWithoutQueueDegradesToDeny(t *testing.T) {
	// No WithApprovalQueue: behavior must be unchanged (instant deny).
	auth := NewAuthorizer(AuthorizerConfig{
		AgentName:    "test-agent",
		AllowedPaths: []string{"*"},
		CanWrite:     true,
		ApprovalMode: "prompt",
	})
	err := auth.Authorize(context.Background(), "work/creds", true, false)
	if err == nil {
		t.Fatal("Authorize should fail without an approval device")
	}
	if !strings.Contains(err.Error(), "requires approval") {
		t.Fatalf("err = %v", err)
	}
}

func TestDenyModeNeverBlocks(t *testing.T) {
	// Mode "deny" must not enqueue even with a queue attached.
	q := approval.NewQueue()
	auth := NewAuthorizer(
		AuthorizerConfig{
			AgentName:    "test-agent",
			AllowedPaths: []string{"*"},
			CanWrite:     true,
			ApprovalMode: "deny",
		},
		WithApprovalQueue(q),
	)
	err := auth.Authorize(context.Background(), "work/creds", true, false)
	if err == nil {
		t.Fatal("deny mode should fail")
	}
	if len(q.Pending()) != 0 {
		t.Fatalf("deny mode enqueued: %+v", q.Pending())
	}
}

func TestApprovedFlagSkipsQueue(t *testing.T) {
	auth, q := approvalAuthorizer(t)
	// An already-approved call must not enqueue or block.
	if err := auth.Authorize(context.Background(), "work/creds", true, true); err != nil {
		t.Fatalf("authorize with approved: %v", err)
	}
	if len(q.Pending()) != 0 {
		t.Fatalf("approved call enqueued: %+v", q.Pending())
	}
}

func TestApprovalWaitContextTimeoutAudits(t *testing.T) {
	auth, q := approvalAuthorizer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := auth.Authorize(ctx, "work/creds", true, false)
	if err == nil {
		t.Fatal("expected error on context timeout")
	}
	// The request remains pending and decidable for the device.
	if len(q.Pending()) != 1 {
		t.Fatalf("pending = %+v", q.Pending())
	}
	_ = errors.Is(err, context.DeadlineExceeded)
}
