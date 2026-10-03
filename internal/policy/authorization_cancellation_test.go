package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/approval"
)

func TestAuthorizationCancellationRetiresOwnPendingConsent(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "ordinary-approval"
		if canceled {
			name = "late-approval-after-cancel"
		}
		t.Run(name, func(t *testing.T) {
			queue := approval.NewQueue()
			defer queue.Close()
			other, err := queue.Enqueue(approval.Request{AgentName: "other", Path: "work/control", Write: true})
			if err != nil {
				t.Fatal(err)
			}
			auth := NewAuthorizer(AuthorizerConfig{AgentName: "test", AllowedPaths: []string{"work/*"}, CanWrite: true, ApprovalMode: "prompt"}, WithApprovalQueue(queue))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- auth.Authorize(ctx, "work/target", true, false) }()
			deadline := time.NewTimer(time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			id := ""
			for id == "" {
				select {
				case <-tick.C:
					for _, pending := range queue.Pending() {
						if pending.ID != other {
							id = pending.ID
						}
					}
				case <-deadline.C:
					t.Fatal("authorization did not enqueue its device consent")
				}
			}
			if canceled {
				cancel()
			}
			// Approval deliberately races the canceled wait. Whether the queue
			// accepts or rejects this late reply, the authorizer cannot grant.
			_, _ = queue.Approve(id, "synthetic-device")
			select {
			case err := <-done:
				if canceled && !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled authorization granted: %v", err)
				}
				if !canceled && err != nil {
					t.Fatalf("ordinary device approval failed: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("authorization did not join after its decision")
			}
			remaining := queue.Pending()
			if len(remaining) != 1 || remaining[0].ID != other {
				t.Fatal("cancellation changed an unrelated pending consent")
			}
		})
	}
}
