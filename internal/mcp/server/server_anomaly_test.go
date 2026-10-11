package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/danieljustus/symaira-vault/internal/anomaly"
	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
)

// This helper executes only in the run_command child, with no vault/keyring IO.
func TestAnomalyCommandHelper(t *testing.T) {
	if len(os.Args) > 1 && os.Args[len(os.Args)-1] == "anomaly-command-helper" {
		os.Exit(0)
	}
}

// Hold the production dispatch anomaly path while only its workers run in
// synctest. Vault IO stays outside: its shared manifest worker is process-wide.
// Running newest tasks first deterministically models a delayed earlier goroutine.
type anomalyScheduler struct{ tasks []func() }

func (q *anomalyScheduler) launch(work func()) { q.tasks = append(q.tasks, work) }
func (q *anomalyScheduler) runNewestFirst() {
	for len(q.tasks) > 0 {
		i := len(q.tasks) - 1
		work := q.tasks[i]
		q.tasks = q.tasks[:i]
		go work()
		synctest.Wait()
	}
}

func anomalyDispatchServer(t *testing.T) (*Server, *anomalyScheduler, *[]anomaly.AnomalyAlert, string) {
	t.Helper()
	t.Setenv("SYMVAULT_NO_NOTIFY", "1") // desktop UI only; security/audit logs stay enabled
	vaultDir, identity := mockVaultWithEntry(t, "fixture", map[string]any{"notes": strings.Repeat("x", 554)})
	s := newTestServerWithVault(t, config.AgentProfile{
		Name: "test", Tier: config.StrPtr("admin"), AllowedPaths: []string{"*"}, CanRunCommands: config.BoolPtr(true),
		CanReadValues: config.BoolPtr(true), ExposeValueTools: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"), AutoUnseal: config.BoolPtr(true),
	}, "stdio", vaultDir)
	s.vault.Identity = identity
	s.approvalCache = newApprovalCache()
	q := &anomalyScheduler{}
	s.anomalyLaunch = q.launch
	alerts := &[]anomaly.AnomalyAlert{}
	s.anomalyDetector = anomaly.New(
		anomaly.WithOffHoursStart(0), anomaly.WithOffHoursEnd(0),
		anomaly.WithAlertHook(func(alert anomaly.AnomalyAlert) { *alerts = append(*alerts, alert) }),
	)
	health, err := s.auditLog.HealthCheck()
	if err != nil {
		t.Fatal(err)
	}
	return s, q, alerts, health.LogFilePath
}

func dispatchAnomalyTool(t *testing.T, s *Server, name string) {
	t.Helper()
	args := map[string]any{"path": "fixture"}
	if name == "run_command" {
		args = map[string]any{"command": []string{os.Args[0], "-test.run=^TestAnomalyCommandHelper$", "--", "anomaly-command-helper"}}
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.executeTool(context.Background(), name, raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if result["isError"] == true {
		t.Fatalf("%s returned error: %v", name, result)
	}
}

func TestAnomalyDispatchCompletionOrder(t *testing.T) {
	s, scheduler, alerts, _ := anomalyDispatchServer(t)
	synctest.Test(t, func(t *testing.T) {
		s.detectAnomalyAsync(context.Background(), "run_command", "", "command", "test", 0, true, 0)
		s.detectAnomalyAsync(context.Background(), "get_entry_value", "fixture", "read", "test", 0, true, 554)
		scheduler.runNewestFirst()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if s.anomalyDetector.WindowLen() != 2 {
			t.Fatal("missing dispatched events")
		}
		for _, alert := range *alerts {
			if alert.Type == anomaly.AlertToolChain {
				t.Fatalf("false read-then-execute alert: %+v", alert)
			}
		}
	})
}

func TestAnomalyDispatchGenuineToolChain(t *testing.T) {
	s, scheduler, alerts, auditPath := anomalyDispatchServer(t)
	synctest.Test(t, func(t *testing.T) {
		s.detectAnomalyAsync(context.Background(), "get_entry_value", "fixture", "read", "test", 0, true, 554)
		s.detectAnomalyAsync(context.Background(), "run_command", "", "command", "test", 0, true, 0)
		s.approvalCache.setRemembered("fixture")
		beforeCheck := time.Now()
		scheduler.runNewestFirst()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if s.anomalyDetector.WindowLen() != 2 {
			t.Fatal("missing dispatched events")
		}
		var chain *anomaly.AnomalyAlert
		for i := range *alerts {
			if (*alerts)[i].Type == anomaly.AlertToolChain {
				chain = &(*alerts)[i]
			}
		}
		if chain == nil {
			t.Fatal("genuine read-then-execute chain was missed")
		}
		if chain.Timestamp.After(beforeCheck) {
			t.Fatal("event timestamp came from background scheduling, not dispatch")
		}
		if s.approvalCache.isRemembered("fixture") {
			t.Fatal("anomaly did not invalidate approval cache")
		}
		raw, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "anomaly_tool_chain") {
			t.Fatal("security audit record missing")
		}
	})
}

func TestAnomalyDispatchEOFAuditLifetime(t *testing.T) {
	s, scheduler, alerts, auditPath := anomalyDispatchServer(t)
	synctest.Test(t, func(t *testing.T) {
		// Low-severity off-hours events still traverse the production audit path.
		s.anomalyDetector = anomaly.New(anomaly.WithOffHoursStart(0), anomaly.WithOffHoursEnd(24),
			anomaly.WithAlertHook(func(alert anomaly.AnomalyAlert) { *alerts = append(*alerts, alert) }))
		s.detectAnomalyAsync(context.Background(), "get_entry_value", "fixture", "read", "test", 0, true, 554)
		closed := make(chan error, 1)
		go func() { closed <- s.Close() }()
		// Quiescence proves Close has either returned (old code) or is waiting
		// for the held worker (fixed code), without sleeps or timeout races.
		synctest.Wait()
		scheduler.runNewestFirst()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if len(*alerts) != 1 {
			t.Fatalf("expected one real off-hours event, got %d", len(*alerts))
		}
		raw, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "anomaly_off_hours") {
			t.Fatal("EOF closed audit sink before held anomaly work wrote its security record")
		}
	})
}

// Real wall-clock control: the captured event must predate held background work.
func TestAnomalyDispatchTimestamp(t *testing.T) {
	s, scheduler, alerts, _ := anomalyDispatchServer(t)
	dispatchAnomalyTool(t, s, "get_entry_value")
	dispatchAnomalyTool(t, s, "run_command")
	beforeCheck := time.Now()
	for _, work := range scheduler.tasks {
		work()
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(*alerts) != 1 || (*alerts)[0].Type != anomaly.AlertToolChain {
		t.Fatal("missing real chain")
	}
	if (*alerts)[0].Timestamp.After(beforeCheck) {
		t.Fatal("timestamp was captured during background work")
	}
}

func TestAnomalyDispatchBusyWorkerDoesNotBlockTools(t *testing.T) {
	s, scheduler, _, _ := anomalyDispatchServer(t)
	defer func() {
		if len(scheduler.tasks) != 0 {
			t.Error("live worker control used the held scheduler")
		}
	}()
	s.anomalyLaunch = nil // real production goroutines, not the held scheduler
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock, first sync.Once
	defer unblock.Do(func() { close(release) })
	s.anomalyDetector = anomaly.New(anomaly.WithOffHoursStart(0), anomaly.WithOffHoursEnd(24),
		anomaly.WithAlertHook(func(anomaly.AnomalyAlert) {
			first.Do(func() { close(entered); <-release })
		}))
	dispatchAnomalyTool(t, s, "get_entry_value")
	<-entered
	// This successful subprocess must finish while the detector hook is held.
	dispatchAnomalyTool(t, s, "run_command")
	unblock.Do(func() { close(release) })
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.anomalyDetector.WindowLen() != 2 {
		t.Fatal("completion events were dropped")
	}
}

func TestAnomalyDispatchCloseDrainsAdmittedTool(t *testing.T) {
	s, _, _, auditPath := anomalyDispatchServer(t)
	// health has no vault reads: process-global vault admission channels must
	// not cross a synctest bubble. The actual executeTool lifecycle is exercised.
	s.anomalyDetector = anomaly.New(anomaly.WithOffHoursStart(0), anomaly.WithOffHoursEnd(24))
	synctest.Test(t, func(t *testing.T) {
		s.anomalyLaunch = nil
		entered, release := make(chan struct{}), make(chan struct{})
		s.RegisterPreCallHook(func(ctx context.Context, _ string, _ mcp.CallToolRequest, _ *Server) (context.Context, error) {
			close(entered)
			<-release
			return ctx, nil
		})
		toolDone := make(chan error, 1)
		go func() {
			_, err := s.executeTool(context.Background(), "health", json.RawMessage(`{"path":"fixture"}`))
			toolDone <- err
		}()
		<-entered
		closeDone := make(chan error, 1)
		go func() { closeDone <- s.Close() }()
		synctest.Wait()
		select {
		case <-closeDone:
			t.Error("Close returned before its admitted tool")
		default:
		}
		// New work is rejected without entering hooks or writing the audit sink.
		_, err := s.executeTool(context.Background(), "health", json.RawMessage(`{}`))
		if err == nil || !strings.Contains(err.Error(), "server is closed") {
			t.Errorf("post-close dispatch error = %v", err)
		}
		close(release)
		if err := <-toolDone; err != nil {
			t.Fatal(err)
		}
		if err := <-closeDone; err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		} // idempotent close
		if s.anomalyDetector.WindowLen() != 1 {
			t.Fatal("admitted completion event lost")
		}
		raw, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "anomaly_off_hours") {
			t.Fatal("admitted tool audit was lost during Close")
		}
	})
}
