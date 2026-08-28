// Package approval implements the pending-request queue that lets an
// enrolled approval device (mobile client) decide agent credential requests
// out-of-band. It is the interface that makes approval mode "prompt" usable:
// an agent call blocks on Wait until a human approves, denies, or the
// request expires — instead of degrading to an instant deny.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Status is the lifecycle state of an approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
)

// Request describes one pending approval.
type Request struct {
	AgentName string
	Path      string
	Write     bool
	Reason    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Entry is a request plus its current state.
type Entry struct {
	Request
	ID        string
	Status    Status
	DecidedAt time.Time
	DecidedBy string
}

// Outcome is the result of waiting on a request.
type Outcome struct {
	ID        string
	Status    Status
	DecidedAt time.Time
	DecidedBy string
}

// ErrNotFound is returned when no request with the id exists.
var ErrNotFound = errors.New("approval request not found")

// ErrClosed is returned when the queue is closed.
var ErrClosed = errors.New("approval queue closed")

// ErrExpired is returned when a wait unblocks because the request expired.
var ErrExpired = errors.New("approval request expired")

// DefaultTTL is how long a pending request stays open before auto-expiry.
const DefaultTTL = 5 * time.Minute

// Queue is a thread-safe pending-approval store. Decisions wake waiting
// agents; expired requests are reaped lazily on access and by ReapExpired.
// Wait self-enforces Entry.ExpiresAt with its own timer so waiters unblock
// without external polling.
type Queue struct {
	mu       sync.Mutex
	entries  map[string]*Entry
	waiters  map[string][]chan Outcome
	ttl      time.Duration
	closed   bool
	notifier chan struct{}
}

// NewQueue creates a queue with the default TTL.
func NewQueue() *Queue { return NewQueueWithTTL(DefaultTTL) }

// NewQueueWithTTL creates a queue with a custom request TTL.
func NewQueueWithTTL(ttl time.Duration) *Queue {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Queue{
		entries:  map[string]*Entry{},
		waiters:  map[string][]chan Outcome{},
		ttl:      ttl,
		notifier: make(chan struct{}, 1),
	}
}

// Enqueue adds a request and returns its ID. If TTL is zero on the request,
// the queue default applies.
func (q *Queue) Enqueue(r Request) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return "", ErrClosed
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	ttl := q.ttl
	if !r.ExpiresAt.IsZero() {
		ttl = r.ExpiresAt.Sub(now)
		if ttl <= 0 {
			ttl = q.ttl
		}
	}
	q.entries[id] = &Entry{
		Request: r,
		ID:      id,
		Status:  StatusPending,
	}
	q.entries[id].ExpiresAt = now.Add(ttl)
	q.poke()
	return id, nil
}

// Get returns a single entry.
func (q *Queue) Get(id string) (Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reapLocked()
	e, ok := q.entries[id]
	if !ok {
		return Entry{}, ErrNotFound
	}
	return *e, nil
}

// List returns all entries, pending first, newest first within status.
func (q *Queue) List() []Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reapLocked()
	out := make([]Entry, 0, len(q.entries))
	for _, e := range q.entries {
		out = append(out, *e)
	}
	// Stable order: pending first, then decided; newest created first.
	sortEntries(out)
	return out
}

// Pending returns only requests still awaiting a decision.
func (q *Queue) Pending() []Entry {
	all := q.List()
	out := make([]Entry, 0, len(all))
	for _, e := range all {
		if e.Status == StatusPending {
			out = append(out, e)
		}
	}
	return out
}

// Approve decides a request as approved and wakes its waiters.
func (q *Queue) Approve(id, decidedBy string) (Outcome, error) {
	return q.decide(id, StatusApproved, decidedBy)
}

// Deny decides a request as denied and wakes its waiters.
func (q *Queue) Deny(id, decidedBy string) (Outcome, error) {
	return q.decide(id, StatusDenied, decidedBy)
}

func (q *Queue) decide(id string, status Status, decidedBy string) (Outcome, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reapLocked()
	e, ok := q.entries[id]
	if !ok {
		return Outcome{}, ErrNotFound
	}
	if e.Status != StatusPending {
		return Outcome{}, fmt.Errorf("approval request %s already %s", id, e.Status)
	}
	now := time.Now().UTC()
	e.Status = status
	e.DecidedAt = now
	e.DecidedBy = decidedBy
	out := Outcome{ID: id, Status: status, DecidedAt: now, DecidedBy: decidedBy}
	q.wakeLocked(id, out)
	q.poke()
	return out, nil
}

// Wait blocks until the request is decided, expires, the context is done, or
// the queue closes. It returns the outcome (StatusExpired on expiry).
// Wait self-enforces Entry.ExpiresAt with its own timer so waiters unblock
// without external polling.
func (q *Queue) Wait(ctx context.Context, id string) (Outcome, error) {
	ch := make(chan Outcome, 1)
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return Outcome{}, ErrClosed
	}
	q.reapLocked()
	e, ok := q.entries[id]
	if !ok {
		q.mu.Unlock()
		return Outcome{}, ErrNotFound
	}
	if e.Status != StatusPending {
		out := Outcome{ID: id, Status: e.Status, DecidedAt: e.DecidedAt, DecidedBy: e.DecidedBy}
		q.mu.Unlock()
		return out, nil
	}
	// Register the waiter before releasing the lock so a decision racing
	// with registration still wakes us.
	q.waiters[id] = append(q.waiters[id], ch)
	q.mu.Unlock()

	// Self-enforce expiry: if the entry is still pending, arm a timer that
	// fires at ExpiresAt and marks the entry expired without requiring
	// an external reaper poll.
	expiryTimer := time.AfterFunc(max(0, time.Until(e.ExpiresAt)), func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if e.Status == StatusPending && time.Now().After(e.ExpiresAt) {
			e.Status = StatusExpired
			e.DecidedAt = e.ExpiresAt
			out := Outcome{ID: id, Status: StatusExpired, DecidedAt: e.ExpiresAt}
			q.wakeLocked(id, out)
			q.poke()
		}
	})

	select {
	case out := <-ch:
		expiryTimer.Stop()
		return out, nil
	case <-ctx.Done():
		q.mu.Lock()
		q.removeWaiterLocked(id, ch)
		q.mu.Unlock()
		expiryTimer.Stop()
		return Outcome{}, ctx.Err()
	}
}

// ReapExpired marks expired pending requests and wakes their waiters. It
// returns the number of requests expired. Called periodically by the
// transport layer or the background reaper ticker.
func (q *Queue) ReapExpired() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.reapLocked()
}

// StartReaper launches a background goroutine that periodically calls
// ReapExpired. It returns a stop function that cancels the goroutine.
// The reaper is bounded by the queue's lifetime: call the stop function
// when the server shuts down.
func (q *Queue) StartReaper(ctx context.Context, interval time.Duration) func() {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				q.ReapExpired()
			case <-stopCh:
				q.ReapExpired()
				return
			case <-ctx.Done():
				q.ReapExpired()
				return
			}
		}
	}()
	return func() {
		close(stopCh)
		<-doneCh
	}
}

func (q *Queue) reapLocked() int {
	now := time.Now().UTC()
	expired := 0
	for id, e := range q.entries {
		if e.Status == StatusPending && now.After(e.ExpiresAt) {
			e.Status = StatusExpired
			e.DecidedAt = e.ExpiresAt
			out := Outcome{ID: id, Status: StatusExpired, DecidedAt: e.ExpiresAt}
			q.wakeLocked(id, out)
			expired++
		} else if e.Status == StatusExpired {
			expired++
		}
	}
	if expired > 0 {
		q.poke()
	}
	return expired
}

// Close shuts the queue down: pending requests become expired, waiters are
// woken with ErrClosed.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	for id, e := range q.entries {
		if e.Status == StatusPending {
			e.Status = StatusExpired
			e.DecidedAt = time.Now().UTC()
			q.wakeLocked(id, Outcome{ID: id, Status: StatusExpired, DecidedAt: e.DecidedAt})
		}
	}
	q.poke()
}

// Notify returns a channel that is signaled whenever the queue state
// changes (new request, decision, expiry). Used by transports to push
// updates to approval devices.
func (q *Queue) Notify() <-chan struct{} { return q.notifier }

func (q *Queue) wakeLocked(id string, out Outcome) {
	for _, ch := range q.waiters[id] {
		select {
		case ch <- out:
		default:
		}
	}
	q.waiters[id] = nil
}

func (q *Queue) removeWaiterLocked(id string, ch chan Outcome) {
	ws := q.waiters[id]
	for i, w := range ws {
		if w == ch {
			q.waiters[id] = append(ws[:i], ws[i+1:]...)
			return
		}
	}
}

func (q *Queue) poke() {
	select {
	case q.notifier <- struct{}{}:
	default:
	}
}

func sortEntries(entries []Entry) {
	// Pending first; within a status group, newest CreatedAt first; ties by ID.
	sort.SliceStable(entries, func(i, j int) bool {
		pi, pj := entries[i].Status == StatusPending, entries[j].Status == StatusPending
		if pi != pj {
			return pi
		}
		if !entries[i].CreatedAt.Equal(entries[j].CreatedAt) {
			return entries[i].CreatedAt.After(entries[j].CreatedAt)
		}
		return entries[i].ID < entries[j].ID
	})
}

func randomID() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate approval id: %w", err)
	}
	return "apr-" + hex.EncodeToString(buf), nil
}

func max(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
