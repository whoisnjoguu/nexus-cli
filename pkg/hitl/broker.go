package hitl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// DefaultTimeout is how long an approval waits for a human before failing closed.
const DefaultTimeout = 60 * time.Second

// ErrUnknownRequest is returned by Broker.Decide for IDs that are not pending (never existed,
// already decided, timed out, or cancelled).
var ErrUnknownRequest = errors.New("hitl: unknown or already decided approval request")

// Broker is an Approver that queues requests until they are decided out of band (for example via
// the local control API used by `nexus-cli approve`). Requests that are not decided before the
// timeout, or whose context ends, are denied.
type Broker struct {
	timeout time.Duration

	mu      sync.Mutex
	pending []*brokerEntry // insertion order == oldest first
	byID    map[string]*brokerEntry
	changed chan struct{}
	version uint64
	subs    map[*subscriber]struct{}
	recent  []Event // newest last, at most RecentLimit
}

type brokerEntry struct {
	req Request
	ch  chan Decision // buffered(1): Decide never blocks
}

// NewBroker returns a Broker whose requests auto-deny after timeout (0 or negative → DefaultTimeout).
func NewBroker(timeout time.Duration) *Broker {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Broker{
		timeout: timeout,
		byID:    make(map[string]*brokerEntry),
		changed: make(chan struct{}),
		subs:    make(map[*subscriber]struct{}),
	}
}

// Timeout reports how long requests wait before being denied.
func (b *Broker) Timeout() time.Duration { return b.timeout }

// NewRequestID returns a random 8-byte hex identifier.
func NewRequestID() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("hitl: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(buf[:])
}

// fillRequest assigns an ID and creation time when missing.
func fillRequest(req Request) Request {
	if req.ID == "" {
		req.ID = NewRequestID()
	}
	if req.Created.IsZero() {
		req.Created = time.Now()
	}
	return req
}

// Approve queues req and blocks until it is decided, ctx ends, or the timeout elapses (→ Deny).
// A request whose ID is already pending is denied immediately (fail closed).
func (b *Broker) Approve(ctx context.Context, req Request) Decision {
	if ctx.Err() != nil {
		return Deny
	}
	req = fillRequest(req)
	e := &brokerEntry{req: req, ch: make(chan Decision, 1)}

	b.mu.Lock()
	if _, dup := b.byID[req.ID]; dup {
		b.mu.Unlock()
		return Deny
	}
	b.byID[req.ID] = e
	b.pending = append(b.pending, e)
	b.notifyLocked()
	b.emitLocked(Event{Type: EventAdded, Request: req})
	b.mu.Unlock()

	timer := time.NewTimer(b.timeout)
	defer timer.Stop()

	ev := Event{Type: EventCancelled, Decision: Deny.String()}
	select {
	case d := <-e.ch:
		return d
	case <-ctx.Done():
	case <-timer.C:
		ev = Event{Type: EventExpired, Decision: Deny.String(), By: "timeout"}
	}

	if b.remove(req.ID, e, ev) {
		return Deny
	}
	// Decide won the race and already removed the entry; it reported success to the human, so
	// honour the decision it delivered.
	return <-e.ch
}

// remove drops e from the queue and publishes ev for it; it reports false if e was no longer
// pending.
func (b *Broker) remove(id string, e *brokerEntry, ev Event) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.removeLocked(id, e, ev)
}

func (b *Broker) removeLocked(id string, e *brokerEntry, ev Event) bool {
	if cur, ok := b.byID[id]; !ok || cur != e {
		return false
	}
	delete(b.byID, id)
	for i, p := range b.pending {
		if p == e {
			b.pending = append(b.pending[:i], b.pending[i+1:]...)
			break
		}
	}
	b.notifyLocked()
	ev.Request = e.req
	b.emitLocked(ev)
	return true
}

// Decide resolves a pending request. It returns ErrUnknownRequest if id is not pending.
func (b *Broker) Decide(id string, d Decision) error { return b.DecideBy(id, d, "") }

// DecideBy is Decide with a label for who or what decided (for example "cli" or "web"); the label
// is reported in decided events and Recent.
func (b *Broker) DecideBy(id string, d Decision, by string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.byID[id]
	if !ok || !b.removeLocked(id, e, Event{Type: EventDecided, Decision: d.String(), By: by}) {
		return ErrUnknownRequest
	}
	e.ch <- d // buffered(1) and sent at most once: never blocks
	return nil
}

// Pending returns a copy of the queued requests, oldest first.
func (b *Broker) Pending() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.snapshotLocked()
}

// Changed returns a channel that is closed on the next addition to or removal from the queue.
func (b *Broker) Changed() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.changed
}

// Watch atomically returns the queue, its version (incremented on every change), and the channel
// that will be closed on the next change. Long-poll servers use it to avoid missing updates.
func (b *Broker) Watch() (pending []Request, version uint64, changed <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.snapshotLocked(), b.version, b.changed
}

func (b *Broker) snapshotLocked() []Request {
	out := make([]Request, len(b.pending))
	for i, e := range b.pending {
		out[i] = e.req
	}
	return out
}

func (b *Broker) notifyLocked() {
	b.version++
	close(b.changed)
	b.changed = make(chan struct{})
}
