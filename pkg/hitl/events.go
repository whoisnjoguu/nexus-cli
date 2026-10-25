package hitl

import "time"

// EventType classifies broker queue changes.
type EventType string

const (
	// EventAdded: a request was queued and is waiting for a human.
	EventAdded EventType = "added"
	// EventDecided: a request was resolved with Broker.Decide / DecideBy.
	EventDecided EventType = "decided"
	// EventExpired: nobody decided before the broker timeout; the request was denied.
	EventExpired EventType = "expired"
	// EventCancelled: the caller went away or another approver (e.g. the terminal) answered first.
	EventCancelled EventType = "cancelled"
)

// RecentLimit is how many resolved requests Broker.Recent remembers.
const RecentLimit = 20

// subscriberBuffer is the per-subscriber event backlog; a subscriber that falls further behind is
// dropped (its channel is closed) rather than blocking the broker.
const subscriberBuffer = 64

// Event describes a change to the broker queue.
type Event struct {
	Type     EventType `json:"type"`
	Request  Request   `json:"request"`
	Decision string    `json:"decision,omitempty"` // for resolved requests: once|session|always|deny
	By       string    `json:"by,omitempty"`       // who resolved it, e.g. "cli", "web", "timeout"
	At       time.Time `json:"at"`
}

type subscriber struct {
	ch chan Event
}

// Subscribe returns a channel that receives every subsequent queue event and a function that
// unsubscribes (idempotent). The channel is closed on unsubscribe, or if the subscriber stops
// draining it and its backlog overflows; callers should then resynchronise (e.g. via Watch) and
// subscribe again.
func (b *Broker) Subscribe() (<-chan Event, func()) {
	s := &subscriber{ch: make(chan Event, subscriberBuffer)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s.ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[s]; ok {
			delete(b.subs, s)
			close(s.ch)
		}
	}
}

// Recent returns up to RecentLimit resolved requests (decided, expired, or cancelled), newest
// first.
func (b *Broker) Recent() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, len(b.recent))
	for i, e := range b.recent {
		out[len(b.recent)-1-i] = e
	}
	return out
}

func (b *Broker) emitLocked(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if ev.Type != EventAdded {
		b.recent = append(b.recent, ev)
		if n := len(b.recent) - RecentLimit; n > 0 {
			b.recent = append(b.recent[:0:0], b.recent[n:]...)
		}
	}
	for s := range b.subs {
		select {
		case s.ch <- ev:
		default:
			delete(b.subs, s)
			close(s.ch)
		}
	}
}
