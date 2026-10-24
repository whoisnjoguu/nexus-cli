package hitl

import (
	"context"
	"testing"
	"time"
)

func nextEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("subscription closed")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

func TestBrokerSubscribeEvents(t *testing.T) {
	b := NewBroker(100 * time.Millisecond)
	ch, unsub := b.Subscribe()
	defer unsub()

	done := make(chan Decision, 1)
	go func() { done <- b.Approve(context.Background(), Request{ID: "a", Tool: "POST"}) }()
	if ev := nextEvent(t, ch); ev.Type != EventAdded || ev.Request.ID != "a" || ev.At.IsZero() {
		t.Fatalf("added: %+v", ev)
	}
	if err := b.DecideBy("a", Session, "web"); err != nil {
		t.Fatal(err)
	}
	if d := <-done; d != Session {
		t.Fatalf("decision %v", d)
	}
	if ev := nextEvent(t, ch); ev.Type != EventDecided || ev.Decision != "session" || ev.By != "web" || ev.Request.Tool != "POST" {
		t.Fatalf("decided: %+v", ev)
	}

	// Timeout → expired.
	go func() { done <- b.Approve(context.Background(), Request{ID: "b"}) }()
	nextEvent(t, ch)
	if ev := nextEvent(t, ch); ev.Type != EventExpired || ev.By != "timeout" || ev.Decision != "deny" {
		t.Fatalf("expired: %+v", ev)
	}
	<-done

	// Context cancellation → cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- b.Approve(ctx, Request{ID: "c"}) }()
	nextEvent(t, ch)
	cancel()
	if ev := nextEvent(t, ch); ev.Type != EventCancelled || ev.Request.ID != "c" {
		t.Fatalf("cancelled: %+v", ev)
	}
	<-done

	rec := b.Recent()
	if len(rec) != 3 || rec[0].Request.ID != "c" || rec[2].Request.ID != "a" {
		t.Fatalf("recent: %+v", rec)
	}

	unsub()
	unsub() // idempotent
	if _, ok := <-ch; ok {
		t.Fatal("channel should be closed after unsubscribe")
	}
}

func TestBrokerRecentLimit(t *testing.T) {
	b := NewBroker(time.Minute)
	for i := 0; i < RecentLimit+5; i++ {
		id := NewRequestID()
		done := make(chan struct{})
		go func() { b.Approve(context.Background(), Request{ID: id}); close(done) }()
		for len(b.Pending()) == 0 {
			time.Sleep(time.Millisecond)
		}
		if err := b.Decide(id, Deny); err != nil {
			t.Fatal(err)
		}
		<-done
	}
	if n := len(b.Recent()); n != RecentLimit {
		t.Fatalf("recent len %d", n)
	}
}

func TestBrokerSlowSubscriberDropped(t *testing.T) {
	b := NewBroker(time.Minute)
	ch, unsub := b.Subscribe()
	defer unsub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < subscriberBuffer+2; i++ {
		go b.Approve(ctx, Request{})
	}
	deadline := time.After(5 * time.Second)
	n := 0
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				if n > subscriberBuffer+1 {
					t.Fatalf("received %d events before close", n)
				}
				return
			}
			n++
		case <-deadline:
			t.Fatal("slow subscriber was never dropped")
		}
		if n == 1 {
			// Stop draining until the backlog overflows.
			for len(b.Pending()) < subscriberBuffer+2 {
				time.Sleep(time.Millisecond)
			}
		}
	}
}
