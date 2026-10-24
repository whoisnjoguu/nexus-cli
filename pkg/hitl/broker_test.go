package hitl

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func waitPending(t *testing.T, b *Broker, n int) []Request {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p := b.Pending(); len(p) == n {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d pending (have %d)", n, len(b.Pending()))
	return nil
}

func TestBrokerDecisions(t *testing.T) {
	for _, d := range []Decision{Deny, Once, Session, Always} {
		t.Run(d.String(), func(t *testing.T) {
			b := NewBroker(time.Minute)
			got := make(chan Decision, 1)
			go func() { got <- b.Approve(context.Background(), Request{Tool: "t"}) }()
			p := waitPending(t, b, 1)
			if len(p[0].ID) != 16 || p[0].Created.IsZero() {
				t.Fatalf("ID/Created not assigned: %+v", p[0])
			}
			if err := b.Decide(p[0].ID, d); err != nil {
				t.Fatal(err)
			}
			if g := <-got; g != d {
				t.Fatalf("got %v want %v", g, d)
			}
			if len(b.Pending()) != 0 {
				t.Fatal("request still pending")
			}
		})
	}
}

func TestBrokerKeepsCallerID(t *testing.T) {
	b := NewBroker(time.Minute)
	created := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	go b.Approve(context.Background(), Request{ID: "abc", Created: created})
	p := waitPending(t, b, 1)
	if p[0].ID != "abc" || !p[0].Created.Equal(created) {
		t.Fatalf("caller fields overwritten: %+v", p[0])
	}
	// A duplicate ID fails closed immediately.
	if d := b.Approve(context.Background(), Request{ID: "abc"}); d != Deny {
		t.Fatalf("duplicate id: got %v", d)
	}
	_ = b.Decide("abc", Deny)
}

func TestBrokerTimeout(t *testing.T) {
	b := NewBroker(50 * time.Millisecond)
	start := time.Now()
	if d := b.Approve(context.Background(), Request{}); d != Deny {
		t.Fatalf("got %v", d)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("returned before timeout")
	}
	if len(b.Pending()) != 0 {
		t.Fatal("timed-out request not removed")
	}
}

func TestBrokerDefaultTimeout(t *testing.T) {
	if NewBroker(0).Timeout() != DefaultTimeout || NewBroker(-1).Timeout() != DefaultTimeout {
		t.Fatal("default timeout not applied")
	}
}

func TestBrokerContextCancel(t *testing.T) {
	b := NewBroker(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan Decision, 1)
	go func() { got <- b.Approve(ctx, Request{}) }()
	waitPending(t, b, 1)
	cancel()
	select {
	case d := <-got:
		if d != Deny {
			t.Fatalf("got %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Approve did not return after cancel")
	}
	if len(b.Pending()) != 0 {
		t.Fatal("cancelled request not removed")
	}
	// Already-cancelled context never enqueues.
	if d := b.Approve(ctx, Request{}); d != Deny || len(b.Pending()) != 0 {
		t.Fatal("cancelled ctx should deny without queueing")
	}
}

func TestBrokerDecideUnknownAndTwice(t *testing.T) {
	b := NewBroker(time.Minute)
	if err := b.Decide("nope", Once); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("got %v", err)
	}
	done := make(chan Decision, 1)
	go func() { done <- b.Approve(context.Background(), Request{ID: "x"}) }()
	waitPending(t, b, 1)
	if err := b.Decide("x", Session); err != nil {
		t.Fatal(err)
	}
	if err := b.Decide("x", Deny); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("second decide: %v", err)
	}
	if d := <-done; d != Session {
		t.Fatalf("got %v", d)
	}
}

func TestBrokerPendingOrderAndCopy(t *testing.T) {
	b := NewBroker(time.Minute)
	for i := 0; i < 3; i++ {
		go b.Approve(context.Background(), Request{ID: fmt.Sprint(i)})
		waitPending(t, b, i+1)
	}
	p := b.Pending()
	for i, r := range p {
		if r.ID != fmt.Sprint(i) {
			t.Fatalf("order: %v", p)
		}
	}
	p[0].ID = "mutated"
	if b.Pending()[0].ID != "0" {
		t.Fatal("Pending did not return a copy")
	}
	_ = b.Decide("1", Deny)
	p = b.Pending()
	if len(p) != 2 || p[0].ID != "0" || p[1].ID != "2" {
		t.Fatalf("after removal: %v", p)
	}
	_ = b.Decide("0", Deny)
	_ = b.Decide("2", Deny)
}

func TestBrokerChanged(t *testing.T) {
	b := NewBroker(time.Minute)
	ch := b.Changed()
	select {
	case <-ch:
		t.Fatal("closed before any change")
	default:
	}
	_, v0, _ := b.Watch()
	go b.Approve(context.Background(), Request{ID: "a"})
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("Changed not closed on add")
	}
	waitPending(t, b, 1)
	_, v1, ch2 := b.Watch()
	if v1 == v0 {
		t.Fatal("version not bumped")
	}
	select {
	case <-ch2:
		t.Fatal("new channel already closed")
	default:
	}
	_ = b.Decide("a", Once)
	select {
	case <-ch2:
	case <-time.After(5 * time.Second):
		t.Fatal("Changed not closed on remove")
	}
}

func TestBrokerConcurrent(t *testing.T) {
	b := NewBroker(10 * time.Second)
	const n = 50
	var wg sync.WaitGroup
	results := make([]Decision, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = b.Approve(context.Background(), Request{ID: fmt.Sprint(i)})
		}(i)
	}
	// Deciders race each other: each ID must be decided exactly once.
	var dwg sync.WaitGroup
	var mu sync.Mutex
	wins := map[string]int{}
	for w := 0; w < 4; w++ {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				mu.Lock()
				done := len(wins) == n
				mu.Unlock()
				if done {
					return
				}
				for _, r := range b.Pending() {
					var id int
					fmt.Sscan(r.ID, &id)
					if b.Decide(r.ID, Decision(id%4)) == nil {
						mu.Lock()
						wins[r.ID]++
						mu.Unlock()
					}
				}
			}
		}()
	}
	wg.Wait()
	dwg.Wait()
	for id, c := range wins {
		if c != 1 {
			t.Fatalf("%s decided %d times", id, c)
		}
	}
	for i, d := range results {
		if d != Decision(i%4) {
			t.Fatalf("request %d got %v", i, d)
		}
	}
}
