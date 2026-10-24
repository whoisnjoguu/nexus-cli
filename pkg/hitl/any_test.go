package hitl

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAnyZeroAndNil(t *testing.T) {
	var nilTTY *TTYApprover
	var nilFunc ApproverFunc
	a := Any(nil, nilTTY, nilFunc)
	if d := a.Approve(context.Background(), Request{}); d != Deny {
		t.Fatalf("got %v", d)
	}
	if d := Any().Approve(context.Background(), Request{}); d != Deny {
		t.Fatalf("zero approvers: got %v", d)
	}
}

func TestAnySingleIsIdentity(t *testing.T) {
	b := NewBroker(time.Second)
	var nilTTY *TTYApprover
	if got := Any(nil, b, nilTTY); got != Approver(b) {
		t.Fatalf("single approver should be returned as is, got %T", got)
	}
}

func TestAnyFirstWinsAndCancelsLosers(t *testing.T) {
	var loserReturned atomic.Bool
	var ids sync.Map
	winner := ApproverFunc(func(ctx context.Context, req Request) Decision {
		ids.Store("winner", req.ID)
		time.Sleep(20 * time.Millisecond)
		return Session
	})
	loser := ApproverFunc(func(ctx context.Context, req Request) Decision {
		ids.Store("loser", req.ID)
		<-ctx.Done()
		time.Sleep(50 * time.Millisecond) // slow teardown must still complete before Any returns
		loserReturned.Store(true)
		return Deny
	})
	b := NewBroker(time.Minute)
	a := Any(loser, winner, b)
	if d := a.Approve(context.Background(), Request{}); d != Session {
		t.Fatalf("got %v", d)
	}
	if !loserReturned.Load() {
		t.Fatal("Any returned before loser finished")
	}
	if len(b.Pending()) != 0 {
		t.Fatal("broker request not withdrawn")
	}
	w, _ := ids.Load("winner")
	l, _ := ids.Load("loser")
	if w == "" || w != l {
		t.Fatalf("approvers saw different IDs: %v vs %v", w, l)
	}
}

func TestAnyBrokerDecides(t *testing.T) {
	b := NewBroker(time.Minute)
	slow := ApproverFunc(func(ctx context.Context, req Request) Decision {
		<-ctx.Done()
		return Deny
	})
	got := make(chan Decision, 1)
	go func() { got <- Any(slow, b).Approve(context.Background(), Request{ID: "fixed"}) }()
	p := waitPending(t, b, 1)
	if p[0].ID != "fixed" {
		t.Fatalf("ID not preserved: %q", p[0].ID)
	}
	if err := b.Decide("fixed", Always); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d != Always {
		t.Fatalf("got %v", d)
	}
}

func TestAnyParentCancel(t *testing.T) {
	block := ApproverFunc(func(ctx context.Context, req Request) Decision {
		<-ctx.Done()
		return Deny
	})
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan Decision, 1)
	go func() { got <- Any(block, block).Approve(ctx, Request{}) }()
	cancel()
	select {
	case d := <-got:
		if d != Deny {
			t.Fatalf("got %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Any did not return")
	}
}

func TestAnyPanicDenies(t *testing.T) {
	boom := ApproverFunc(func(context.Context, Request) Decision { panic("boom") })
	block := ApproverFunc(func(ctx context.Context, req Request) Decision {
		<-ctx.Done()
		return Once
	})
	if d := Any(boom, block).Approve(context.Background(), Request{}); d != Deny {
		t.Fatalf("got %v", d)
	}
}
