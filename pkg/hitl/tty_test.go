package hitl

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newTestTTY(t *testing.T, timeout time.Duration) (*TTYApprover, *io.PipeWriter, *syncBuf) {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	out := &syncBuf{}
	a, ok := NewTTYApprover(TTYOptions{Timeout: timeout, In: pr, Out: out, IsTerminal: func() bool { return true }})
	if !ok || a == nil {
		t.Fatal("expected terminal approver")
	}
	return a, pw, out
}

func waitOutput(t *testing.T, out *syncBuf, substr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), substr) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("output never contained %q:\n%s", substr, out.String())
}

func recv(t *testing.T, ch <-chan Decision, within time.Duration) Decision {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(within):
		t.Fatal("approver did not return in time")
		return Deny
	}
}

func TestNewTTYApproverNotTerminal(t *testing.T) {
	a, ok := NewTTYApprover(TTYOptions{In: strings.NewReader(""), IsTerminal: func() bool { return false }})
	if ok || a != nil {
		t.Fatal("expected ok=false")
	}
	// Non-file input with default detection is not a terminal either.
	if _, ok := NewTTYApprover(TTYOptions{In: strings.NewReader("")}); ok {
		t.Fatal("expected ok=false for non-file input")
	}
}

func TestTTYKeys(t *testing.T) {
	cases := map[string]Decision{
		"y": Once, "Y": Once, "s": Session, "S": Session, "a": Always, "A": Always,
		"n": Deny, "N": Deny, "q": Deny, "\x03": Deny,
	}
	for key, want := range cases {
		t.Run(strings.ReplaceAll(key, "\x03", "ctrl+c"), func(t *testing.T) {
			a, pw, out := newTestTTY(t, time.Minute)
			got := make(chan Decision, 1)
			go func() {
				got <- a.Approve(context.Background(), Request{
					Tool: "tools/call", Target: "fs.write", AgentID: "agent-1", ActAsUser: "alice",
					Reason: "high risk", Params: `{"path":"/etc/passwd"}`,
				})
			}()
			waitOutput(t, out, "fs.write")
			for _, s := range []string{"agent-1", "alice", "tools/call", "high risk", "/etc/passwd", "auto-deny in"} {
				if !strings.Contains(out.String(), s) {
					t.Errorf("prompt missing %q", s)
				}
			}
			if _, err := pw.Write([]byte(key)); err != nil {
				t.Fatal(err)
			}
			if d := recv(t, got, 5*time.Second); d != want {
				t.Fatalf("key %q: got %v want %v", key, d, want)
			}
		})
	}
}

func TestTTYTimeout(t *testing.T) {
	a, _, out := newTestTTY(t, 1200*time.Millisecond)
	start := time.Now()
	d := a.Approve(context.Background(), Request{Target: "slow"})
	if d != Deny {
		t.Fatalf("got %v", d)
	}
	if el := time.Since(start); el < time.Second || el > 4*time.Second {
		t.Fatalf("timeout took %v", el)
	}
	waitOutput(t, out, "Timed out")
}

func TestTTYContextCancel(t *testing.T) {
	a, pw, out := newTestTTY(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan Decision, 1)
	go func() { got <- a.Approve(ctx, Request{Target: "cancel-me"}) }()
	waitOutput(t, out, "cancel-me")
	cancel()
	if d := recv(t, got, 2*time.Second); d != Deny {
		t.Fatalf("got %v", d)
	}
	// The terminal is released: the next prompt works.
	waitOutput(t, out, "withdrawn")
	got2 := make(chan Decision, 1)
	go func() { got2 <- a.Approve(context.Background(), Request{Target: "next-one"}) }()
	waitOutput(t, out, "next-one")
	pw.Write([]byte("y"))
	if d := recv(t, got2, 5*time.Second); d != Once {
		t.Fatalf("next prompt: %v", d)
	}
}

func TestTTYCancelledBeforeStart(t *testing.T) {
	a, _, _ := newTestTTY(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d := a.Approve(ctx, Request{}); d != Deny {
		t.Fatalf("got %v", d)
	}
}

func TestTTYQueue(t *testing.T) {
	a, pw, out := newTestTTY(t, time.Minute)
	first := make(chan Decision, 1)
	go func() { first <- a.Approve(context.Background(), Request{Target: "req-one"}) }()
	waitOutput(t, out, "req-one")

	rest := make(chan Decision, 2)
	go func() { rest <- a.Approve(context.Background(), Request{Target: "req-two"}) }()
	go func() { rest <- a.Approve(context.Background(), Request{Target: "req-two"}) }()
	waitOutput(t, out, "2 more pending")
	if a.Queued() != 2 {
		t.Fatalf("Queued() = %d", a.Queued())
	}

	pw.Write([]byte("y"))
	if d := recv(t, first, 5*time.Second); d != Once {
		t.Fatalf("first: %v", d)
	}
	waitOutput(t, out, "req-two")
	waitOutput(t, out, "1 more pending")
	pw.Write([]byte("s"))
	if d := recv(t, rest, 5*time.Second); d != Session {
		t.Fatalf("second: %v", d)
	}
	time.Sleep(100 * time.Millisecond) // let the third prompt render before typing
	pw.Write([]byte("n"))
	if d := recv(t, rest, 5*time.Second); d != Deny {
		t.Fatalf("third: %v", d)
	}
}

func TestTTYQueuedWaiterCancel(t *testing.T) {
	a, pw, out := newTestTTY(t, time.Minute)
	first := make(chan Decision, 1)
	go func() { first <- a.Approve(context.Background(), Request{Target: "holder"}) }()
	waitOutput(t, out, "holder")

	ctx, cancel := context.WithCancel(context.Background())
	queued := make(chan Decision, 1)
	go func() { queued <- a.Approve(ctx, Request{Target: "waiter"}) }()
	waitOutput(t, out, "1 more pending")
	cancel()
	if d := recv(t, queued, 2*time.Second); d != Deny {
		t.Fatalf("queued: %v", d)
	}
	if a.Queued() != 0 {
		t.Fatalf("Queued() = %d", a.Queued())
	}
	pw.Write([]byte("a"))
	if d := recv(t, first, 5*time.Second); d != Always {
		t.Fatalf("first: %v", d)
	}
}

func TestTTYDiscardsTypeAhead(t *testing.T) {
	a, pw, _ := newTestTTY(t, 1200*time.Millisecond)
	// Written (and consumed by the pump) before any prompt exists: must not approve anything.
	if _, err := pw.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let the pump park the bytes
	if d := a.Approve(context.Background(), Request{}); d != Deny {
		t.Fatalf("type-ahead approved request: %v", d)
	}
}

func TestTTYInputEOFFailsClosed(t *testing.T) {
	a, pw, _ := newTestTTY(t, time.Second)
	pw.Close()
	if d := a.Approve(context.Background(), Request{}); d != Deny {
		t.Fatalf("got %v", d)
	}
}

func TestTTYNoGoroutineLeak(t *testing.T) {
	base := runtime.NumGoroutine()
	func() {
		pr, pw := io.Pipe()
		out := &syncBuf{}
		a, _ := NewTTYApprover(TTYOptions{Timeout: time.Minute, In: pr, Out: out, IsTerminal: func() bool { return true }})
		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			got := make(chan Decision, 1)
			target := "leak-" + string(rune('a'+i))
			go func() { got <- a.Approve(ctx, Request{Target: target}) }()
			waitOutput(t, out, target)
			if i%2 == 0 {
				pw.Write([]byte("y"))
			} else {
				cancel()
			}
			recv(t, got, 5*time.Second)
			cancel()
		}
		pw.Close()
	}()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > base+1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base+1 {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines: %d before, %d after\n%s", base, n, buf[:runtime.Stack(buf, true)])
	}
}
