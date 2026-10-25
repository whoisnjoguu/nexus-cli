package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

// MinInterval is the minimum spacing between approval notifications; requests arriving faster
// are coalesced into one "N approvals pending" notification.
const MinInterval = 3 * time.Second

// Info describes where the human can answer approvals.
type Info struct {
	// UIURL is the approvals web UI page (e.g. http://127.0.0.1:port/ui), if served.
	UIURL string
	// UIActive reports whether a web UI session is signed in; when true the notification points
	// at UIURL instead of `nexus-cli approve`.
	UIActive func() bool
	// Interval overrides MinInterval (tests).
	Interval time.Duration
	// OnError receives notifier errors (optional).
	OnError func(error)
}

func (i Info) hint() string {
	if i.UIURL != "" && i.UIActive != nil && i.UIActive() {
		return "Open " + i.UIURL
	}
	return "Run: nexus-cli approve"
}

// WatchBroker notifies n whenever a new request is queued on b, until ctx ends. At most one
// notification is sent per interval; bursts are coalesced. It blocks; run it in a goroutine.
func WatchBroker(ctx context.Context, b *hitl.Broker, n Notifier, info Info) {
	if b == nil || n == nil {
		return
	}
	if _, nop := n.(Nop); nop {
		return
	}
	interval := info.Interval
	if interval <= 0 {
		interval = MinInterval
	}

	var (
		last    time.Time // when the previous notification was sent
		dirty   bool      // requests arrived since then
		timer   *time.Timer
		timerC  <-chan time.Time
		events  <-chan hitl.Event
		unsub   = func() {}
		pending = func() []hitl.Request { return b.Pending() }
	)
	defer func() { unsub() }()
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	send := func(reqs []hitl.Request) {
		if len(reqs) == 0 {
			return
		}
		title, body := Message(reqs, info.hint())
		last = time.Now()
		dirty = false
		if err := n.Notify(title, body); err != nil && info.OnError != nil {
			info.OnError(err)
		}
	}

	for {
		if events == nil {
			events, unsub = b.Subscribe()
		}
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			// Notifications describe the live queue, so a request decided before we get here
			// is not announced.
			if !ok { // fell behind: resubscribe and treat as new activity
				events = nil
				dirty = true
			} else if ev.Type != hitl.EventAdded {
				continue
			}
			if wait := interval - time.Since(last); wait > 0 {
				dirty = true
				if timerC == nil {
					timer = time.NewTimer(wait)
					timerC = timer.C
				}
				continue
			}
			send(pending())
		case <-timerC:
			timerC = nil
			if dirty {
				send(pending())
			}
		}
	}
}

// Message renders the notification for the pending requests (oldest first); hint says how to
// answer. All request fields are sanitised.
func Message(reqs []hitl.Request, hint string) (title, body string) {
	if len(reqs) == 0 {
		return "", ""
	}
	r := reqs[0]
	what := Clean(strings.TrimSpace(r.Tool+" "+r.Target), 120)
	agent := Clean(r.AgentID, 60)
	if agent == "" {
		agent = "agent"
	}
	if len(reqs) == 1 {
		title = fmt.Sprintf("Approval needed: %s → %s", agent, what)
		body = hint
		if reason := Clean(r.Reason, 100); reason != "" {
			body = reason + " · " + hint
		}
	} else {
		title = fmt.Sprintf("%d approvals pending", len(reqs))
		body = fmt.Sprintf("Oldest: %s → %s · %s", agent, what, hint)
	}
	return Clean(title, MaxLen), Clean(body, MaxLen)
}
