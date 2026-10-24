package hitl

import (
	"context"
	"time"
)

// Request is a pending human-in-the-loop decision, independent of how it is presented.
type Request struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	ActAsUser string    `json:"act_as"`
	Tool      string    `json:"tool"`
	Target    string    `json:"target"`
	Params    string    `json:"params,omitempty"`
	Reason    string    `json:"reason"`
	Created   time.Time `json:"created"`
}

// Approver collects a human decision for a request. Implementations must fail closed: a cancelled
// context, timeout, or missing human all yield Deny.
type Approver interface {
	Approve(ctx context.Context, req Request) Decision
}

// ApproverFunc adapts a function to the Approver interface.
type ApproverFunc func(ctx context.Context, req Request) Decision

// Approve calls f.
func (f ApproverFunc) Approve(ctx context.Context, req Request) Decision { return f(ctx, req) }

// DenyAll is an Approver that always denies (used when no human can be reached).
var DenyAll Approver = ApproverFunc(func(context.Context, Request) Decision { return Deny })

// String renders a decision for logs and APIs.
func (d Decision) String() string {
	switch d {
	case Once:
		return "once"
	case Session:
		return "session"
	case Always:
		return "always"
	default:
		return "deny"
	}
}

// ParseDecision parses once/session/always/deny (and y/s/a/n); anything else is Deny.
func ParseDecision(s string) Decision {
	switch s {
	case "once", "y", "yes", "allow":
		return Once
	case "session", "s":
		return Session
	case "always", "a":
		return Always
	default:
		return Deny
	}
}
