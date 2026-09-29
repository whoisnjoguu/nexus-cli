// Package sdk lets agents embed nexus-cli's authorization directly, gating every tool call
// against policy, human approval, and the audit log without running a separate proxy.
package sdk

import (
	"context"
	"fmt"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// ToolCall describes a single action an agent wants to take.
type ToolCall struct {
	SessionID string
	JTI       string
	Agent     string
	ActAs     string
	Method    string
	Host      string
	Path      string
	Tool      string
	Scopes    []string
}

// Decision is the SDK's authorization outcome.
type Decision struct {
	Allowed bool
	Reason  string
}

// Gate authorizes tool calls. jarviscore (or any agent loop) calls Authorize before executing
// a tool; a non-Allowed decision must abort the call.
type Gate interface {
	Authorize(ctx context.Context, call ToolCall) (Decision, error)
}

// Approver renders a human-in-the-loop decision for calls that policy routes to HITL.
// Implementations must fail closed (return false) when they cannot obtain a human answer.
type Approver interface {
	Approve(ctx context.Context, call ToolCall, reason string) bool
}

// ApproverFunc adapts a function to the Approver interface.
type ApproverFunc func(ctx context.Context, call ToolCall, reason string) bool

// Approve implements Approver.
func (f ApproverFunc) Approve(ctx context.Context, call ToolCall, reason string) bool {
	return f(ctx, call, reason)
}

// DenyAll is the safe default approver: it denies every HITL request.
var DenyAll Approver = ApproverFunc(func(context.Context, ToolCall, string) bool { return false })

// LocalGate authorizes calls against an in-process policy engine, escalating HITL decisions to
// an Approver and recording every outcome to the audit log.
type LocalGate struct {
	engine   *policy.Engine
	approver Approver
	auditlog *audit.Logger
}

// NewLocalGate wires a gate. A nil approver fails HITL closed; a nil logger disables auditing.
func NewLocalGate(engine *policy.Engine, approver Approver, auditlog *audit.Logger) *LocalGate {
	if approver == nil {
		approver = DenyAll
	}
	return &LocalGate{engine: engine, approver: approver, auditlog: auditlog}
}

// Authorize evaluates policy, resolves any HITL escalation, records the decision, and returns it.
func (g *LocalGate) Authorize(ctx context.Context, call ToolCall) (Decision, error) {
	if g.engine == nil {
		return Decision{}, fmt.Errorf("nexus sdk: gate has no policy engine")
	}
	dec := g.engine.Evaluate(policy.Request{
		SessionID: call.SessionID,
		JTI:       call.JTI,
		Method:    call.Method,
		Host:      call.Host,
		Path:      call.Path,
		Tool:      call.Tool,
		Scopes:    call.Scopes,
	})

	allowed := false
	reason := dec.Reason
	switch dec.Action {
	case policy.ActionAllow:
		allowed = true
	case policy.ActionHITL:
		allowed = g.approver.Approve(ctx, call, dec.Reason)
		if !allowed {
			reason = "denied at human-in-the-loop"
		}
	case policy.ActionDeny:
		allowed = false
	}

	g.record(call, dec, allowed, reason)
	return Decision{Allowed: allowed, Reason: reason}, nil
}

func (g *LocalGate) record(call ToolCall, dec policy.Decision, allowed bool, reason string) {
	if g.auditlog == nil {
		return
	}
	outcome := "deny"
	if allowed {
		outcome = "allow"
	}
	tool := call.Tool
	if tool == "" {
		tool = call.Method
	}
	target := call.Host + call.Path
	_ = g.auditlog.Log(audit.Entry{
		JTI:      call.JTI,
		Agent:    call.Agent,
		ActAs:    call.ActAs,
		Tool:     tool,
		Target:   target,
		Scopes:   call.Scopes,
		Decision: outcome,
		Reason:   reason,
	})
}
