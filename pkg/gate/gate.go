// Package gate runs the decision pipeline for a single tool call outside the HTTP proxy path:
// optional token verification, policy evaluation, human-in-the-loop approval bounded by a timeout,
// session grants and persisted "always" rules, and the audit record. The control API's
// POST /v1/check uses it so that `dev`, `run` and `mcp serve` answer SDK calls with the same
// Engine (taints, one_time rules, session grants) that gates their own traffic.
package gate

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// DefaultApprovalTimeout bounds a human decision when Config.ApprovalTimeout is unset.
const DefaultApprovalTimeout = 60 * time.Second

// Who decided a call, as reported in Result.Source and the audit log.
const (
	SourcePolicy  = "policy"  // a policy rule (or provider rule) decided
	SourceDefault = "default" // no rule matched: the egress allowlist or default_action decided
	SourceApprove = "approve" // a human decided (now, or earlier via a session grant)
	SourceGuard   = "guard"   // nexus refused before or instead of policy (bad token, no approver)
)

// Config wires a Gate. Engine is required; everything else is optional.
type Config struct {
	Engine *policy.Engine
	// Approver answers HITL decisions (e.g. hitl.Any(tty, broker)). Nil denies them.
	Approver hitl.Approver
	// ApprovalTimeout bounds how long a call waits for a human (default 60s); expiry denies.
	ApprovalTimeout time.Duration
	Audit           *audit.Logger
	// OnPersistRule persists an "always allow" rule chosen at the approval prompt.
	OnPersistRule func(policy.Rule)
	// Strict puts a human in front of every call the policy would allow (session grants stick).
	Strict bool
	// Verifier checks Call.Token. Without one, any call carrying a token is denied.
	Verifier *jwt.Verifier
	// RequireToken denies calls that carry no nexus token (mirrors the proxy's --require-auth).
	RequireToken bool
	// Replay, when set, consumes the jti of tokens minted single_use.
	Replay *jwt.ReplayGuard
	// AgentID and ActAs identify calls that carry neither a token nor their own identity.
	AgentID string
	ActAs   string
}

// Call is one tool call or HTTP action to authorize.
type Call struct {
	AgentID  string
	ActAs    string
	Session  string // defaults to "<agent>|<act_as>", the key the proxy and MCP gateway use
	Token    string // optional nexus dual-actor JWT; when set it is authoritative for identity
	Tool     string
	Provider string
	Method   string
	Host     string
	Path     string
	Scopes   []string
	Args     map[string]any
	// RawArgs is the exact JSON of Args, hashed into the audit entry. Derived from Args when nil.
	RawArgs []byte
}

// Result is the outcome of a call.
type Result struct {
	Allowed    bool
	Reason     string
	Rule       string // the matched rule, rendered (see RuleLabel)
	Source     string // SourcePolicy, SourceDefault, SourceApprove or SourceGuard
	ApprovalID string // set when the call went to a human
}

// Decision renders Allowed as "allow" or "deny".
func (r Result) Decision() string {
	if r.Allowed {
		return "allow"
	}
	return "deny"
}

// Gate authorizes calls. It is safe for concurrent use.
type Gate struct {
	cfg Config
}

// New builds a Gate.
func New(cfg Config) (*Gate, error) {
	if cfg.Engine == nil {
		return nil, errors.New("gate: nil policy engine")
	}
	if cfg.ApprovalTimeout <= 0 {
		cfg.ApprovalTimeout = DefaultApprovalTimeout
	}
	if cfg.AgentID == "" {
		cfg.AgentID = "anonymous-agent"
	}
	if cfg.ActAs == "" {
		cfg.ActAs = "unknown-user"
	}
	return &Gate{cfg: cfg}, nil
}

// ApprovalTimeout reports how long a call may wait for a human.
func (g *Gate) ApprovalTimeout() time.Duration { return g.cfg.ApprovalTimeout }

// Check authorizes c, blocking for a human decision when policy asks for one. Cancelling ctx
// during the approval denies the call.
func (g *Gate) Check(ctx context.Context, c Call) Result {
	res, p := g.Begin(c)
	if p == nil {
		return res
	}
	return p.Wait(ctx)
}

// Begin authenticates and evaluates c. A final decision is audited and returned with a nil
// Pending. When a human must decide, the returned Pending (whose ID is already known) must be
// resolved with Wait, which asks the approver, applies grants and audits the outcome.
func (g *Gate) Begin(c Call) (Result, *Pending) {
	e := g.resolve(c)
	if e.denied != nil {
		g.record(e, *e.denied)
		return *e.denied, nil
	}

	dec := g.cfg.Engine.Evaluate(e.req)
	if g.cfg.Strict && dec.Action == policy.ActionAllow && !g.cfg.Engine.SessionGranted(e.req) {
		dec = policy.Decision{Action: policy.ActionHITL, Rule: dec.Rule, Reason: "strict mode: " + dec.Reason}
	}
	res := Result{Reason: dec.Reason, Rule: RuleLabel(dec.Rule), Source: sourceOf(dec)}
	switch dec.Action {
	case policy.ActionAllow:
		res.Allowed = true
		if dec.Reason == "session grant" {
			res.Source = SourceApprove
		}
	case policy.ActionHITL:
		p := &Pending{g: g, e: e, dec: dec, done: make(chan struct{})}
		p.hreq = hitl.Request{
			ID:        hitl.NewRequestID(),
			AgentID:   e.agent,
			ActAsUser: e.actAs,
			Tool:      e.label(),
			Target:    e.target(),
			Params:    preview(e.raw),
			Reason:    dec.Reason,
			Created:   time.Now(),
		}
		res.Source = SourceApprove
		res.ApprovalID = p.hreq.ID
		p.base = res
		return res, p
	}
	g.record(e, res)
	return res, nil
}

// Pending is a call waiting for a human decision.
type Pending struct {
	g    *Gate
	e    evalCtx
	dec  policy.Decision
	base Result
	hreq hitl.Request

	once sync.Once
	done chan struct{}
	res  Result
}

// ID is the approval request ID shown by `nexus-cli approve`.
func (p *Pending) ID() string { return p.hreq.ID }

// Done is closed once the decision is known.
func (p *Pending) Done() <-chan struct{} { return p.done }

// Result blocks until the decision is known and returns it.
func (p *Pending) Result() Result {
	<-p.done
	return p.res
}

// Wait asks the approver (bounded by the approval timeout and ctx), applies session grants or
// persisted rules, audits, and returns the outcome. Only the first call asks; later and concurrent
// calls return the same result.
func (p *Pending) Wait(ctx context.Context) Result {
	p.once.Do(func() {
		p.res = p.g.approve(ctx, p)
		p.g.record(p.e, p.res)
		close(p.done)
	})
	<-p.done
	return p.res
}

func (g *Gate) approve(parent context.Context, p *Pending) Result {
	res := p.base
	res.Allowed = false
	if g.cfg.Approver == nil {
		res.Source = SourceGuard
		res.Reason = "denied at human-in-the-loop (no approver attached)"
		return res
	}
	ctx, cancel := context.WithTimeout(parent, g.cfg.ApprovalTimeout)
	defer cancel()
	d := g.cfg.Approver.Approve(ctx, p.hreq)
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			res.Reason = "denied at human-in-the-loop (approval timed out)"
		} else {
			res.Reason = "denied at human-in-the-loop (approval cancelled)"
		}
		return res
	}
	switch d {
	case hitl.Once:
		res.Allowed, res.Reason = true, "approved once"
	case hitl.Session:
		g.cfg.Engine.GrantSession(p.e.req, p.dec)
		res.Allowed, res.Reason = true, "approved for session"
	case hitl.Always:
		g.cfg.Engine.GrantSession(p.e.req, p.dec)
		g.persist(p.e.req, p.dec.Rule)
		res.Allowed, res.Reason = true, "approved & persisted"
	default:
		res.Reason = "denied at human-in-the-loop"
	}
	return res
}

// persist writes an "always allow" rule for exactly the call the human saw, keeping the matched
// rule's scope, taints, one-time and argument constraints so persisting never widens them.
func (g *Gate) persist(req policy.Request, matched *policy.Rule) {
	if g.cfg.OnPersistRule == nil {
		return
	}
	var m policy.Match
	if req.Tool != "" {
		m = policy.Match{Tool: req.Tool, Provider: req.Provider}
		if matched != nil && len(matched.Match.Args) > 0 {
			m.Args = make(map[string]string, len(matched.Match.Args))
			for k, v := range matched.Match.Args {
				m.Args[k] = v
			}
		}
	} else {
		m = policy.Match{Method: req.Method, Host: req.Host, Path: req.Path}
	}
	g.cfg.OnPersistRule(policy.PersistedAllow(m, matched))
}

// evalCtx is a call after identity resolution.
type evalCtx struct {
	agent, actAs string
	req          policy.Request
	raw          []byte
	denied       *Result // set when the call is refused before policy
}

func (e evalCtx) label() string {
	switch {
	case e.req.Tool != "" && e.req.Provider != "":
		return e.req.Tool + " (" + e.req.Provider + ")"
	case e.req.Tool != "":
		return e.req.Tool
	default:
		return e.req.Method
	}
}

func (e evalCtx) target() string {
	if e.req.Host != "" {
		return e.req.Host + e.req.Path
	}
	if e.req.Tool == "" {
		return e.req.Path
	}
	t := "sdk:" + e.req.Tool
	if e.req.Provider != "" {
		t += ":" + e.req.Provider
	}
	return t
}

func (g *Gate) resolve(c Call) evalCtx {
	raw := c.RawArgs
	if raw == nil && len(c.Args) > 0 {
		raw, _ = json.Marshal(c.Args)
	}
	e := evalCtx{agent: c.AgentID, actAs: c.ActAs, raw: raw}
	scopes := c.Scopes
	jti := ""
	finish := func() evalCtx {
		if e.agent == "" {
			e.agent = g.cfg.AgentID
		}
		if e.actAs == "" {
			e.actAs = g.cfg.ActAs
		}
		e.req = request(c, e, scopes, jti)
		return e
	}
	deny := func(reason string) evalCtx {
		e.denied = &Result{Reason: reason, Source: SourceGuard}
		return finish()
	}

	switch {
	case c.Token != "":
		if g.cfg.Verifier == nil {
			return deny("token verification unavailable")
		}
		claims, err := g.cfg.Verifier.Verify(c.Token)
		if err != nil {
			return deny("invalid token: " + err.Error())
		}
		if (c.AgentID != "" && c.AgentID != claims.AgentID) || (c.ActAs != "" && c.ActAs != claims.ActAs) {
			e.agent, e.actAs = claims.AgentID, claims.ActAs
			return deny("agent_id/act_as do not match the token")
		}
		e.agent, e.actAs, jti = claims.AgentID, claims.ActAs, claims.ID
		// The token's scopes are authoritative; a caller may only narrow them.
		if len(c.Scopes) > 0 {
			scopes = intersect(claims.Scopes, c.Scopes)
		} else {
			scopes = claims.Scopes
		}
		if claims.SingleUse && g.cfg.Replay != nil {
			exp := time.Now().Add(time.Minute)
			if claims.ExpiresAt != nil {
				exp = claims.ExpiresAt.Time
			}
			if err := g.cfg.Replay.Use(claims.ID, exp); err != nil {
				return deny("token already used")
			}
		}
	case g.cfg.RequireToken:
		return deny("a nexus token is required")
	}
	return finish()
}

func request(c Call, e evalCtx, scopes []string, jti string) policy.Request {
	session := c.Session
	if session == "" {
		session = e.agent + "|" + e.actAs
	}
	return policy.Request{
		SessionID: session,
		JTI:       jti,
		Method:    c.Method,
		Host:      c.Host,
		Path:      c.Path,
		Tool:      c.Tool,
		Provider:  c.Provider,
		Scopes:    scopes,
		Args:      c.Args,
	}
}

func (g *Gate) record(e evalCtx, res Result) {
	if g.cfg.Audit == nil {
		return
	}
	tool := e.req.Tool
	if tool == "" {
		tool = e.req.Method
	}
	_ = g.cfg.Audit.Log(audit.Entry{
		JTI:      e.req.JTI,
		Agent:    e.agent,
		ActAs:    e.actAs,
		Tool:     tool,
		Target:   e.target(),
		Scopes:   e.req.Scopes,
		Decision: res.Decision(),
		Reason:   res.Reason,
		Session:  e.req.SessionID,
		Rule:     res.Rule,
		ArgsHash: audit.HashArgs(e.raw),
		Source:   res.Source,
	})
}

func sourceOf(dec policy.Decision) string {
	if dec.Rule == nil && (dec.Reason == "no matching rule (default)" || strings.Contains(dec.Reason, "egress allowlist")) {
		return SourceDefault
	}
	return SourcePolicy
}

// RuleLabel renders a policy rule compactly, e.g. "tool=fs__write_file args[path]=/w/** -> allow".
func RuleLabel(r *policy.Rule) string {
	if r == nil {
		return ""
	}
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("tool", r.Match.Tool)
	add("provider", r.Match.Provider)
	add("method", r.Match.Method)
	add("host", r.Match.Host)
	add("path", r.Match.Path)
	keys := make([]string, 0, len(r.Match.Args))
	for k := range r.Match.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, "args["+k+"]="+r.Match.Args[k])
	}
	return strings.Join(parts, " ") + " -> " + string(r.Action)
}

func intersect(have, want []string) []string {
	var out []string
	for _, s := range want {
		if slices.Contains(have, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// preview renders arguments for the approval prompt, bounded so a huge call can't flood it.
func preview(raw []byte) string {
	const maxPreview = 2 << 10
	if len(raw) > maxPreview {
		return strings.ToValidUTF8(string(raw[:maxPreview]), "") + "…"
	}
	return string(raw)
}
