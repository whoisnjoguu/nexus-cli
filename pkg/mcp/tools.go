package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func toolDefs() []map[string]any {
	return []map[string]any{
		{
			"name":        "mint_token",
			"description": "Mint a short-lived Ed25519 dual-actor JWT binding an agent identity (sub) to a human principal (act_as).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_id":    map[string]any{"type": "string", "description": "Unique agent identity"},
					"user_id":     map[string]any{"type": "string", "description": "Human principal (act_as)"},
					"scopes":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Allowed scopes"},
					"ttl_seconds": map[string]any{"type": "integer", "description": "Token lifetime in seconds", "default": 30},
				},
				"required": []string{"agent_id", "user_id"},
			},
		},
		{
			"name":        "list_providers",
			"description": "List the providers registered on the Nexus Gateway that access can be requested for.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "list_connections",
			"description": "List the provider connections the human has already established, with live status.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "request_access",
			"description": "Request access to a provider. Returns a consent URL the human must approve; the agent cannot self-grant. Poll connection_status afterward.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"provider": map[string]any{"type": "string", "description": "Provider name (e.g. github, google-drive)"},
					"scopes":   map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional OAuth scopes; defaults to the Gateway's registered set"},
				},
				"required": []string{"provider"},
			},
		},
		{
			"name":        "connection_status",
			"description": "Check whether a provider connection is active (consent completed).",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"provider": map[string]any{"type": "string"}},
				"required":   []string{"provider"},
			},
		},
		{
			"name":        "get_credential",
			"description": "Return a short-lived access token for a provider. DENIED by default (secretless) — prefer using the tool through Nexus so the agent never holds the raw token.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"provider": map[string]any{"type": "string"}},
				"required":   []string{"provider"},
			},
		},
	}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) handleToolCall(rc *reqCtx) (any, *rpcError) {
	var p toolCallParams
	if err := json.Unmarshal(rc.params, &p); err != nil {
		return nil, newErr(codeInvalidParams, "invalid params: "+err.Error())
	}
	args := decodeObject(p.Arguments)
	provider := extractProvider(p.Arguments)

	preq := policy.Request{Tool: p.Name, Provider: provider, Args: args}
	preq.Host, preq.Path = egressTarget(args)

	az := s.authorize(rc, preq)
	s.recordTool(rc, p.Name, provider, p.Arguments, az)
	if !az.allowed {
		s.logf("tool call %q denied: %s", p.Name, az.reason)
		return textResult(true, "Tool execution denied by Nexus guardrail: "+az.reason), nil
	}

	if up := s.routeTool(p.Name); up != nil {
		return s.callUpstreamTool(rc, up, p.Name)
	}

	switch p.Name {
	case "mint_token":
		return s.callMintToken(p.Arguments), nil
	case "list_providers":
		return s.callListProviders(), nil
	case "list_connections":
		return s.callListConnections(), nil
	case "request_access":
		return s.callRequestAccess(p.Arguments), nil
	case "connection_status":
		return s.callConnectionStatus(p.Arguments), nil
	case "get_credential":
		return s.callGetCredential(p.Arguments), nil
	}
	if up := s.upstreamForName(p.Name); up != nil {
		return textResult(true, fmt.Sprintf("upstream %q is unavailable (%s)", up.name, up.stateName())), nil
	}
	return textResult(true, "unknown tool: "+p.Name), nil
}

func extractProvider(args json.RawMessage) string {
	var a struct {
		Provider string `json:"provider"`
	}
	_ = json.Unmarshal(args, &a)
	return a.Provider
}

// egressTarget finds an absolute http(s) URL in the url/uri/endpoint argument of a fetch-style
// tool so the egress allowlist and taint escalation apply to MCP tools that reach the network.
func egressTarget(args map[string]any) (host, path string) {
	for _, key := range []string{"url", "uri", "endpoint"} {
		v, ok := args[key].(string)
		if !ok {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(v))
		if err != nil || u.Host == "" {
			continue
		}
		if scheme := strings.ToLower(u.Scheme); scheme == "http" || scheme == "https" {
			return u.Host, u.EscapedPath()
		}
	}
	return "", ""
}

// authz is the outcome of authorize, with what the audit log needs to explain it.
type authz struct {
	allowed bool
	reason  string
	rule    string // the matched policy rule, rendered (see ruleLabel)
	source  string // who decided: policy, session-grant, elicitation, approve, ...
}

// authorize resolves whether a request may proceed, escalating HITL to the approvers. Read-only
// broker tools always pass; get_credential is denied unless a policy rule explicitly permits it.
func (s *Server) authorize(rc *reqCtx, preq policy.Request) authz {
	switch preq.Tool {
	case "list_providers", "list_connections", "connection_status":
		return authz{allowed: true, reason: "read-only broker tool", source: "builtin"}
	}
	preq.SessionID = s.agentID + "|" + s.actAs
	label := preq.Tool
	if preq.Provider != "" {
		label = preq.Tool + " (" + preq.Provider + ")"
	}
	if s.engine != nil {
		dec := s.engine.Evaluate(preq)
		az := authz{rule: ruleLabel(dec.Rule), source: "policy"}
		switch dec.Action {
		case policy.ActionAllow:
			az.allowed, az.reason = true, dec.Reason
			if dec.Reason == "session grant" {
				az.source = "session-grant"
			}
			return az
		case policy.ActionHITL:
			d, who := s.approve(rc, preq, label, dec.Reason)
			az.source = who
			switch d {
			case hitl.Once:
				az.allowed, az.reason = true, "approved once"
			case hitl.Session:
				s.engine.GrantSession(preq, dec)
				az.allowed, az.reason = true, "approved for session"
			case hitl.Always:
				s.engine.GrantSession(preq, dec)
				s.persistAllow(preq, dec.Rule)
				az.allowed, az.reason = true, "approved & persisted"
			default:
				az.reason = "denied at human-in-the-loop"
			}
			return az
		default:
			az.reason = dec.Reason
			return az
		}
	}
	// No policy engine: handing out raw tokens is never permissive.
	if preq.Tool == "get_credential" {
		return authz{reason: "get_credential requires an explicit policy allow rule (secretless by default)", source: "builtin"}
	}
	if s.strict || preq.Tool == "sampling/createMessage" {
		d, who := s.approve(rc, preq, label, "strict mode")
		if d.Allowed() {
			return authz{allowed: true, reason: "approved at human-in-the-loop", source: who}
		}
		return authz{reason: "denied at human-in-the-loop", source: who}
	}
	return authz{allowed: true, reason: "no policy (permissive)", source: "builtin"}
}

// ruleLabel renders a policy rule compactly for the audit log, e.g. "tool=fs__write_file args[path]=/w/** -> allow".
func ruleLabel(r *policy.Rule) string {
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

// approve asks a human: via MCP elicitation when the client supports it, racing the out-of-band
// approver (`nexus-cli approve`). With neither available it fails closed.
func (s *Server) approve(rc *reqCtx, preq policy.Request, label, reason string) (hitl.Decision, string) {
	var winner atomic.Pointer[string]
	tag := func(name string, a hitl.Approver) hitl.Approver {
		return hitl.ApproverFunc(func(ctx context.Context, req hitl.Request) hitl.Decision {
			d := a.Approve(ctx, req)
			if ctx.Err() == nil {
				winner.CompareAndSwap(nil, &name)
			}
			return d
		})
	}
	var elicit, oob hitl.Approver
	if rc.sess.capabilities().elicitation {
		elicit = tag("elicitation", s.elicitApprover(rc))
	}
	if s.oob != nil {
		oob = tag("approve", s.oob)
	}
	if elicit == nil && oob == nil {
		s.logf("approval needed for %s but client lacks elicitation and no out-of-band approver is configured; denying", label)
		return hitl.Deny, "no-approver"
	}
	approver := hitl.Any(elicit, oob)
	req := hitl.Request{
		ID:        hitl.NewRequestID(),
		AgentID:   s.agentID,
		ActAsUser: s.actAs,
		Tool:      label,
		Target:    targetFor(preq),
		Params:    paramsPreview(preq.Args),
		Reason:    reason,
		Created:   time.Now(),
	}
	if s.oob != nil {
		s.logf("approval pending for %s (id %s, %s): run `nexus-cli approve` in another terminal", label, req.ID, reason)
	}
	ctx, cancel := context.WithTimeout(rc.ctx, s.approvalTimeout)
	defer cancel()
	d := approver.Approve(ctx, req)
	if ctx.Err() == context.DeadlineExceeded && d == hitl.Deny {
		s.logf("approval for %s timed out; denying", label)
		return d, "approval-timeout"
	}
	if w := winner.Load(); w != nil {
		return d, *w
	}
	return d, "hitl"
}

func targetFor(preq policy.Request) string {
	if preq.Host != "" {
		return preq.Host + preq.Path
	}
	if uri, ok := preq.Args["uri"].(string); ok {
		return uri
	}
	if p, ok := preq.Args["path"].(string); ok {
		return p
	}
	return "mcp:" + preq.Tool
}

func paramsPreview(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	b, _ := json.Marshal(args)
	return string(b)
}

// elicitApprover collects a decision from the client via elicitation/create (once / session /
// always / deny). It fails closed on decline, cancel, error or timeout.
func (s *Server) elicitApprover(rc *reqCtx) hitl.Approver {
	return hitl.ApproverFunc(func(ctx context.Context, req hitl.Request) hitl.Decision {
		resp, err := rc.sess.request(ctx, rc.out, "elicitation/create", map[string]any{
			"message": fmt.Sprintf("Nexus guardrail: approve %q? (%s)", req.Tool, req.Reason),
			"requestedSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"decision": map[string]any{
						"type":        "string",
						"title":       "Decision",
						"description": "Approve once, for this session, always (save to policy), or deny",
						"enum":        []string{"once", "session", "always", "deny"},
					},
				},
				"required": []string{"decision"},
			},
		})
		if err != nil {
			return hitl.Deny
		}
		if resp.Error != nil {
			s.logf("elicitation error: %s", resp.Error.Message)
			return hitl.Deny
		}
		var res struct {
			Action  string `json:"action"`
			Content struct {
				Decision string `json:"decision"`
			} `json:"content"`
		}
		if err := json.Unmarshal(resp.Result, &res); err != nil || res.Action != "accept" {
			return hitl.Deny
		}
		switch res.Content.Decision {
		case "once":
			return hitl.Once
		case "session":
			return hitl.Session
		case "always":
			return hitl.Always
		}
		return hitl.Deny
	})
}

// persistAllow writes an "always allow" rule for this tool/provider via the configured callback,
// keeping the argument constraints of the rule that prompted so they can't be widened.
func (s *Server) persistAllow(req policy.Request, matched *policy.Rule) {
	if s.persistRule == nil {
		return
	}
	m := policy.Match{Tool: req.Tool, Provider: req.Provider}
	if matched != nil && len(matched.Match.Args) > 0 {
		m.Args = make(map[string]string, len(matched.Match.Args))
		for k, v := range matched.Match.Args {
			m.Args[k] = v
		}
	}
	s.persistRule(policy.PersistedAllow(m, matched))
}

func (s *Server) recordTool(rc *reqCtx, name, provider string, args json.RawMessage, az authz) {
	if s.auditlog == nil {
		return
	}
	outcome := "deny"
	if az.allowed {
		outcome = "allow"
	}
	target := "mcp:" + name
	if provider != "" {
		target += ":" + provider
	}
	_ = s.auditlog.Log(audit.Entry{
		Agent:    s.agentID,
		ActAs:    s.actAs,
		Tool:     name,
		Target:   target,
		Decision: outcome,
		Reason:   az.reason,
		Session:  rc.sess.auditID(),
		Rule:     az.rule,
		ArgsHash: audit.HashArgs(bytes.TrimSpace(args)),
		Source:   az.source,
	})
}

func (s *Server) callMintToken(args json.RawMessage) map[string]any {
	var a struct {
		AgentID string   `json:"agent_id"`
		UserID  string   `json:"user_id"`
		Scopes  []string `json:"scopes"`
		TTL     int      `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return textResult(true, "invalid arguments: "+err.Error())
	}
	if a.AgentID == "" {
		return textResult(true, "agent_id is required")
	}
	if s.signer == nil {
		return textResult(true, "token signing is not configured")
	}
	if a.TTL <= 0 {
		a.TTL = 30
	}
	if len(a.Scopes) == 0 {
		a.Scopes = []string{"read"}
	}

	// act_as is bound to the server's logged-in principal, never the agent-supplied argument,
	// so an agent cannot forge the human identity it operates under.
	actAs := s.actAs
	if actAs == "" {
		actAs = a.UserID
	}
	scopes := capScopes(s.ceiling, a.Scopes)

	tok, err := s.signer.MintDualActorToken(a.AgentID, actAs, scopes, time.Duration(a.TTL)*time.Second)
	if err != nil {
		return textResult(true, "mint failed: "+err.Error())
	}
	s.logf("minted token agent=%s act_as=%s ttl=%ds", a.AgentID, actAs, a.TTL)
	return textResult(false, tok)
}

// capScopes intersects requested scopes with a ceiling; an empty ceiling is unrestricted.
func capScopes(ceiling, requested []string) []string {
	if len(ceiling) == 0 {
		return requested
	}
	allow := make(map[string]bool, len(ceiling))
	for _, s := range ceiling {
		allow[s] = true
	}
	var out []string
	for _, s := range requested {
		if allow[s] {
			out = append(out, s)
		}
	}
	return out
}
