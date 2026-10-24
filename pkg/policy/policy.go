// Package policy evaluates agent tool calls against a declarative least-privilege ruleset.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// Action is the decision a rule produces for a matching request.
type Action string

const (
	ActionAllow Action = "allow" // permit without interruption
	ActionDeny  Action = "deny"  // block outright
	ActionHITL  Action = "hitl"  // require a human-in-the-loop approval
)

// Match describes the request attributes a rule applies to. Empty fields are wildcards.
type Match struct {
	Method   string `yaml:"method"`
	Host     string `yaml:"host"`
	Path     string `yaml:"path"`
	Tool     string `yaml:"tool"`
	Provider string `yaml:"provider"`
	// Args constrains tool rules by call arguments (see argsMatch); ignored without Tool/Provider.
	Args map[string]string `yaml:"args,omitempty"`
}

// Rule binds a match to an action and the scope required to exercise it.
type Rule struct {
	Match   Match    `yaml:"match"`
	Scope   string   `yaml:"scope"`
	Action  Action   `yaml:"action"`
	OneTime bool     `yaml:"one_time"`
	Taints  []string `yaml:"taints"` // labels this call stamps onto the session
	// Inject, when true, replaces the outbound Authorization with a short-lived upstream
	// credential fetched from the broker for the token's connection (secretless egress).
	Inject bool `yaml:"inject"`
}

// Egress constrains which hosts an agent may reach at all.
type Egress struct {
	Allow []string `yaml:"allow"`
	// Passthrough lists host patterns whose HTTPS traffic is tunnelled without TLS interception
	// (e.g. certificate-pinned clients); only the host-level CONNECT decision applies to them.
	Passthrough []string `yaml:"passthrough,omitempty"`
}

// Policy is the full ruleset loaded from nexus.yaml.
type Policy struct {
	Agent         string                  `yaml:"agent"`
	Egress        Egress                  `yaml:"egress"`
	Tools         []Rule                  `yaml:"tools"`
	Providers     map[string]ProviderRule `yaml:"providers,omitempty"`
	DefaultAction Action                  `yaml:"default_action"`
	// EscalateWhenTainted routes egress to non-allowlisted hosts through HITL once the
	// session has touched a sensitive scope, catching read-then-exfiltrate tool chains.
	EscalateWhenTainted bool `yaml:"escalate_when_tainted"`
}

// ProviderRule governs an agent's access to one provider via the broker (edited in the TUI).
type ProviderRule struct {
	Access     Action   `yaml:"access"`               // request_access decision (allow/hitl/deny)
	Credential Action   `yaml:"credential,omitempty"` // get_credential decision (defaults to deny)
	Scopes     []string `yaml:"scopes,omitempty"`     // OAuth scopes to request for this provider
}

// Request is a single tool/egress attempt to authorize.
type Request struct {
	SessionID string
	JTI       string
	Method    string
	Host      string
	Path      string
	Tool      string
	Provider  string
	Scopes    []string
	Args      map[string]any // tool-call arguments, matched by Match.Args
}

// Decision is the outcome of evaluating a request.
type Decision struct {
	Action Action
	Rule   *Rule
	Reason string
	// TaintEscalated is set when taint tracking raised an otherwise-allowed call to HITL.
	TaintEscalated bool
	// Source is "guard" when the built-in protected-path guard decided (see SetProtectedPaths).
	Source string
}

// Allowed reports whether the decision permits execution without further interaction.
func (d Decision) Allowed() bool { return d.Action == ActionAllow }

// SessionIdleTTL is how long an idle session keeps its taint, one-time and grant state.
const SessionIdleTTL = 12 * time.Hour

// sessionState is the mutable per-session evaluation state.
type sessionState struct {
	tainted  map[string]bool // taint label -> seen
	consumed map[string]bool // ruleFingerprint -> used (one_time)
	granted  map[string]bool // grantKey -> grant also covers taint escalation
	lastSeen time.Time
}

// Engine evaluates requests against a policy while tracking per-session taint and one-time use.
type Engine struct {
	policy Policy

	mu        sync.Mutex
	sessions  map[string]*sessionState
	lastSweep time.Time
	now       func() time.Time

	guard atomic.Pointer[guardSet]
}

// NewEngine builds an evaluator around a policy, applying sane defaults.
func NewEngine(p Policy) *Engine {
	if p.DefaultAction == "" {
		p.DefaultAction = ActionDeny
	}
	return &Engine{
		policy:   p,
		sessions: make(map[string]*sessionState),
		now:      time.Now,
	}
}

// sessionLocked returns the state for a session, evicting idle sessions at most once a minute.
func (e *Engine) sessionLocked(id string) *sessionState {
	now := e.now()
	if now.Sub(e.lastSweep) > time.Minute {
		for k, s := range e.sessions {
			if now.Sub(s.lastSeen) > SessionIdleTTL {
				delete(e.sessions, k)
			}
		}
		e.lastSweep = now
	}
	s, ok := e.sessions[id]
	if !ok {
		s = &sessionState{
			tainted:  make(map[string]bool),
			consumed: make(map[string]bool),
			granted:  make(map[string]bool),
		}
		e.sessions[id] = s
	}
	s.lastSeen = now
	return s
}

// GrantKey derives the coarse identity of a request for session grants: a tool+provider pair, or
// a method+host pair for egress. Approving "this session" then covers the same shape of call.
func GrantKey(req Request) string {
	if req.Tool != "" {
		return "tool:" + req.Tool + "|" + req.Provider
	}
	return "http:" + req.Method + "|" + stripPort(req.Host)
}

// GrantSession records a HITL approval so later prompts for the same shape of call in the session
// are skipped. It never overrides deny; it covers taint escalation only if dec was one.
func (e *Engine) GrantSession(req Request, dec Decision) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.sessionLocked(req.SessionID)
	key := GrantKey(req)
	s.granted[key] = s.granted[key] || dec.TaintEscalated
}

// SessionGranted reports whether a human already approved this shape of call for the session.
func (e *Engine) SessionGranted(req Request) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.sessionLocked(req.SessionID).granted[GrantKey(req)]
	return ok
}

// PersistedAllow builds the "always allow" rule for a match, inheriting the constraints of the
// rule that produced the prompt so a prepended allow can't drop its scope, taints or one-time use.
func PersistedAllow(m Match, matched *Rule) Rule {
	r := Rule{Match: m, Action: ActionAllow}
	if matched != nil {
		r.Scope = matched.Scope
		r.OneTime = matched.OneTime
		r.Taints = append([]string(nil), matched.Taints...)
		r.Inject = matched.Inject
	}
	return r
}

// Load reads and parses a policy file.
func Load(path string) (Policy, error) {
	var p Policy
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("read policy %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("parse policy %s: %w", path, err)
	}
	return p, nil
}

// DefaultPolicyPath returns the conventional per-project policy location.
func DefaultPolicyPath() string { return "nexus.yaml" }

// DefaultPolicy is the safe-tier ruleset used when no nexus.yaml is present: read-only tools and
// GETs run without prompting, catastrophic tools are denied, and everything ambiguous asks once.
// This keeps agents autonomous for safe work while blocking the destructive tail.
func DefaultPolicy() Policy {
	return Policy{
		Agent:               "default",
		DefaultAction:       ActionHITL,
		EscalateWhenTainted: true,
		Tools: []Rule{
			// An MCP server asking the host LLM to generate text is a prompt-injection vector.
			{Match: Match{Tool: "sampling/createMessage"}, Action: ActionHITL},
			// MCP resource reads and prompt templates are read-only ("*" globs stop at "/").
			{Match: Match{Tool: "resources/read"}, Action: ActionAllow},
			{Match: Match{Tool: "prompts/get"}, Action: ActionAllow},
			{Match: Match{Tool: "execute_shell"}, Action: ActionDeny},
			{Match: Match{Tool: "*delete*"}, Action: ActionHITL},
			// Read-only verbs, anchored at a word start ("read_file", "fs__read_file") so that
			// "forget_password" or "thread_reply" don't ride along on a substring match.
			{Match: Match{Tool: "read_*"}, Action: ActionAllow},
			{Match: Match{Tool: "*__read_*"}, Action: ActionAllow},
			{Match: Match{Tool: "list_*"}, Action: ActionAllow},
			{Match: Match{Tool: "*__list_*"}, Action: ActionAllow},
			{Match: Match{Tool: "search_*"}, Action: ActionAllow},
			{Match: Match{Tool: "*__search_*"}, Action: ActionAllow},
			{Match: Match{Tool: "get_*"}, Action: ActionAllow},
			{Match: Match{Tool: "*__get_*"}, Action: ActionAllow},
			{Match: Match{Method: "GET"}, Action: ActionAllow},
			{Match: Match{Method: "HEAD"}, Action: ActionAllow},
		},
	}
}

// Policy returns the underlying ruleset.
func (e *Engine) Policy() Policy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy
}

// ProviderScopes returns the OAuth scopes configured for a provider, if any.
func (e *Engine) ProviderScopes(provider string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.Providers[provider].Scopes
}

// Evaluate authorizes a request, mutating session state (taint, one-time consumption) as a side effect.
func (e *Engine) Evaluate(req Request) Decision {
	if dec, ok := e.checkGuard(req); ok {
		return dec
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	s := e.sessionLocked(req.SessionID)
	dec := e.evaluateLocked(s, req)

	// A session grant only answers a prompt the human already answered; deny/scope/one-time still win.
	if dec.Action == ActionHITL {
		if coversTaint, ok := s.granted[GrantKey(req)]; ok && (coversTaint || !dec.TaintEscalated) {
			return Decision{Action: ActionAllow, Rule: dec.Rule, Reason: "session grant"}
		}
	}
	return dec
}

func (e *Engine) evaluateLocked(s *sessionState, req Request) Decision {
	// Broker-access tools are governed by the providers section (TUI-managed). get_credential is
	// deny-by-default so agents never receive raw tokens unless explicitly permitted.
	if req.Tool == "request_access" || req.Tool == "get_credential" {
		pr, ok := e.policy.Providers[req.Provider]
		if req.Tool == "get_credential" {
			if ok && pr.Credential != "" {
				return Decision{Action: pr.Credential, Reason: "provider credential rule"}
			}
			return Decision{Action: ActionDeny, Reason: "get_credential denied by default (secretless)"}
		}
		if ok && pr.Access != "" {
			return Decision{Action: pr.Access, Reason: "provider access rule"}
		}
		// fall through to Tools/default for providers not explicitly configured
	}

	for i := range e.policy.Tools {
		rule := &e.policy.Tools[i]
		if !ruleMatches(rule.Match, req) {
			continue
		}

		if rule.Scope != "" && !hasScope(req.Scopes, rule.Scope) {
			return Decision{Action: ActionDeny, Rule: rule, Reason: fmt.Sprintf("token missing required scope %q", rule.Scope)}
		}

		if rule.OneTime && s.consumed[ruleFingerprint(rule)] {
			return Decision{Action: ActionDeny, Rule: rule, Reason: "one-time authorization already consumed for this session"}
		}

		action := rule.Action
		if action == "" {
			action = e.policy.DefaultAction
		}

		// Read-then-exfiltrate guard: a permitted egress to a non-allowlisted host after
		// the session has touched sensitive data escalates to a human decision.
		if action == ActionAllow && e.policy.EscalateWhenTainted && req.Host != "" &&
			len(s.tainted) > 0 && !hostAllowed(e.policy.Egress.Allow, req.Host) {
			s.stampTaint(rule.Taints)
			return Decision{Action: ActionHITL, Rule: rule, Reason: "tainted session egressing to non-allowlisted host", TaintEscalated: true}
		}

		s.stampTaint(rule.Taints)
		if rule.OneTime && action != ActionDeny {
			s.consumed[ruleFingerprint(rule)] = true
		}
		return Decision{Action: action, Rule: rule, Reason: "matched rule"}
	}

	// No explicit rule: fall back to the egress allowlist, then the default action.
	if req.Host != "" && len(e.policy.Egress.Allow) > 0 {
		if hostAllowed(e.policy.Egress.Allow, req.Host) {
			return Decision{Action: ActionAllow, Reason: "host in egress allowlist"}
		}
		return Decision{Action: ActionDeny, Reason: fmt.Sprintf("host %q not in egress allowlist", req.Host)}
	}

	return Decision{Action: e.policy.DefaultAction, Reason: "no matching rule (default)"}
}

func (s *sessionState) stampTaint(labels []string) {
	for _, l := range labels {
		s.tainted[l] = true
	}
}

func ruleMatches(m Match, req Request) bool {
	if m.Tool != "" || m.Provider != "" {
		if m.Tool != "" && !toolMatch(m.Tool, req.Tool) {
			return false
		}
		if m.Provider != "" && !toolMatch(m.Provider, req.Provider) {
			return false
		}
		return len(m.Args) == 0 || argsMatch(m.Args, req.Args)
	}
	if m.Method != "" && m.Method != "*" && !strings.EqualFold(m.Method, req.Method) {
		return false
	}
	if m.Host != "" && !hostMatch(m.Host, req.Host) {
		return false
	}
	if m.Path != "" && !pathMatch(m.Path, req.Path) {
		return false
	}
	// A match with no criteria at all never matches, to avoid accidental catch-alls.
	return m.Method != "" || m.Host != "" || m.Path != ""
}

// toolMatch compares a rule pattern to a value, supporting "*" globs (e.g. "fs__read*", "google-*").
func toolMatch(pattern, tool string) bool {
	pattern = strings.ToLower(pattern)
	tool = strings.ToLower(tool)
	if strings.Contains(pattern, "*") {
		ok, err := filepath.Match(pattern, tool)
		return err == nil && ok
	}
	return pattern == tool
}

func hasScope(have []string, want string) bool {
	for _, s := range have {
		if s == want {
			return true
		}
	}
	return false
}

// HostMatches reports whether host (with or without a port) matches any of patterns, using the
// egress glob semantics: exact hosts or a single leading "*." wildcard label.
func HostMatches(patterns []string, host string) bool { return hostAllowed(patterns, host) }

func hostAllowed(allow []string, host string) bool {
	host = stripPort(host)
	for _, pat := range allow {
		if hostMatch(pat, host) {
			return true
		}
	}
	return false
}

// hostMatch supports exact hosts and a single leading "*." wildcard label.
func hostMatch(pattern, host string) bool {
	pattern = stripPort(strings.ToLower(pattern))
	host = stripPort(strings.ToLower(host))
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".github.com"
		return strings.HasSuffix(host, suffix) && host != suffix[1:]
	}
	return false
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}
	return host
}

// pathMatch supports "**" (any suffix) and "*" (single segment) glob semantics.
func pathMatch(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "**"))
	}
	ok, err := filepath.Match(pattern, path)
	return err == nil && ok
}

func ruleFingerprint(r *Rule) string {
	return strings.Join([]string{r.Match.Method, r.Match.Host, r.Match.Path, r.Match.Tool, r.Scope}, "\x1f") + argsFingerprint(r.Match.Args)
}
