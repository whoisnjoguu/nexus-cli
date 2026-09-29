// Package policy evaluates agent tool calls against a declarative least-privilege ruleset.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
}

// Decision is the outcome of evaluating a request.
type Decision struct {
	Action Action
	Rule   *Rule
	Reason string
}

// Allowed reports whether the decision permits execution without further interaction.
func (d Decision) Allowed() bool { return d.Action == ActionAllow }

// Engine evaluates requests against a policy while tracking per-session taint and one-time use.
type Engine struct {
	policy Policy

	mu       sync.Mutex
	tainted  map[string]map[string]bool // sessionID -> taint label -> seen
	consumed map[string]bool            // sessionID|ruleFingerprint -> used (one_time)
	granted  map[string]bool            // sessionID|grantKey -> approved for the session
}

// NewEngine builds an evaluator around a policy, applying sane defaults.
func NewEngine(p Policy) *Engine {
	if p.DefaultAction == "" {
		p.DefaultAction = ActionDeny
	}
	return &Engine{
		policy:   p,
		tainted:  make(map[string]map[string]bool),
		consumed: make(map[string]bool),
		granted:  make(map[string]bool),
	}
}

// GrantKey derives the coarse identity of a request for session grants: a tool+provider pair, or
// a method+host pair for egress. Approving "this session" then covers the same shape of call.
func GrantKey(req Request) string {
	if req.Tool != "" {
		return "tool:" + req.Tool + "|" + req.Provider
	}
	return "http:" + req.Method + "|" + stripPort(req.Host)
}

// GrantSession records an approval so future matching calls in the same session skip the prompt.
func (e *Engine) GrantSession(req Request) {
	e.mu.Lock()
	e.granted[req.SessionID+"|"+GrantKey(req)] = true
	e.mu.Unlock()
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
			{Match: Match{Tool: "execute_shell"}, Action: ActionDeny},
			{Match: Match{Tool: "*delete*"}, Action: ActionHITL},
			{Match: Match{Tool: "*read*"}, Action: ActionAllow},
			{Match: Match{Tool: "*list*"}, Action: ActionAllow},
			{Match: Match{Tool: "*search*"}, Action: ActionAllow},
			{Match: Match{Tool: "*get*"}, Action: ActionAllow},
			{Match: Match{Method: "GET"}, Action: ActionAllow},
			{Match: Match{Method: "HEAD"}, Action: ActionAllow},
		},
	}
}

// Policy returns the underlying ruleset.
func (e *Engine) Policy() Policy { return e.policy }

// ProviderScopes returns the OAuth scopes configured for a provider, if any.
func (e *Engine) ProviderScopes(provider string) []string {
	return e.policy.Providers[provider].Scopes
}

// Evaluate authorizes a request, mutating session state (taint, one-time consumption) as a side effect.
func (e *Engine) Evaluate(req Request) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	// A prior "approve for this session" short-circuits the prompt for the same shape of call.
	if e.granted[req.SessionID+"|"+GrantKey(req)] {
		return Decision{Action: ActionAllow, Reason: "session grant"}
	}

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

		if rule.OneTime {
			key := req.SessionID + "|" + ruleFingerprint(rule)
			if e.consumed[key] {
				return Decision{Action: ActionDeny, Rule: rule, Reason: "one-time authorization already consumed for this session"}
			}
		}

		action := rule.Action
		if action == "" {
			action = e.policy.DefaultAction
		}

		// Read-then-exfiltrate guard: a permitted egress to a non-allowlisted host after
		// the session has touched sensitive data escalates to a human decision.
		if action == ActionAllow && e.policy.EscalateWhenTainted && req.Host != "" &&
			e.sessionTaintedLocked(req.SessionID) && !hostAllowed(e.policy.Egress.Allow, req.Host) {
			e.stampTaintLocked(req.SessionID, rule.Taints)
			return Decision{Action: ActionHITL, Rule: rule, Reason: "tainted session egressing to non-allowlisted host"}
		}

		e.stampTaintLocked(req.SessionID, rule.Taints)
		if rule.OneTime && action != ActionDeny {
			e.consumed[req.SessionID+"|"+ruleFingerprint(rule)] = true
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

func (e *Engine) sessionTaintedLocked(session string) bool {
	return len(e.tainted[session]) > 0
}

func (e *Engine) stampTaintLocked(session string, labels []string) {
	if len(labels) == 0 {
		return
	}
	if e.tainted[session] == nil {
		e.tainted[session] = make(map[string]bool)
	}
	for _, l := range labels {
		e.tainted[session][l] = true
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
		return true
	}
	if m.Method != "" && !strings.EqualFold(m.Method, req.Method) {
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
	return strings.Join([]string{r.Match.Method, r.Match.Host, r.Match.Path, r.Match.Tool, r.Scope}, "\x1f")
}
