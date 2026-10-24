package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testEngine() *Engine {
	return NewEngine(Policy{
		Agent:               "claims-processor-v1",
		Egress:              Egress{Allow: []string{"api.internal.company.com", "*.github.com"}},
		EscalateWhenTainted: true,
		Tools: []Rule{
			{Match: Match{Method: "GET", Host: "api.internal.company.com", Path: "/v1/claims/**"}, Scope: "claims:read", Action: ActionAllow, Taints: []string{"db:read"}},
			{Match: Match{Method: "POST", Path: "/v1/payouts/**"}, Scope: "payout:write", Action: ActionHITL, OneTime: true},
			{Match: Match{Tool: "execute_shell"}, Action: ActionDeny},
		},
	})
}

func TestAllowWithScope(t *testing.T) {
	e := testEngine()
	d := e.Evaluate(Request{SessionID: "s1", Method: "GET", Host: "api.internal.company.com", Path: "/v1/claims/123", Scopes: []string{"claims:read"}})
	if d.Action != ActionAllow {
		t.Fatalf("want allow, got %s (%s)", d.Action, d.Reason)
	}
}

func TestDenyMissingScope(t *testing.T) {
	e := testEngine()
	d := e.Evaluate(Request{SessionID: "s1", Method: "GET", Host: "api.internal.company.com", Path: "/v1/claims/123", Scopes: []string{"other"}})
	if d.Action != ActionDeny {
		t.Fatalf("want deny, got %s", d.Action)
	}
}

func TestHITLOnPayout(t *testing.T) {
	e := testEngine()
	d := e.Evaluate(Request{SessionID: "s1", Method: "POST", Host: "api.internal.company.com", Path: "/v1/payouts/execute", Scopes: []string{"payout:write"}})
	if d.Action != ActionHITL {
		t.Fatalf("want hitl, got %s", d.Action)
	}
}

func TestOneTimeConsumed(t *testing.T) {
	e := testEngine()
	req := Request{SessionID: "s1", Method: "POST", Host: "api.internal.company.com", Path: "/v1/payouts/execute", Scopes: []string{"payout:write"}}
	if d := e.Evaluate(req); d.Action != ActionHITL {
		t.Fatalf("first call want hitl, got %s", d.Action)
	}
	if d := e.Evaluate(req); d.Action != ActionDeny {
		t.Fatalf("second call want deny (one-time), got %s", d.Action)
	}
}

func TestExecuteShellDenied(t *testing.T) {
	e := testEngine()
	d := e.Evaluate(Request{SessionID: "s1", Tool: "execute_shell"})
	if d.Action != ActionDeny {
		t.Fatalf("want deny, got %s", d.Action)
	}
}

func TestEgressAllowlistFallback(t *testing.T) {
	e := testEngine()
	// no rule matches example.org; it is not in the allowlist -> deny
	if d := e.Evaluate(Request{SessionID: "s1", Method: "GET", Host: "example.org", Path: "/x"}); d.Action != ActionDeny {
		t.Fatalf("want deny for non-allowlisted host, got %s", d.Action)
	}
	// api.github.com matches *.github.com allowlist -> allow
	if d := e.Evaluate(Request{SessionID: "s1", Method: "GET", Host: "api.github.com", Path: "/x"}); d.Action != ActionAllow {
		t.Fatalf("want allow for allowlisted host, got %s", d.Action)
	}
}

func TestTaintEscalation(t *testing.T) {
	e := NewEngine(Policy{
		Egress:              Egress{Allow: []string{"api.internal.company.com"}},
		EscalateWhenTainted: true,
		Tools: []Rule{
			{Match: Match{Method: "GET", Host: "api.internal.company.com", Path: "/**"}, Action: ActionAllow, Taints: []string{"db:read"}},
			{Match: Match{Method: "POST", Host: "evil.example.com", Path: "/**"}, Action: ActionAllow},
		},
	})
	// First a benign read that taints the session.
	if d := e.Evaluate(Request{SessionID: "s1", Method: "GET", Host: "api.internal.company.com", Path: "/data"}); d.Action != ActionAllow {
		t.Fatalf("read want allow, got %s", d.Action)
	}
	// Now egress to a non-allowlisted host should escalate to HITL despite the allow rule.
	if d := e.Evaluate(Request{SessionID: "s1", Method: "POST", Host: "evil.example.com", Path: "/leak"}); d.Action != ActionHITL {
		t.Fatalf("tainted egress want hitl, got %s (%s)", d.Action, d.Reason)
	}
}

func TestHostMatch(t *testing.T) {
	cases := []struct {
		pat, host string
		want      bool
	}{
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "github.com", false},
		{"api.github.com", "api.github.com:443", true},
		{"example.com", "example.org", false},
	}
	for _, c := range cases {
		if got := hostMatch(c.pat, c.host); got != c.want {
			t.Errorf("hostMatch(%q,%q)=%v want %v", c.pat, c.host, got, c.want)
		}
	}
}

func TestProviderAccessRule(t *testing.T) {
	e := NewEngine(Policy{
		DefaultAction: ActionDeny,
		Providers: map[string]ProviderRule{
			"github":       {Access: ActionAllow, Scopes: []string{"repo"}},
			"google-drive": {Access: ActionHITL},
		},
	})
	if d := e.Evaluate(Request{Tool: "request_access", Provider: "github"}); d.Action != ActionAllow {
		t.Fatalf("github request_access want allow, got %s", d.Action)
	}
	if d := e.Evaluate(Request{Tool: "request_access", Provider: "google-drive"}); d.Action != ActionHITL {
		t.Fatalf("drive request_access want hitl, got %s", d.Action)
	}
	// Unconfigured provider falls back to default.
	if d := e.Evaluate(Request{Tool: "request_access", Provider: "slack"}); d.Action != ActionDeny {
		t.Fatalf("slack request_access want deny(default), got %s", d.Action)
	}
}

func TestGetCredentialDeniedByDefault(t *testing.T) {
	e := NewEngine(Policy{
		DefaultAction: ActionAllow, // even permissive default must not leak tokens
		Providers:     map[string]ProviderRule{"github": {Access: ActionAllow}},
	})
	if d := e.Evaluate(Request{Tool: "get_credential", Provider: "github"}); d.Action != ActionDeny {
		t.Fatalf("get_credential must default to deny, got %s", d.Action)
	}
	// Explicit opt-in is honored.
	e2 := NewEngine(Policy{Providers: map[string]ProviderRule{"github": {Credential: ActionHITL}}})
	if d := e2.Evaluate(Request{Tool: "get_credential", Provider: "github"}); d.Action != ActionHITL {
		t.Fatalf("explicit credential rule want hitl, got %s", d.Action)
	}
}

func TestProviderGlobMatch(t *testing.T) {
	if !toolMatch("google-*", "google-drive") {
		t.Fatal("google-* should match google-drive")
	}
	if toolMatch("google-*", "slack") {
		t.Fatal("google-* should not match slack")
	}
}

func TestSessionGrant(t *testing.T) {
	e := NewEngine(Policy{
		DefaultAction: ActionHITL,
		Tools:         []Rule{{Match: Match{Method: "POST", Path: "/**"}, Action: ActionHITL}},
	})
	req := Request{SessionID: "s", Method: "POST", Host: "api.internal", Path: "/x"}
	d := e.Evaluate(req)
	if d.Action != ActionHITL {
		t.Fatalf("first call want hitl, got %s", d.Action)
	}
	e.GrantSession(req, d)
	if d := e.Evaluate(req); d.Action != ActionAllow {
		t.Fatalf("after grant want allow, got %s", d.Action)
	}
	// Same host, different path -> still covered (grant is host-level).
	if d := e.Evaluate(Request{SessionID: "s", Method: "POST", Host: "api.internal", Path: "/y"}); d.Action != ActionAllow {
		t.Fatalf("same-host different-path should be covered, got %s", d.Action)
	}
	// Different host -> not covered.
	if d := e.Evaluate(Request{SessionID: "s", Method: "POST", Host: "evil.example", Path: "/x"}); d.Action == ActionAllow {
		t.Fatal("grant must not cover a different host")
	}
	// Different session -> not covered.
	if d := e.Evaluate(Request{SessionID: "other", Method: "POST", Host: "api.internal", Path: "/x"}); d.Action == ActionAllow {
		t.Fatal("grant must not leak across sessions")
	}
}

func TestSessionGrantDoesNotOverrideDeny(t *testing.T) {
	e := NewEngine(Policy{
		Tools: []Rule{
			{Match: Match{Method: "POST", Path: "/admin/**"}, Action: ActionDeny},
			{Match: Match{Method: "POST", Path: "/billing/**"}, Scope: "billing:write", Action: ActionHITL},
			{Match: Match{Method: "POST", Path: "/**"}, Action: ActionHITL},
		},
	})
	req := Request{SessionID: "s", Method: "POST", Host: "api.internal", Path: "/x"}
	e.GrantSession(req, e.Evaluate(req))

	if d := e.Evaluate(Request{SessionID: "s", Method: "POST", Host: "api.internal", Path: "/admin/users"}); d.Action != ActionDeny {
		t.Fatalf("grant must not override a deny rule, got %s (%s)", d.Action, d.Reason)
	}
	if d := e.Evaluate(Request{SessionID: "s", Method: "POST", Host: "api.internal", Path: "/billing/pay"}); d.Action != ActionDeny {
		t.Fatalf("grant must not override a scope requirement, got %s (%s)", d.Action, d.Reason)
	}
}

func TestSessionGrantDoesNotOverrideOneTime(t *testing.T) {
	e := testEngine()
	req := Request{SessionID: "s", Method: "POST", Host: "api.internal.company.com", Path: "/v1/payouts/execute", Scopes: []string{"payout:write"}}
	e.GrantSession(req, e.Evaluate(req))
	if d := e.Evaluate(req); d.Action != ActionDeny {
		t.Fatalf("one-time rule must stay consumed despite grant, got %s (%s)", d.Action, d.Reason)
	}
}

func TestGrantAtTaintPromptCoversTaint(t *testing.T) {
	e := NewEngine(Policy{
		Egress:              Egress{Allow: []string{"api.internal"}},
		EscalateWhenTainted: true,
		Tools: []Rule{
			{Match: Match{Method: "GET", Host: "api.internal"}, Action: ActionAllow, Taints: []string{"db:read"}},
			{Match: Match{Method: "PUT", Host: "paste.example"}, Action: ActionAllow},
		},
	})
	e.Evaluate(Request{SessionID: "s", Method: "GET", Host: "api.internal", Path: "/secrets"})

	put := Request{SessionID: "s", Method: "PUT", Host: "paste.example", Path: "/"}
	d := e.Evaluate(put)
	if d.Action != ActionHITL || !d.TaintEscalated {
		t.Fatalf("tainted egress want escalated hitl, got %s (%s)", d.Action, d.Reason)
	}
	e.GrantSession(put, d)
	if d := e.Evaluate(put); d.Action != ActionAllow {
		t.Fatalf("grant made at a taint prompt should cover it, got %s (%s)", d.Action, d.Reason)
	}
}

func TestCleanGrantForSameShapeStillEscalates(t *testing.T) {
	e := NewEngine(Policy{
		Egress:              Egress{Allow: []string{"api.internal"}},
		EscalateWhenTainted: true,
		Tools: []Rule{
			{Match: Match{Method: "GET", Host: "api.internal"}, Action: ActionAllow, Taints: []string{"db:read"}},
			{Match: Match{Method: "POST", Host: "paste.example", Path: "/draft"}, Action: ActionHITL},
			{Match: Match{Method: "POST", Host: "paste.example"}, Action: ActionAllow},
		},
	})
	draft := Request{SessionID: "s", Method: "POST", Host: "paste.example", Path: "/draft"}
	e.GrantSession(draft, e.Evaluate(draft))

	e.Evaluate(Request{SessionID: "s", Method: "GET", Host: "api.internal", Path: "/secrets"})
	if d := e.Evaluate(Request{SessionID: "s", Method: "POST", Host: "paste.example", Path: "/leak"}); d.Action != ActionHITL {
		t.Fatalf("pre-taint grant must not bypass taint escalation, got %s (%s)", d.Action, d.Reason)
	}
}

func TestIdleSessionsEvicted(t *testing.T) {
	e := testEngine()
	now := time.Unix(1_000_000, 0)
	e.now = func() time.Time { return now }

	e.Evaluate(Request{SessionID: "old", Method: "GET", Host: "api.internal.company.com", Path: "/v1/claims/1", Scopes: []string{"claims:read"}})
	now = now.Add(SessionIdleTTL + 2*time.Minute)
	e.Evaluate(Request{SessionID: "new", Tool: "execute_shell"})

	if _, ok := e.sessions["old"]; ok {
		t.Fatal("idle session should have been evicted")
	}
	if _, ok := e.sessions["new"]; !ok {
		t.Fatal("active session should be retained")
	}
}

func TestPersistedAllowInheritsConstraints(t *testing.T) {
	matched := &Rule{Scope: "repo:write", Taints: []string{"vcs"}, OneTime: true, Action: ActionHITL}
	r := PersistedAllow(Match{Method: "POST", Host: "api.github.com", Path: "/repos/x"}, matched)
	if r.Action != ActionAllow || r.Scope != "repo:write" || !r.OneTime || len(r.Taints) != 1 || r.Taints[0] != "vcs" {
		t.Fatalf("persisted rule lost constraints: %+v", r)
	}
	if r.Match.Path != "/repos/x" {
		t.Fatalf("persisted rule must keep the exact path, got %q", r.Match.Path)
	}
	matched.Taints[0] = "mutated"
	if r.Taints[0] != "vcs" {
		t.Fatal("persisted rule must not alias the matched rule's taints")
	}
}

func TestDefaultPolicyTiers(t *testing.T) {
	e := NewEngine(DefaultPolicy())
	cases := []struct {
		req  Request
		want Action
	}{
		{Request{SessionID: "s", Tool: "read_file"}, ActionAllow},
		{Request{SessionID: "s", Tool: "list_directory"}, ActionAllow},
		{Request{SessionID: "s", Tool: "execute_shell"}, ActionDeny},
		{Request{SessionID: "s", Tool: "write_file"}, ActionHITL}, // ambiguous -> ask
		{Request{SessionID: "s", Method: "GET", Host: "h", Path: "/"}, ActionAllow},
	}
	for _, c := range cases {
		if d := e.Evaluate(c.req); d.Action != c.want {
			t.Errorf("%+v: want %s, got %s", c.req, c.want, d.Action)
		}
	}
}

func TestHostMatches(t *testing.T) {
	pats := []string{"api.github.com", "*.pinned.example"}
	cases := map[string]bool{
		"api.github.com":         true,
		"API.GitHub.com:443":     true,
		"github.com":             false,
		"a.pinned.example":       true,
		"x.y.pinned.example:443": true,
		"pinned.example":         false,
		"evil.com":               false,
	}
	for host, want := range cases {
		if got := HostMatches(pats, host); got != want {
			t.Errorf("HostMatches(%q) = %v, want %v", host, got, want)
		}
	}
	if HostMatches(nil, "api.github.com") {
		t.Error("empty pattern list must not match")
	}
}

func TestLoadParsesPassthrough(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	if err := os.WriteFile(path, []byte("egress:\n  allow: [api.github.com]\n  passthrough: [\"*.pinned.example\", bank.example]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Egress.Passthrough) != 2 || p.Egress.Passthrough[0] != "*.pinned.example" || p.Egress.Passthrough[1] != "bank.example" {
		t.Fatalf("passthrough = %v", p.Egress.Passthrough)
	}
}
