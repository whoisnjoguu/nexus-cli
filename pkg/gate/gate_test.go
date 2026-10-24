package gate

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func testPolicy() policy.Policy {
	return policy.Policy{
		DefaultAction: policy.ActionDeny,
		Tools: []policy.Rule{
			{Match: policy.Match{Tool: "read"}, Action: policy.ActionAllow},
			{Match: policy.Match{Tool: "pay"}, Scope: "pay:write", Action: policy.ActionAllow},
			{Match: policy.Match{Tool: "write", Args: map[string]string{"path": "/w/**"}}, Action: policy.ActionHITL, Taints: []string{"t"}},
		},
	}
}

func newGate(t *testing.T, cfg Config) *Gate {
	t.Helper()
	if cfg.Engine == nil {
		cfg.Engine = policy.NewEngine(testPolicy())
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func approverOf(d hitl.Decision) hitl.Approver {
	return hitl.ApproverFunc(func(context.Context, hitl.Request) hitl.Decision { return d })
}

func TestNewRequiresEngine(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("want error")
	}
}

func TestNoApproverDenies(t *testing.T) {
	g := newGate(t, Config{})
	res := g.Check(context.Background(), Call{Tool: "write", Args: map[string]any{"path": "/w/a"}})
	if res.Allowed || res.Source != SourceGuard || !strings.Contains(res.Reason, "no approver") || res.ApprovalID == "" {
		t.Fatalf("got %+v", res)
	}
}

func TestAlwaysPersistsNarrowRule(t *testing.T) {
	var got []policy.Rule
	g := newGate(t, Config{Approver: approverOf(hitl.Always), OnPersistRule: func(r policy.Rule) { got = append(got, r) }})
	res := g.Check(context.Background(), Call{Tool: "write", Args: map[string]any{"path": "/w/a"}})
	if !res.Allowed || res.Reason != "approved & persisted" {
		t.Fatalf("got %+v", res)
	}
	if len(got) != 1 || got[0].Match.Tool != "write" || got[0].Match.Args["path"] != "/w/**" || got[0].Action != policy.ActionAllow || len(got[0].Taints) != 1 {
		t.Fatalf("persisted %+v", got)
	}
	// The session grant also applies to the next call.
	if res := g.Check(context.Background(), Call{Tool: "write", Args: map[string]any{"path": "/w/b"}}); !res.Allowed || res.Reason != "session grant" {
		t.Fatalf("second: %+v", res)
	}
}

func TestStrictEscalatesAllows(t *testing.T) {
	var asked int
	g := newGate(t, Config{Strict: true, Approver: hitl.ApproverFunc(func(context.Context, hitl.Request) hitl.Decision {
		asked++
		return hitl.Session
	})})
	for i := 0; i < 2; i++ {
		if res := g.Check(context.Background(), Call{Tool: "read"}); !res.Allowed {
			t.Fatalf("got %+v", res)
		}
	}
	if asked != 1 {
		t.Fatalf("asked %d times", asked)
	}
}

func TestScopesFromTokenOnlyNarrow(t *testing.T) {
	signer, err := jwt.NewTokenSigner()
	if err != nil {
		t.Fatal(err)
	}
	g := newGate(t, Config{Verifier: signer.Verifier()})
	tok, _ := signer.Mint(jwt.MintOptions{AgentID: "a", UserID: "u", Scopes: []string{"read"}, TTL: time.Minute})
	// A caller can't add a scope the token lacks.
	if res := g.Check(context.Background(), Call{Tool: "pay", Token: tok, Scopes: []string{"pay:write"}}); res.Allowed {
		t.Fatalf("scope escalation: %+v", res)
	}
	tok2, _ := signer.Mint(jwt.MintOptions{AgentID: "a", UserID: "u", Scopes: []string{"pay:write"}, TTL: time.Minute})
	if res := g.Check(context.Background(), Call{Tool: "pay", Token: tok2}); !res.Allowed {
		t.Fatalf("token scope: %+v", res)
	}
	if res := g.Check(context.Background(), Call{Tool: "pay", Token: tok2, Scopes: []string{"other"}}); res.Allowed {
		t.Fatalf("narrowed away: %+v", res)
	}
}

func TestSingleUseTokenConsumed(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	g := newGate(t, Config{Verifier: signer.Verifier(), Replay: jwt.NewReplayGuard()})
	tok, _ := signer.Mint(jwt.MintOptions{AgentID: "a", UserID: "u", TTL: time.Minute, SingleUse: true})
	if res := g.Check(context.Background(), Call{Tool: "read", Token: tok}); !res.Allowed {
		t.Fatalf("first: %+v", res)
	}
	if res := g.Check(context.Background(), Call{Tool: "read", Token: tok}); res.Allowed || res.Source != SourceGuard {
		t.Fatalf("reuse: %+v", res)
	}
}

func TestPendingWaitOnce(t *testing.T) {
	var mu sync.Mutex
	asked := 0
	g := newGate(t, Config{Approver: hitl.ApproverFunc(func(ctx context.Context, r hitl.Request) hitl.Decision {
		mu.Lock()
		asked++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		return hitl.Once
	})})
	res, p := g.Begin(Call{Tool: "write", Args: map[string]any{"path": "/w/x"}})
	if p == nil || res.ApprovalID != p.ID() || res.Source != SourceApprove {
		t.Fatalf("begin: %+v %v", res, p)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := p.Wait(context.Background()); !r.Allowed || r.ApprovalID != p.ID() {
				t.Errorf("wait: %+v", r)
			}
		}()
	}
	wg.Wait()
	if asked != 1 {
		t.Fatalf("asked %d", asked)
	}
	if r := p.Result(); !r.Allowed {
		t.Fatalf("result: %+v", r)
	}
}

func TestRuleLabel(t *testing.T) {
	r := &policy.Rule{Match: policy.Match{Tool: "w", Args: map[string]string{"b": "2", "a": "1"}}, Action: policy.ActionHITL}
	if got := RuleLabel(r); got != "tool=w args[a]=1 args[b]=2 -> hitl" {
		t.Fatal(got)
	}
	if RuleLabel(nil) != "" {
		t.Fatal("nil")
	}
}
