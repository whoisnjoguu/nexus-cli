package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

type fakeResolver struct {
	token string
	gotGW string
	gotID string
}

func (f *fakeResolver) Token(_ context.Context, gatewayURL, connectionID string) (string, error) {
	f.gotGW, f.gotID = gatewayURL, connectionID
	return f.token, nil
}

func TestCredentialInjection(t *testing.T) {
	var gotAuth, gotNexusTok string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotNexusTok = r.Header.Get("X-Nexus-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	signer, _ := jwt.NewTokenSigner()
	engine := policy.NewEngine(policy.Policy{
		Tools: []policy.Rule{{Match: policy.Match{Method: "GET", Path: "/**"}, Action: policy.ActionAllow, Inject: true}},
	})
	res := &fakeResolver{token: "broker-secret"}
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: engine, Credentials: res})

	tok, _ := signer.Mint(jwt.MintOptions{AgentID: "agent", UserID: "alice", Scopes: []string{"read"}, ConnID: "conn-123", Gateway: "http://gw.local", TTL: time.Minute})
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)

	if gotAuth != "Bearer broker-secret" {
		t.Fatalf("upstream Authorization = %q, want injected broker token", gotAuth)
	}
	if gotNexusTok != "" {
		t.Fatalf("nexus token leaked upstream: %q", gotNexusTok)
	}
	if res.gotID != "conn-123" || res.gotGW != "http://gw.local" {
		t.Fatalf("resolver called with gw=%q id=%q", res.gotGW, res.gotID)
	}
}

func TestInjectionFailsClosedWithoutConnection(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	engine := policy.NewEngine(policy.Policy{
		Tools: []policy.Rule{{Match: policy.Match{Method: "GET", Path: "/**"}, Action: policy.ActionAllow, Inject: true}},
	})
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: engine, Credentials: &fakeResolver{token: "x"}})

	// Token has no ConnID -> injection required but impossible -> fail closed.
	tok, _ := signer.Mint(jwt.MintOptions{AgentID: "agent", UserID: "alice", Scopes: []string{"read"}, TTL: time.Minute})
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when injection impossible, got %d", rec.Code)
	}
}

func TestStripsClientSuppliedIdentity(t *testing.T) {
	var gotAgent, gotActAs string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgent = r.Header.Get("X-Nexus-Agent-ID")
		gotActAs = r.Header.Get("X-Nexus-Act-As")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// No auth: the proxy must not trust client-provided identity headers.
	p := New(Config{})
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.Header.Set("X-Nexus-Agent-ID", "attacker-spoofed")
	req.Header.Set("X-Nexus-Act-As", "ceo@company.com")
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)

	if gotAgent == "attacker-spoofed" || gotActAs == "ceo@company.com" {
		t.Fatalf("client-supplied identity leaked downstream: agent=%q act_as=%q", gotAgent, gotActAs)
	}
	if gotAgent != "anonymous-agent" || gotActAs != "unknown-user" {
		t.Fatalf("expected anonymous identity, got agent=%q act_as=%q", gotAgent, gotActAs)
	}
}

func TestPolicyDenyBlocksRequest(t *testing.T) {
	engine := policy.NewEngine(policy.Policy{
		Tools: []policy.Rule{{Match: policy.Match{Method: "GET", Path: "/**"}, Action: policy.ActionDeny}},
	})
	p := New(Config{Engine: engine})
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/blocked", nil)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from policy deny, got %d", rec.Code)
	}
}

func TestReplayGuardRejectsReusedToken(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	signer, _ := jwt.NewTokenSigner()
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Replay: jwt.NewReplayGuard()})
	tok, _ := signer.MintDualActorToken("agent", "alice", []string{"read"}, time.Minute)

	first, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	first.Header.Set("Authorization", "Bearer "+tok)
	rec1 := httptest.NewRecorder()
	p.handleIntercept(rec1, first)
	if rec1.Code == http.StatusUnauthorized {
		t.Fatalf("first use should be accepted, got 401")
	}

	second, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	second.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	p.handleIntercept(rec2, second)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replayed token should be rejected with 401, got %d", rec2.Code)
	}
}
