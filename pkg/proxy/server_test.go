package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func TestRequireAuthForwardsWithClaims(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Nexus-Act-As"); got != "alice" {
			t.Errorf("downstream X-Nexus-Act-As = %q, want alice", got)
		}
		if got := r.Header.Get("X-Nexus-Agent-ID"); got != "agent" {
			t.Errorf("downstream X-Nexus-Agent-ID = %q, want agent", got)
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()

	signer, err := jwt.NewTokenSigner()
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxyServer(0, false, true, signer.Verifier())
	tok, err := signer.MintDualActorToken("agent", "alice", []string{"read"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("expected forwarded 418, got %d", rec.Code)
	}
}

func TestRequireAuthRejectsMissingToken(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	p := NewProxyServer(0, false, true, signer.Verifier())

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuthRejectsBadToken(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	p := NewProxyServer(0, false, true, signer.Verifier())

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer not.a.jwt")
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestTaintSurvivesAcrossSingleUseTokens(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)

	engine := policy.NewEngine(policy.Policy{
		Egress:              policy.Egress{Allow: []string{u.Hostname()}},
		EscalateWhenTainted: true,
		Tools: []policy.Rule{
			{Match: policy.Match{Method: "GET", Host: u.Hostname()}, Action: policy.ActionAllow, Taints: []string{"db:read"}},
			{Match: policy.Match{Method: "POST", Host: "paste.example"}, Action: policy.ActionAllow},
		},
	})
	signer, _ := jwt.NewTokenSigner()
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Replay: jwt.NewReplayGuard(), Engine: engine})

	tok, _ := signer.MintDualActorToken("agent", "alice", nil, time.Minute)
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/secrets", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tainting read want 200, got %d", rec.Code)
	}

	// A fresh token (new jti) for the same agent+human must land in the same, now tainted, session.
	d := engine.Evaluate(policy.Request{SessionID: "agent|alice", Method: "POST", Host: "paste.example", Path: "/leak"})
	if d.Action != policy.ActionHITL || !d.TaintEscalated {
		t.Fatalf("exfil after taint want escalated hitl, got %s (%s)", d.Action, d.Reason)
	}
}

func TestPersistAllowKeepsExactShape(t *testing.T) {
	var got policy.Rule
	p := New(Config{OnPersistRule: func(r policy.Rule) { got = r }})
	matched := &policy.Rule{Scope: "repo:write", Taints: []string{"vcs"}}
	p.persistAllow(policy.Request{Method: "POST", Host: "api.github.com", Path: "/repos/a/b/issues"}, matched)

	want := policy.Match{Method: "POST", Host: "api.github.com", Path: "/repos/a/b/issues"}
	if !reflect.DeepEqual(got.Match, want) || got.Action != policy.ActionAllow || got.Scope != "repo:write" || len(got.Taints) != 1 {
		t.Fatalf("persisted rule = %+v", got)
	}
}

func TestBearerTokenSources(t *testing.T) {
	cases := []struct {
		name   string
		set    func(*http.Request)
		expect string
	}{
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc") }, "abc"},
		{"proxy-authorization", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "bearer def") }, "def"},
		{"x-nexus-token", func(r *http.Request) { r.Header.Set("X-Nexus-Token", "ghi") }, "ghi"},
		{"none", func(r *http.Request) {}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			c.set(req)
			if got := bearerToken(req); got != c.expect {
				t.Fatalf("bearerToken = %q, want %q", got, c.expect)
			}
		})
	}
}
