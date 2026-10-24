package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/gate"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func checkPolicy() policy.Policy {
	return policy.Policy{
		DefaultAction:       policy.ActionDeny,
		EscalateWhenTainted: true,
		Egress:              policy.Egress{Allow: []string{"api.good.com"}},
		Tools: []policy.Rule{
			{Match: policy.Match{Tool: "fs__read*"}, Action: policy.ActionAllow, Taints: []string{"secrets"}},
			{Match: policy.Match{Tool: "shell"}, Action: policy.ActionDeny},
			{Match: policy.Match{Tool: "fs__write", Args: map[string]string{"path": "/tmp/**"}}, Action: policy.ActionAllow},
			{Match: policy.Match{Tool: "fs__write"}, Action: policy.ActionHITL},
			{Match: policy.Match{Tool: "deploy"}, Action: policy.ActionAllow, OneTime: true},
			{Match: policy.Match{Method: "POST"}, Action: policy.ActionAllow},
		},
	}
}

type checkEnv struct {
	s      *Server
	b      *hitl.Broker
	log    *audit.Logger
	path   string
	signer *jwt.TokenSigner
}

func startCheckServer(t *testing.T, timeout time.Duration, mod func(*gate.Config)) *checkEnv {
	t.Helper()
	s, b := startServer(t, timeout)
	apath := filepath.Join(t.TempDir(), "audit.jsonl")
	lg, err := audit.Open(apath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lg.Close() })
	signer, err := jwt.NewTokenSigner()
	if err != nil {
		t.Fatal(err)
	}
	cfg := gate.Config{
		Engine:          policy.NewEngine(checkPolicy()),
		Approver:        b,
		ApprovalTimeout: timeout,
		Audit:           lg,
		Verifier:        signer.Verifier(),
	}
	if mod != nil {
		mod(&cfg)
	}
	g, err := gate.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.SetChecker(g)
	return &checkEnv{s: s, b: b, log: lg, path: apath, signer: signer}
}

func (e *checkEnv) client() *Client { return NewClient(e.s.Info()) }

func (e *checkEnv) check(t *testing.T, req CheckRequest) CheckResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := e.client().Check(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// decideWhenQueued answers the first approval that appears on the broker.
func decideWhenQueued(t *testing.T, b *hitl.Broker, d hitl.Decision) <-chan hitl.Request {
	t.Helper()
	out := make(chan hitl.Request, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if p := b.Pending(); len(p) > 0 {
				_ = b.Decide(p[0].ID, d)
				out <- p[0]
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		close(out)
	}()
	return out
}

func TestCheckAllowDenyDefault(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	cases := []struct {
		name   string
		req    CheckRequest
		want   string
		source string
		rule   string
	}{
		{"allow", CheckRequest{Tool: "fs__read_file", Args: json.RawMessage(`{"path":"/etc/hosts"}`)}, "allow", gate.SourcePolicy, "tool=fs__read* -> allow"},
		{"deny", CheckRequest{Tool: "shell"}, "deny", gate.SourcePolicy, "tool=shell -> deny"},
		{"default", CheckRequest{Tool: "unknown_tool"}, "deny", gate.SourceDefault, ""},
		{"args-allow", CheckRequest{Tool: "fs__write", Args: json.RawMessage(`{"path":"/tmp/x"}`)}, "allow", gate.SourcePolicy, "tool=fs__write args[path]=/tmp/** -> allow"},
		{"egress-allowlist", CheckRequest{Method: "get", Host: "api.good.com", Path: "/x"}, "allow", gate.SourceDefault, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.check(t, tc.req)
			if got.Decision != tc.want || got.Source != tc.source || got.Rule != tc.rule || got.ApprovalID != "" {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestCheckHITLApprovedAndDenied(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	for _, tc := range []struct {
		d    hitl.Decision
		want string
	}{{hitl.Once, "allow"}, {hitl.Deny, "deny"}} {
		seen := decideWhenQueued(t, e.b, tc.d)
		got := e.check(t, CheckRequest{AgentID: "bot", ActAs: "alice", Tool: "fs__write", Args: json.RawMessage(`{"path":"/etc/passwd"}`)})
		req := <-seen
		if got.Decision != tc.want || got.Source != gate.SourceApprove || got.ApprovalID == "" || got.ApprovalID != req.ID {
			t.Fatalf("%v: got %+v (req %+v)", tc.d, got, req)
		}
		if req.Tool != "fs__write" || req.AgentID != "bot" || req.ActAsUser != "alice" || !strings.Contains(req.Params, "/etc/passwd") {
			t.Fatalf("approval request: %+v", req)
		}
	}
}

func TestCheckHITLSessionGrantSticks(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	decideWhenQueued(t, e.b, hitl.Session)
	if got := e.check(t, CheckRequest{Tool: "fs__write"}); got.Decision != "allow" || got.Reason != "approved for session" {
		t.Fatalf("got %+v", got)
	}
	// Same session: no prompt.
	if got := e.check(t, CheckRequest{Tool: "fs__write"}); got.Decision != "allow" || got.Reason != "session grant" || got.Source != gate.SourceApprove {
		t.Fatalf("got %+v", got)
	}
	// Another session still asks (wait 0 → pending).
	if got := e.check(t, CheckRequest{Tool: "fs__write", Session: "other", Wait: "0"}); got.Decision != "pending" {
		t.Fatalf("got %+v", got)
	}
}

func TestCheckHITLTimeout(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, func(c *gate.Config) { c.ApprovalTimeout = 150 * time.Millisecond })
	start := time.Now()
	got := e.check(t, CheckRequest{Tool: "fs__write"})
	if got.Decision != "deny" || got.Reason != "denied at human-in-the-loop (approval timed out)" || got.ApprovalID == "" {
		t.Fatalf("got %+v", got)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not applied")
	}
	if n := len(e.b.Pending()); n != 0 {
		t.Fatalf("%d approvals left pending", n)
	}
}

func TestCheckOneTimeConsumed(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	if got := e.check(t, CheckRequest{Tool: "deploy"}); got.Decision != "allow" {
		t.Fatalf("first: %+v", got)
	}
	got := e.check(t, CheckRequest{Tool: "deploy"})
	if got.Decision != "deny" || !strings.Contains(got.Reason, "one-time") {
		t.Fatalf("second: %+v", got)
	}
	// A different session has its own budget.
	if got := e.check(t, CheckRequest{Tool: "deploy", Session: "s2"}); got.Decision != "allow" {
		t.Fatalf("other session: %+v", got)
	}
}

func TestCheckTaintEscalation(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	post := CheckRequest{AgentID: "bot", ActAs: "alice", Method: "POST", Host: "evil.example", Path: "/upload", Wait: "0"}
	if got := e.check(t, post); got.Decision != "allow" {
		t.Fatalf("before taint: %+v", got)
	}
	if got := e.check(t, CheckRequest{AgentID: "bot", ActAs: "alice", Tool: "fs__read_file"}); got.Decision != "allow" {
		t.Fatalf("read: %+v", got)
	}
	got := e.check(t, post)
	if got.Decision != "pending" || got.ApprovalID == "" || !strings.Contains(got.Reason, "tainted") {
		t.Fatalf("after taint: %+v", got)
	}
	// Other identities are untainted.
	other := post
	other.AgentID = "bot2"
	if got := e.check(t, other); got.Decision != "allow" {
		t.Fatalf("other session: %+v", got)
	}
	if err := e.b.Decide(got.ApprovalID, hitl.Deny); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPendingAndPoll(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	cl := e.client()
	ctx := context.Background()
	got, err := cl.Check(ctx, CheckRequest{Tool: "fs__write", Wait: "0"})
	if err != nil || got.Decision != "pending" || got.ApprovalID == "" {
		t.Fatalf("got %+v %v", got, err)
	}
	// The approval is visible to `nexus-cli approve` under the same ID.
	p := e.b.Pending()
	if len(p) != 1 || p[0].ID != got.ApprovalID {
		t.Fatalf("pending %+v", p)
	}
	st, err := cl.CheckStatus(ctx, got.ApprovalID, 0)
	if err != nil || st.Decision != "pending" {
		t.Fatalf("poll: %+v %v", st, err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = cl.Decide(ctx, got.ApprovalID, hitl.Once)
	}()
	st, err = cl.CheckStatus(ctx, got.ApprovalID, 5*time.Second)
	if err != nil || st.Decision != "allow" || st.Reason != "approved once" || st.ApprovalID != got.ApprovalID {
		t.Fatalf("long poll: %+v %v", st, err)
	}
	// The result stays pollable.
	if st2, err := cl.CheckStatus(ctx, got.ApprovalID, 0); err != nil || st2 != st {
		t.Fatalf("repoll: %+v %v", st2, err)
	}
	if _, err := cl.CheckStatus(ctx, "nope", 0); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestCheckWaitReturnsDecisionWithinWindow(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	decideWhenQueued(t, e.b, hitl.Once)
	if got := e.check(t, CheckRequest{Tool: "fs__write", Wait: "5s"}); got.Decision != "allow" {
		t.Fatalf("got %+v", got)
	}
	// An undecided call returns pending after the window.
	got := e.check(t, CheckRequest{Tool: "fs__write", Wait: "50ms"})
	if got.Decision != "pending" {
		t.Fatalf("got %+v", got)
	}
	_ = e.b.Decide(got.ApprovalID, hitl.Deny)
}

func TestCheckAudited(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	e.check(t, CheckRequest{AgentID: "bot", ActAs: "alice", Tool: "fs__read_file", Args: json.RawMessage(`{"path":"/a"}`)})
	e.check(t, CheckRequest{AgentID: "bot", ActAs: "alice", Tool: "shell"})
	decideWhenQueued(t, e.b, hitl.Once)
	e.check(t, CheckRequest{AgentID: "bot", ActAs: "alice", Tool: "fs__write"})
	e.check(t, CheckRequest{AgentID: "bot", ActAs: "alice", Method: "GET", Host: "api.good.com", Path: "/v1"})

	entries, err := audit.ReadAll(e.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d entries: %+v", len(entries), entries)
	}
	want := []struct{ tool, target, decision, source, reason string }{
		{"fs__read_file", "sdk:fs__read_file", "allow", "policy", "matched rule"},
		{"shell", "sdk:shell", "deny", "policy", "matched rule"},
		{"fs__write", "sdk:fs__write", "allow", "approve", "approved once"},
		{"GET", "api.good.com/v1", "allow", "default", "host in egress allowlist"},
	}
	for i, w := range want {
		en := entries[i]
		if en.Tool != w.tool || en.Target != w.target || en.Decision != w.decision || en.Source != w.source || en.Reason != w.reason ||
			en.Agent != "bot" || en.ActAs != "alice" || en.Session != "bot|alice" {
			t.Fatalf("entry %d: %+v", i, en)
		}
	}
	if entries[0].ArgsHash != audit.HashArgs([]byte(`{"path":"/a"}`)) || entries[0].Rule != "tool=fs__read* -> allow" {
		t.Fatalf("entry 0 args/rule: %+v", entries[0])
	}
	if entries[1].ArgsHash != "" {
		t.Fatalf("no-args hash: %+v", entries[1])
	}
	if _, err := audit.Verify(e.path); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

func TestCheckValidation(t *testing.T) {
	e := startCheckServer(t, time.Second, nil)
	cases := []struct {
		name, body string
		ct         string
		code       int
	}{
		{"unknown field", `{"tool":"x","bogus":1}`, "application/json", http.StatusBadRequest},
		{"trailing", `{"tool":"x"} {}`, "application/json", http.StatusBadRequest},
		{"not json", `tool=x`, "application/json", http.StatusBadRequest},
		{"empty call", `{}`, "application/json", http.StatusBadRequest},
		{"args not object", `{"tool":"x","args":[1]}`, "application/json", http.StatusBadRequest},
		{"bad wait", `{"tool":"x","wait":"soon"}`, "application/json", http.StatusBadRequest},
		{"content type", `{"tool":"x"}`, "text/plain", http.StatusUnsupportedMediaType},
		{"too large", `{"tool":"x","args":{"a":"` + strings.Repeat("a", 70<<10) + `"}}`, "application/json", http.StatusRequestEntityTooLarge},
		{"ok", `{"tool":"shell","args":null}`, "application/json; charset=utf-8", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := rawReq(t, e.s, http.MethodPost, "/v1/check", tc.body, func(r *http.Request) { r.Header.Set("Content-Type", tc.ct) })
			if resp.StatusCode != tc.code {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d (%s), want %d", resp.StatusCode, b, tc.code)
			}
		})
	}
	// Just under the limit is accepted.
	body := `{"tool":"shell","args":{"a":"` + strings.Repeat("a", 60<<10) + `"}}`
	if resp := rawReq(t, e.s, http.MethodPost, "/v1/check", body, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("60KiB body: %d", resp.StatusCode)
	}
}

func TestCheckAuth(t *testing.T) {
	e := startCheckServer(t, time.Second, nil)
	for _, auth := range []string{"", "Bearer wrong", "Bearer " + e.s.Info().Token + "x"} {
		resp := rawReq(t, e.s, http.MethodPost, "/v1/check", `{"tool":"shell"}`, func(r *http.Request) {
			if auth == "" {
				r.Header.Del("Authorization")
			} else {
				r.Header.Set("Authorization", auth)
			}
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("auth %q: %d", auth, resp.StatusCode)
		}
	}
	resp := rawReq(t, e.s, http.MethodGet, "/v1/check/abc", "", func(r *http.Request) { r.Header.Del("Authorization") })
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("poll without auth: %d", resp.StatusCode)
	}
	info := e.s.Info()
	info.Token = "nope"
	if _, err := NewClient(info).Check(context.Background(), CheckRequest{Tool: "shell"}); err != ErrUnauthorized {
		t.Fatalf("client: %v", err)
	}
}

func TestCheckTokens(t *testing.T) {
	e := startCheckServer(t, time.Second, func(c *gate.Config) { c.RequireToken = true })
	tok, err := e.signer.Mint(jwt.MintOptions{AgentID: "bot", UserID: "alice", Scopes: []string{"read"}, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.check(t, CheckRequest{Tool: "fs__read_file"}); got.Decision != "deny" || got.Source != gate.SourceGuard || !strings.Contains(got.Reason, "token is required") {
		t.Fatalf("missing token: %+v", got)
	}
	if got := e.check(t, CheckRequest{Tool: "fs__read_file", Token: tok + "x"}); got.Decision != "deny" || got.Source != gate.SourceGuard || !strings.Contains(got.Reason, "invalid token") {
		t.Fatalf("bad token: %+v", got)
	}
	if got := e.check(t, CheckRequest{Tool: "fs__read_file", Token: tok, AgentID: "mallory"}); got.Decision != "deny" || !strings.Contains(got.Reason, "do not match") {
		t.Fatalf("mismatch: %+v", got)
	}
	if got := e.check(t, CheckRequest{Tool: "fs__read_file", Token: tok}); got.Decision != "allow" {
		t.Fatalf("valid token: %+v", got)
	}
	entries, err := audit.ReadAll(e.path)
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	if last.Agent != "bot" || last.ActAs != "alice" || last.JTI == "" || len(last.Scopes) != 1 || last.Session != "bot|alice" {
		t.Fatalf("token identity not used: %+v", last)
	}

	// Without RequireToken, an invalid token still denies.
	e2 := startCheckServer(t, time.Second, nil)
	if got := e2.check(t, CheckRequest{Tool: "fs__read_file", Token: "garbage"}); got.Decision != "deny" || got.Source != gate.SourceGuard {
		t.Fatalf("optional bad token: %+v", got)
	}
	if got := e2.check(t, CheckRequest{Tool: "fs__read_file"}); got.Decision != "allow" {
		t.Fatalf("optional no token: %+v", got)
	}
}

func TestCheckDisabled(t *testing.T) {
	s, _ := startServer(t, time.Second)
	resp := rawReq(t, s, http.MethodPost, "/v1/check", `{"tool":"x"}`, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestCheckClientDisconnectDenies(t *testing.T) {
	e := startCheckServer(t, 5*time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := e.client().Check(ctx, CheckRequest{Tool: "fs__write"})
		errc <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.b.Pending()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("never queued")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-errc
	for len(e.b.Pending()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("approval not withdrawn after disconnect")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// The cancelled call is audited as a denial.
	for {
		entries, _ := audit.ReadAll(e.path)
		if len(entries) == 1 {
			if entries[0].Decision != "deny" || !strings.Contains(entries[0].Reason, "cancelled") {
				t.Fatalf("entry: %+v", entries[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no audit entry")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCheckCloseReleasesAsync(t *testing.T) {
	e := startCheckServer(t, 30*time.Second, nil)
	got := e.check(t, CheckRequest{Tool: "fs__write", Wait: "0"})
	if got.Decision != "pending" {
		t.Fatalf("got %+v", got)
	}
	e.s.Close()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.b.Pending()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("async approval survived Close")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
