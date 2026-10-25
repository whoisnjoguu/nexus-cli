package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// startProxy serves p on an ephemeral loopback port and returns its URL plus a stop func that
// asserts Serve returned nil.
func startProxy(t *testing.T, p *ProxyServer) (*url.URL, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.Serve(ctx, ln) }()
	u, _ := url.Parse("http://" + ln.Addr().String())
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-errCh:
				if err != nil {
					t.Errorf("Serve returned %v, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("Serve did not return after shutdown")
			}
		})
	}
	t.Cleanup(stop)
	return u, stop
}

func proxyClient(proxyURL *url.URL) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 10 * time.Second}
}

func withToken(u *url.URL, tok string) *url.URL {
	c := *u
	c.User = url.UserPassword("agent", tok)
	return &c
}

func TestListenAddrDefaultsToLoopback(t *testing.T) {
	if got := (Config{Port: 8075}).ListenAddr(); got != "127.0.0.1:8075" {
		t.Fatalf("default ListenAddr = %q, want 127.0.0.1:8075", got)
	}
	if got := (Config{Port: 8075, Listen: "0.0.0.0:9000"}).ListenAddr(); got != "0.0.0.0:9000" {
		t.Fatalf("explicit ListenAddr = %q", got)
	}
}

func TestListenAndServeShutsDownCleanly(t *testing.T) {
	p := New(Config{Listen: "127.0.0.1:0"})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- p.ListenAndServe(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe did not return")
	}
}

func TestServeGracefulShutdownClosesTunnels(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	p := New(Config{})
	u, stop := startProxy(t, p)

	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := echo.Addr().String()
	_, _ = io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT failed: %v %v", resp, err)
	}
	_, _ = io.WriteString(conn, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel echo = %q, %v", buf, err)
	}

	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown hung on open tunnel")
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("tunnel still open after shutdown")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("tunnel not closed by shutdown (read timed out)")
	}
}

func TestHealthBypassesAuth(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	a := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, _ := audit.Open(a)
	t.Cleanup(func() { _ = logger.Close() })
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Audit: logger,
		Engine: policy.NewEngine(policy.Policy{Tools: []policy.Rule{{Action: policy.ActionDeny}}})})
	u, _ := startProxy(t, p)

	resp, err := http.Get(u.String() + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var got map[string]string
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &got) != nil || got["status"] != "ok" || got["service"] != "nexus-cli" {
		t.Fatalf("health = %d %s", resp.StatusCode, body)
	}

	resp, err = http.Get(u.String() + "/other")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("non-health direct request without auth = %d, want 401", resp.StatusCode)
	}
	if entries, _ := audit.Tail(a, 10); len(entries) != 0 {
		t.Fatalf("health/auth failures should not be audited, got %+v", entries)
	}
}

func TestTokenReusableWithoutSingleUse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	signer, _ := jwt.NewTokenSigner()
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier()})
	u, _ := startProxy(t, p)
	tok, _ := signer.MintDualActorToken("agent", "alice", nil, time.Minute)
	client := proxyClient(withToken(u, tok))
	for i := 0; i < 5; i++ {
		resp, err := client.Get(upstream.URL + "/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d with reused token = %d, want 200", i, resp.StatusCode)
		}
	}
}

func TestSingleUseClaimRejectsReplay(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	signer, _ := jwt.NewTokenSigner()
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier()}) // Replay nil: created by New
	tok, _ := signer.Mint(jwt.MintOptions{AgentID: "agent", UserID: "alice", TTL: time.Minute, SingleUse: true})

	codes := []int{}
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		p.handleIntercept(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusUnauthorized {
		t.Fatalf("single_use token codes = %v, want [200 401]", codes)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier()})
	tok, _ := signer.MintDualActorToken("agent", "alice", nil, -time.Minute)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token = %d, want 401", rec.Code)
	}
}

func TestBasicProxyAuthViaHTTPClient(t *testing.T) {
	var got http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	signer, _ := jwt.NewTokenSigner()
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier()})
	u, _ := startProxy(t, p)
	tok, _ := signer.MintDualActorToken("agent-7", "alice", nil, time.Minute)

	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/data", nil)
	req.Header.Set("Authorization", "Bearer upstream-own-secret")
	req.Header.Set("Proxy-Connection", "keep-alive")
	resp, err := proxyClient(withToken(u, tok)).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	if v := got.Get("Proxy-Authorization"); v != "" {
		t.Fatalf("Proxy-Authorization leaked upstream: %q", v)
	}
	if v := got.Get("Proxy-Connection"); v != "" {
		t.Fatalf("Proxy-Connection forwarded upstream: %q", v)
	}
	if v := got.Get("Authorization"); v != "Bearer upstream-own-secret" {
		t.Fatalf("client's upstream Authorization altered: %q", v)
	}
	if v := got.Get("X-Nexus-Agent-ID"); v != "agent-7" {
		t.Fatalf("X-Nexus-Agent-ID = %q, want agent-7", v)
	}
}

func TestNexusTokenInAuthorizationIsStripped(t *testing.T) {
	var gotAuth, gotTok string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotTok = r.Header.Get("Authorization"), r.Header.Get("X-Nexus-Token")
	}))
	defer upstream.Close()
	signer, _ := jwt.NewTokenSigner()
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier()})
	tok, _ := signer.MintDualActorToken("agent", "alice", nil, time.Minute)

	for _, hdr := range []string{"Authorization", "X-Nexus-Token"} {
		req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
		if hdr == "Authorization" {
			req.Header.Set(hdr, "Bearer "+tok)
		} else {
			req.Header.Set(hdr, tok)
		}
		rec := httptest.NewRecorder()
		p.handleIntercept(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s token = %d, want 200", hdr, rec.Code)
		}
		if gotAuth != "" || gotTok != "" {
			t.Fatalf("%s: nexus token leaked upstream auth=%q x-nexus-token=%q", hdr, gotAuth, gotTok)
		}
	}
}

func TestAuthorizationBasicIsNotANexusToken(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier()})
	tok, _ := signer.MintDualActorToken("agent", "alice", nil, time.Minute)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.SetBasicAuth("agent", tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Authorization: Basic accepted as nexus token (%d)", rec.Code)
	}
	if got, src := extractToken(req); got != "" || src != tokenNone {
		t.Fatalf("extractToken = %q/%v, want none", got, src)
	}
}

func TestExtractTokenSources(t *testing.T) {
	basic := func(user, pass string) string {
		r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
		r.SetBasicAuth(user, pass)
		return r.Header.Get("Authorization")
	}
	cases := []struct {
		name string
		hdr  map[string]string
		tok  string
		src  tokenSource
	}{
		{"proxy-bearer", map[string]string{"Proxy-Authorization": "Bearer t1"}, "t1", tokenProxyAuthorization},
		{"proxy-basic", map[string]string{"Proxy-Authorization": basic("ignored", "t2")}, "t2", tokenProxyAuthorization},
		{"proxy-basic-colon-in-pass", map[string]string{"Proxy-Authorization": basic("u", "a:b")}, "a:b", tokenProxyAuthorization},
		{"proxy-basic-empty-pass", map[string]string{"Proxy-Authorization": basic("u", "")}, "", tokenNone},
		{"proxy-wins", map[string]string{"Proxy-Authorization": "Bearer p", "Authorization": "Bearer a"}, "p", tokenProxyAuthorization},
		{"auth-bearer", map[string]string{"Authorization": "bearer t3"}, "t3", tokenAuthorization},
		{"auth-basic", map[string]string{"Authorization": basic("u", "t4")}, "", tokenNone},
		{"x-nexus", map[string]string{"X-Nexus-Token": " t5 "}, "t5", tokenXNexus},
		{"bearer-no-space", map[string]string{"Authorization": "Bearert6"}, "", tokenNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
			for k, v := range c.hdr {
				r.Header.Set(k, v)
			}
			tok, src := extractToken(r)
			if tok != c.tok || src != c.src {
				t.Fatalf("extractToken = %q/%v, want %q/%v", tok, src, c.tok, c.src)
			}
		})
	}
}

type recordingApprover struct {
	mu       sync.Mutex
	reqs     []hitl.Request
	decision hitl.Decision
}

func (a *recordingApprover) Approve(_ context.Context, req hitl.Request) hitl.Decision {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reqs = append(a.reqs, req)
	return a.decision
}

func (a *recordingApprover) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.reqs)
}

func hitlEngine() *policy.Engine {
	return policy.NewEngine(policy.Policy{Tools: []policy.Rule{
		{Match: policy.Match{Method: "POST", Path: "/**"}, Action: policy.ActionHITL, Scope: "write"},
		{Match: policy.Match{Method: "GET", Path: "/**"}, Action: policy.ActionAllow},
	}})
}

func TestApproverReceivesRequestFields(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	uu, _ := url.Parse(upstream.URL)
	signer, _ := jwt.NewTokenSigner()
	ap := &recordingApprover{decision: hitl.Once}
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: hitlEngine(), Approver: ap})
	tok, _ := signer.MintDualActorToken("agent-1", "alice", []string{"write"}, time.Minute)

	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/repos/x?q=1", strings.NewReader("{}"))
	req.Header.Set("Proxy-Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approved once = %d, want 200", rec.Code)
	}
	if ap.calls() != 1 {
		t.Fatalf("approver calls = %d", ap.calls())
	}
	got := ap.reqs[0]
	if got.AgentID != "agent-1" || got.ActAsUser != "alice" || got.Tool != "POST" ||
		got.Target != uu.Host+"/repos/x" || got.Params != "q=1" || got.Reason != "matched rule" ||
		got.ID == "" || got.Created.IsZero() {
		t.Fatalf("approver request = %+v", got)
	}
}

func TestApprovalDecisions(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	signer, _ := jwt.NewTokenSigner()
	tok, _ := signer.MintDualActorToken("agent", "alice", []string{"write"}, time.Minute)

	cases := []struct {
		decision      hitl.Decision
		wantCode      int
		wantCalls     int // after two identical requests
		wantPersisted bool
	}{
		{hitl.Deny, http.StatusForbidden, 2, false},
		{hitl.Once, http.StatusOK, 2, false},
		{hitl.Session, http.StatusOK, 1, false},
		{hitl.Always, http.StatusOK, 1, true},
	}
	for _, c := range cases {
		t.Run(c.decision.String(), func(t *testing.T) {
			ap := &recordingApprover{decision: c.decision}
			var persisted []policy.Rule
			a := filepath.Join(t.TempDir(), "audit.jsonl")
			logger, _ := audit.Open(a)
			t.Cleanup(func() { _ = logger.Close() })
			p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: hitlEngine(), Approver: ap, Audit: logger,
				OnPersistRule: func(r policy.Rule) { persisted = append(persisted, r) }})
			for i := 0; i < 2; i++ {
				req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/x", nil)
				req.Header.Set("Authorization", "Bearer "+tok)
				rec := httptest.NewRecorder()
				p.handleIntercept(rec, req)
				if rec.Code != c.wantCode {
					t.Fatalf("request %d = %d, want %d", i, rec.Code, c.wantCode)
				}
			}
			if ap.calls() != c.wantCalls {
				t.Fatalf("approver calls = %d, want %d", ap.calls(), c.wantCalls)
			}
			if (len(persisted) == 1) != c.wantPersisted || len(persisted) > 1 {
				t.Fatalf("persisted rules = %+v", persisted)
			}
			if c.wantPersisted && (persisted[0].Action != policy.ActionAllow || persisted[0].Match.Method != "POST" || persisted[0].Scope != "write") {
				t.Fatalf("persisted rule = %+v", persisted[0])
			}
			entries, _ := audit.Tail(a, 10)
			if len(entries) != 2 {
				t.Fatalf("audit entries = %d, want 2", len(entries))
			}
			want := "allow"
			if c.decision == hitl.Deny {
				want = "deny"
			}
			if entries[0].Decision != want {
				t.Fatalf("audit decision = %q, want %q", entries[0].Decision, want)
			}
		})
	}
}

func TestApprovalTimeoutDenies(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	tok, _ := signer.MintDualActorToken("agent", "alice", []string{"write"}, time.Minute)
	a := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, _ := audit.Open(a)
	t.Cleanup(func() { _ = logger.Close() })
	var sawErr error
	ap := hitl.ApproverFunc(func(ctx context.Context, _ hitl.Request) hitl.Decision {
		<-ctx.Done()
		sawErr = ctx.Err()
		return hitl.Once // misbehaving approver: must still fail closed
	})
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: hitlEngine(), Approver: ap, Audit: logger,
		ApprovalTimeout: 50 * time.Millisecond})

	req, _ := http.NewRequest(http.MethodPost, "http://example.invalid/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("timed-out approval = %d, want 403", rec.Code)
	}
	if !errors.Is(sawErr, context.DeadlineExceeded) {
		t.Fatalf("approver ctx err = %v, want deadline exceeded", sawErr)
	}
	entries, _ := audit.Tail(a, 10)
	if len(entries) != 1 || entries[0].Decision != "deny" || !strings.Contains(entries[0].Reason, "timed out") {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestClientDisconnectCancelsApproval(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	tok, _ := signer.MintDualActorToken("agent", "alice", []string{"write"}, time.Minute)
	started := make(chan struct{})
	cancelled := make(chan error, 1)
	ap := hitl.ApproverFunc(func(ctx context.Context, _ hitl.Request) hitl.Decision {
		close(started)
		<-ctx.Done()
		cancelled <- ctx.Err()
		return hitl.Deny
	})
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: hitlEngine(), Approver: ap, ApprovalTimeout: time.Minute})
	u, _ := startProxy(t, p)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.invalid/x", nil)
	errCh := make(chan error, 1)
	go func() {
		resp, err := proxyClient(withToken(u, tok)).Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("approver never called")
	}
	cancel()
	select {
	case err := <-cancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("approver ctx err = %v, want canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client disconnect did not cancel approver ctx")
	}
	<-errCh
}

func TestShutdownCancelsPendingApproval(t *testing.T) {
	started := make(chan struct{})
	ap := hitl.ApproverFunc(func(ctx context.Context, _ hitl.Request) hitl.Decision {
		close(started)
		<-ctx.Done()
		return hitl.Deny
	})
	engine := policy.NewEngine(policy.Policy{Tools: []policy.Rule{{Match: policy.Match{Method: "POST"}, Action: policy.ActionHITL}}})
	p := New(Config{Engine: engine, Approver: ap, ApprovalTimeout: time.Minute})
	u, stop := startProxy(t, p)
	codeCh := make(chan int, 1)
	go func() {
		resp, err := proxyClient(u).Post("http://example.invalid/x", "text/plain", nil)
		if err != nil {
			codeCh <- 0
			return
		}
		resp.Body.Close()
		codeCh <- resp.StatusCode
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("approver never called")
	}
	start := time.Now()
	stop()
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("shutdown waited %v for a pending approval", d)
	}
	if code := <-codeCh; code != http.StatusForbidden && code != 0 {
		t.Fatalf("pending approval on shutdown = %d, want 403", code)
	}
}
