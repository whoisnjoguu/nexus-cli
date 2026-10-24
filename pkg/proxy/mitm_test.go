package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/ca"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// lockedBuffer is a goroutine-safe io.Writer for capturing proxy stderr.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// seenRequest is what the TLS upstream observed for one request.
type seenRequest struct {
	Method string
	Host   string
	Path   string
	Header http.Header
	Body   string
}

// tlsUpstream is an httptest TLS server (certificate valid for example.com and 127.0.0.1) that
// records every request it receives and supports a minimal Upgrade echo on /ws.
type tlsUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []seenRequest
}

func newTLSUpstream(t *testing.T) *tlsUpstream {
	t.Helper()
	u := &tlsUpstream{}
	u.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.seen = append(u.seen, seenRequest{Method: r.Method, Host: r.Host, Path: r.URL.Path, Header: r.Header.Clone(), Body: string(body)})
		u.mu.Unlock()
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			conn, brw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_, _ = io.Copy(conn, brw)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream:"+r.Method+" "+r.URL.Path+" "+string(body))
	}))
	u.Config.ErrorLog = log.New(io.Discard, "", 0) // passthrough tests provoke expected handshake errors
	u.StartTLS()
	t.Cleanup(u.Close)
	return u
}

func (u *tlsUpstream) requests() []seenRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seenRequest(nil), u.seen...)
}

// transport dials every upstream host to the test server and trusts only its certificate.
func (u *tlsUpstream) transport() http.RoundTripper {
	addr := u.Listener.Addr().String()
	tr := u.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return tr
}

func (u *tlsUpstream) roots() *x509.CertPool {
	return u.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

type mitmHarness struct {
	t         *testing.T
	up        *tlsUpstream
	ca        *ca.CA
	signer    *jwt.TokenSigner
	p         *ProxyServer
	proxyURL  *url.URL
	stop      func()
	auditPath string
	stderr    *lockedBuffer
}

func newTestCA(t *testing.T) *ca.CA {
	t.Helper()
	c, err := ca.LoadOrCreate(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// newMITM starts an authenticated MITM proxy in front of a TLS upstream. mod may adjust Config.
func newMITM(t *testing.T, pol policy.Policy, mod func(*Config)) *mitmHarness {
	t.Helper()
	h := &mitmHarness{t: t, up: newTLSUpstream(t), ca: newTestCA(t), stderr: &lockedBuffer{}}
	var err error
	if h.signer, err = jwt.NewTokenSigner(); err != nil {
		t.Fatal(err)
	}
	h.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := audit.Open(h.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		RequireAuth:       true,
		Verifier:          h.signer.Verifier(),
		Engine:            policy.NewEngine(pol),
		Audit:             logger,
		MITM:              h.ca,
		UpstreamTransport: h.up.transport(),
		Approver:          hitl.DenyAll,
	}
	if mod != nil {
		mod(&cfg)
	}
	h.p = New(cfg)
	h.p.stderr = h.stderr
	h.proxyURL, h.stop = startProxy(t, h.p)
	return h
}

func (h *mitmHarness) token(opts jwt.MintOptions) string {
	h.t.Helper()
	if opts.AgentID == "" {
		opts.AgentID = "agent"
	}
	if opts.UserID == "" {
		opts.UserID = "alice"
	}
	if opts.TTL == 0 {
		opts.TTL = time.Minute
	}
	tok, err := h.signer.Mint(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

// client returns an HTTP client that proxies through nexus with tok and trusts roots.
func (h *mitmHarness) client(tok string, roots *x509.CertPool) *http.Client {
	u := *h.proxyURL
	u.User = url.UserPassword("nexus", tok)
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&u), TLSClientConfig: &tls.Config{RootCAs: roots}},
		Timeout:   10 * time.Second,
	}
}

func (h *mitmHarness) defaultClient() *http.Client {
	return h.client(h.token(jwt.MintOptions{Scopes: []string{"read"}}), h.ca.Pool())
}

func (h *mitmHarness) auditEntries() []audit.Entry {
	h.t.Helper()
	entries, err := audit.Tail(h.auditPath, 100)
	if err != nil {
		h.t.Fatal(err)
	}
	return entries
}

func do(t *testing.T, c *http.Client, method, rawURL string, body io.Reader, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func get(path string) policy.Rule {
	return policy.Rule{Match: policy.Match{Method: "GET", Host: "example.com", Path: path}, Action: policy.ActionAllow}
}

func TestMITMAllowsPathRuleAndForwardsIdentity(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{get("/zen")}}, nil)
	code, body := do(t, h.defaultClient(), "GET", "https://example.com/zen", nil, map[string]string{
		"Authorization":    "Bearer upstream-api-key",
		"X-Nexus-Agent-ID": "spoofed",
	})
	if code != http.StatusOK || body != "upstream:GET /zen " {
		t.Fatalf("GET /zen = %d %q", code, body)
	}
	reqs := h.up.requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream saw %d requests", len(reqs))
	}
	got := reqs[0]
	if got.Header.Get("X-Nexus-Agent-ID") != "agent" || got.Header.Get("X-Nexus-Act-As") != "alice" {
		t.Fatalf("upstream identity headers = %v", got.Header)
	}
	if got.Header.Get("Proxy-Authorization") != "" {
		t.Fatal("Proxy-Authorization leaked upstream")
	}
	if got.Header.Get("Authorization") != "Bearer upstream-api-key" {
		t.Fatalf("client's upstream Authorization not passed through: %q", got.Header.Get("Authorization"))
	}
	if got.Host != "example.com" {
		t.Fatalf("upstream Host = %q", got.Host)
	}
	entries := h.auditEntries()
	if len(entries) != 1 || entries[0].Decision != "allow" || entries[0].Tool != "GET" ||
		entries[0].Target != "example.com/zen" || entries[0].Agent != "agent" {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestMITMPerRequestPolicyOnSameHost(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{
		get("/allowed"),
		{Match: policy.Match{Method: "GET", Host: "example.com", Path: "/secret"}, Action: policy.ActionDeny},
	}}, nil)
	c := h.defaultClient()
	if code, _ := do(t, c, "GET", "https://example.com/allowed", nil, nil); code != http.StatusOK {
		t.Fatalf("/allowed = %d", code)
	}
	if code, _ := do(t, c, "GET", "https://example.com/secret", nil, nil); code != http.StatusForbidden {
		t.Fatalf("/secret = %d, want 403", code)
	}
	// Default action (deny) for an unmatched path too.
	if code, _ := do(t, c, "DELETE", "https://example.com/allowed", nil, nil); code != http.StatusForbidden {
		t.Fatalf("DELETE /allowed = %d, want 403", code)
	}
	for _, r := range h.up.requests() {
		if r.Path != "/allowed" || r.Method != "GET" {
			t.Fatalf("denied request reached upstream: %+v", r)
		}
	}
	var decisions []string
	for _, e := range h.auditEntries() {
		decisions = append(decisions, e.Decision+" "+e.Tool+" "+e.Target)
	}
	want := []string{"allow GET example.com/allowed", "deny GET example.com/secret", "deny DELETE example.com/allowed"}
	if strings.Join(decisions, "|") != strings.Join(want, "|") {
		t.Fatalf("audit = %v, want %v", decisions, want)
	}
}

func TestMITMInjectsCredential(t *testing.T) {
	res := &fakeResolver{token: "broker-secret"}
	rule := get("/user")
	rule.Inject = true
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{rule}}, func(c *Config) { c.Credentials = res })
	tok := h.token(jwt.MintOptions{ConnID: "conn-1", Gateway: "http://gw.local"})
	code, _ := do(t, h.client(tok, h.ca.Pool()), "GET", "https://example.com/user", nil,
		map[string]string{"Authorization": "Bearer agent-supplied"})
	if code != http.StatusOK {
		t.Fatalf("inject = %d", code)
	}
	reqs := h.up.requests()
	if len(reqs) != 1 || reqs[0].Header.Get("Authorization") != "Bearer broker-secret" {
		t.Fatalf("upstream Authorization = %+v", reqs)
	}
	if res.gotID != "conn-1" || res.gotGW != "http://gw.local" {
		t.Fatalf("resolver got gw=%q id=%q", res.gotGW, res.gotID)
	}

	// Without a broker connection on the token the injection fails closed.
	code, _ = do(t, h.defaultClient(), "GET", "https://example.com/user", nil, nil)
	if code != http.StatusForbidden {
		t.Fatalf("inject without connection = %d, want 403", code)
	}
}

func TestMITMTaintEscalation(t *testing.T) {
	ap := &recordingApprover{decision: hitl.Deny}
	h := newMITM(t, policy.Policy{
		EscalateWhenTainted: true,
		Egress:              policy.Egress{Allow: []string{"example.com"}},
		Tools: []policy.Rule{
			{Match: policy.Match{Method: "GET", Host: "example.com", Path: "/secrets/**"}, Action: policy.ActionAllow, Taints: []string{"secret"}},
			{Match: policy.Match{Method: "GET", Path: "/**"}, Action: policy.ActionAllow},
		},
	}, func(c *Config) { c.Approver = ap })
	c := h.client(h.token(jwt.MintOptions{}), h.ca.Pool())

	// 127.0.0.1 is a valid name on the upstream certificate but not in the egress allowlist.
	if code, _ := do(t, c, "GET", "https://127.0.0.1/ping", nil, nil); code != http.StatusOK {
		t.Fatalf("pre-taint egress = %d", code)
	}
	if code, _ := do(t, c, "GET", "https://example.com/secrets/db", nil, nil); code != http.StatusOK {
		t.Fatalf("secret read = %d", code)
	}
	if ap.calls() != 0 {
		t.Fatalf("approver called before taint: %d", ap.calls())
	}
	if code, _ := do(t, c, "GET", "https://127.0.0.1/ping", nil, nil); code != http.StatusForbidden {
		t.Fatalf("tainted egress = %d, want 403", code)
	}
	if ap.calls() != 1 {
		t.Fatalf("approver calls = %d, want 1", ap.calls())
	}
	if r := ap.reqs[0]; r.Target != "127.0.0.1/ping" || !strings.Contains(r.Reason, "tainted") {
		t.Fatalf("approval request = %+v", r)
	}
}

func TestMITMOneTimeAcrossRequestsInTunnel(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{
		{Match: policy.Match{Method: "POST", Host: "example.com", Path: "/deploy"}, Action: policy.ActionAllow, OneTime: true},
	}}, nil)
	c := h.defaultClient()
	var conns atomic.Int32
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		if !i.Reused {
			conns.Add(1)
		}
	}}
	codes := make([]int, 0, 2)
	for i := 0; i < 2; i++ {
		// A body without a known length is sent chunked.
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace),
			"POST", "https://example.com/deploy", io.NopCloser(strings.NewReader("payload")))
		req.ContentLength = -1
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusForbidden {
		t.Fatalf("one_time codes = %v, want [200 403]", codes)
	}
	if conns.Load() != 1 {
		t.Fatalf("requests used %d tunnels, want 1", conns.Load())
	}
	reqs := h.up.requests()
	if len(reqs) != 1 || reqs[0].Body != "payload" {
		t.Fatalf("upstream saw %+v", reqs)
	}
}

func TestMITMRejectsHostHeaderMismatch(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{
		{Match: policy.Match{Method: "GET", Path: "/**"}, Action: policy.ActionAllow},
	}}, nil)
	req, _ := http.NewRequest("GET", "https://example.com/x", nil)
	req.Host = "evil.example"
	resp, err := h.defaultClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("fronted request = %d, want 403", resp.StatusCode)
	}
	if n := len(h.up.requests()); n != 0 {
		t.Fatalf("fronted request reached upstream (%d)", n)
	}
	entries := h.auditEntries()
	if len(entries) != 1 || entries[0].Decision != "deny" || !strings.Contains(entries[0].Reason, "domain fronting") {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestMITMPassthroughHostIsRawTunnel(t *testing.T) {
	h := newMITM(t, policy.Policy{Egress: policy.Egress{Allow: []string{"127.0.0.1"}}},
		func(c *Config) { c.Passthrough = []string{"127.0.0.1"} })
	target := h.up.URL + "/raw"

	// Through a raw tunnel the client sees the real upstream certificate, not a nexus leaf.
	if _, err := h.defaultClient().Get(target); err == nil {
		t.Fatal("client trusting only the nexus CA should fail on a passthrough host")
	}
	code, body := do(t, h.client(h.token(jwt.MintOptions{}), h.up.roots()), "GET", target, nil, nil)
	if code != http.StatusOK || body != "upstream:GET /raw " {
		t.Fatalf("passthrough = %d %q", code, body)
	}
	reqs := h.up.requests()
	if len(reqs) != 1 || reqs[0].Header.Get("X-Nexus-Agent-ID") != "" {
		t.Fatalf("passthrough request was intercepted: %+v", reqs)
	}
	for _, e := range h.auditEntries() {
		if e.Tool != "CONNECT" || e.Target != h.up.Listener.Addr().String() || e.Decision != "allow" {
			t.Fatalf("passthrough audit should be host-level CONNECT only, got %+v", e)
		}
	}
}

func TestMITMClientRejectsCA(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{get("/zen")}}, nil)
	c := h.client(h.token(jwt.MintOptions{}), x509.NewCertPool())
	for i := 0; i < 2; i++ {
		if _, err := c.Get("https://example.com/zen"); err == nil {
			t.Fatal("client without the nexus CA should fail the handshake")
		}
		c.CloseIdleConnections()
	}
	want := "client rejected nexus CA for example.com; run 'nexus-cli ca install' or use 'nexus-cli run'"
	deadline := time.Now().Add(5 * time.Second)
	var entries []audit.Entry
	for time.Now().Before(deadline) {
		if entries = h.auditEntries(); len(entries) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 2 {
		t.Fatalf("audit = %+v, want 2 handshake denials", entries)
	}
	for _, e := range entries {
		if e.Decision != "deny" || e.Tool != "CONNECT" || e.Target != "example.com" || !strings.HasPrefix(e.Reason, want) {
			t.Fatalf("audit entry = %+v", e)
		}
	}
	if got := h.stderr.String(); strings.Count(got, want) != 1 {
		t.Fatalf("stderr hint should appear exactly once (rate-limited), got %q", got)
	}
	if n := len(h.up.requests()); n != 0 {
		t.Fatalf("upstream reached despite failed handshake (%d)", n)
	}
}

func TestMITMKeepAliveAuditsEachRequest(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{get("/a"), get("/b"), get("/c")}}, nil)
	c := h.defaultClient()
	var newConns atomic.Int32
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		if !i.Reused {
			newConns.Add(1)
		}
	}}
	for _, p := range []string{"/a", "/b", "/c"} {
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), "GET", "https://example.com"+p, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s = %d", p, resp.StatusCode)
		}
	}
	if newConns.Load() != 1 {
		t.Fatalf("keep-alive: %d tunnels for 3 requests, want 1", newConns.Load())
	}
	var targets []string
	for _, e := range h.auditEntries() {
		targets = append(targets, e.Target)
	}
	if strings.Join(targets, ",") != "example.com/a,example.com/b,example.com/c" {
		t.Fatalf("audit targets = %v", targets)
	}
}

func TestMITMUpgradePassthrough(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{get("/ws")}}, nil)
	req, _ := http.NewRequest("GET", "https://example.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	c := h.defaultClient()
	c.Timeout = 0 // a client timeout wraps the body, hiding the upgraded io.ReadWriteCloser
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", resp.StatusCode)
	}
	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("101 body is %T, not a ReadWriteCloser", resp.Body)
	}
	if _, err := io.WriteString(rwc, "ping"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(rwc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo over upgraded stream = %q, %v", buf, err)
	}
	if e := h.auditEntries(); len(e) != 1 || e[0].Target != "example.com/ws" || e[0].Decision != "allow" {
		t.Fatalf("audit = %+v", e)
	}
}

// rawConnect opens a CONNECT to target with an optional token and returns the conn and reader.
func rawConnect(t *testing.T, proxyAddr, target, tok string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	auth := ""
	if tok != "" {
		auth = "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("nexus:"+tok)) + "\r\n"
	}
	_, _ = io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n"+auth+"\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return conn, br, resp
}

func TestMITMGracefulShutdownClosesTunnels(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{get("/zen")}}, nil)
	conn, _, resp := rawConnect(t, h.proxyURL.Host, "example.com:443", h.token(jwt.MintOptions{}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %d", resp.StatusCode)
	}
	tc := tls.Client(conn, &tls.Config{RootCAs: h.ca.Pool(), ServerName: "example.com"})
	_, _ = io.WriteString(tc, "GET /zen HTTP/1.1\r\nHost: example.com\r\n\r\n")
	tbr := bufio.NewReader(tc)
	inner, err := http.ReadResponse(tbr, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, inner.Body)
	inner.Body.Close()
	if inner.StatusCode != http.StatusOK {
		t.Fatalf("inner GET = %d", inner.StatusCode)
	}

	done := make(chan struct{})
	go func() { h.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown hung on an open MITM tunnel")
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := tbr.ReadByte(); err == nil {
		t.Fatal("MITM tunnel still open after shutdown")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("MITM tunnel not closed by shutdown (read timed out)")
	}
}

func TestMITMUnauthenticatedConnectRejectedBeforeTLS(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{get("/zen")}}, nil)
	for _, tok := range []string{"", "not-a-jwt"} {
		_, _, resp := rawConnect(t, h.proxyURL.Host, "example.com:443", tok)
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("CONNECT with token %q = %d, want 407", tok, resp.StatusCode)
		}
		if !strings.HasPrefix(resp.Header.Get("Proxy-Authenticate"), "Basic") {
			t.Fatalf("missing Proxy-Authenticate challenge: %v", resp.Header)
		}
	}
	if e := h.auditEntries(); len(e) != 0 {
		t.Fatalf("auth failures should not be audited: %+v", e)
	}
}

func TestMITMSingleUseCheckedOnceAtConnect(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{get("/a"), get("/b")}}, nil)
	tok := h.token(jwt.MintOptions{SingleUse: true})
	c := h.client(tok, h.ca.Pool())
	for _, p := range []string{"/a", "/b"} {
		if code, _ := do(t, c, "GET", "https://example.com"+p, nil, nil); code != http.StatusOK {
			t.Fatalf("%s in the same tunnel = %d", p, code)
		}
	}
	// A second tunnel replays the consumed jti.
	_, _, resp := rawConnect(t, h.proxyURL.Host, "example.com:443", tok)
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("replayed single-use CONNECT = %d, want 407", resp.StatusCode)
	}
}

func TestMITMNonDefaultPortKeptUpstream(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{
		{Match: policy.Match{Method: "GET", Host: "example.com", Path: "/p"}, Action: policy.ActionAllow},
	}}, nil)
	code, _ := do(t, h.defaultClient(), "GET", "https://example.com:8443/p", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GET :8443 = %d", code)
	}
	if e := h.auditEntries(); len(e) != 1 || e[0].Target != "example.com:8443/p" {
		t.Fatalf("audit = %+v", e)
	}
}

func TestSplitConnectHost(t *testing.T) {
	cases := map[string][2]string{
		"Example.COM:443":  {"example.com", "example.com"},
		"example.com:8443": {"example.com", "example.com:8443"},
		"example.com":      {"example.com", "example.com"},
		"[::1]:443":        {"::1", "[::1]"},
		"[::1]:8443":       {"::1", "[::1]:8443"},
		"127.0.0.1:443":    {"127.0.0.1", "127.0.0.1"},
	}
	for in, want := range cases {
		h, u := splitConnectHost(in)
		if h != want[0] || u != want[1] {
			t.Errorf("splitConnectHost(%q) = %q,%q want %q,%q", in, h, u, want[0], want[1])
		}
	}
}

func TestStrictEscalatesPolicyAllows(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	signer, _ := jwt.NewTokenSigner()
	ap := &recordingApprover{decision: hitl.Session}
	engine := policy.NewEngine(policy.Policy{Tools: []policy.Rule{
		{Match: policy.Match{Method: "GET", Path: "/**"}, Action: policy.ActionAllow},
	}})
	p := New(Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: engine, Approver: ap, Strict: true})
	tok, _ := signer.MintDualActorToken("agent", "alice", nil, time.Minute)
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
		req.Header.Set("Proxy-Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		p.handleIntercept(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
	if ap.calls() != 1 || !strings.HasPrefix(ap.reqs[0].Reason, "strict mode") {
		t.Fatalf("strict: approver calls = %d (%+v), want 1 (session approval sticks)", ap.calls(), ap.reqs)
	}
}

// The default upstream transport must speak HTTP/1.1 even to HTTP/2-capable servers (a clone of
// http.DefaultTransport otherwise still offers "h2" via ALPN and the upstream hangs up).
func TestDefaultTransportHTTP1ToH2Upstream(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	tr, ok := New(Config{}).transport.(*http.Transport)
	if !ok {
		t.Fatal("default transport is not *http.Transport")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default transport must verify upstream certificates")
	}
	tr.TLSClientConfig.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatalf("h2-capable upstream: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "HTTP/1.1" {
		t.Fatalf("upstream saw %q, want HTTP/1.1", body)
	}
}

// Clients like curl finish the TLS handshake and only then verify the certificate, aborting with a
// reset before sending any request. That must be reported like a handshake rejection, while a
// client that simply closes an idle tunnel must not be.
func TestMITMPostHandshakeRejection(t *testing.T) {
	h := newMITM(t, policy.Policy{Tools: []policy.Rule{get("/zen")}}, nil)
	tok := h.token(jwt.MintOptions{})
	handshake := func() (*net.TCPConn, *tls.Conn) {
		conn, br, resp := rawConnect(t, h.proxyURL.Host, "example.com:443", tok)
		if resp.StatusCode != http.StatusOK || br.Buffered() != 0 {
			t.Fatalf("CONNECT = %d", resp.StatusCode)
		}
		tc := tls.Client(conn, &tls.Config{ServerName: "example.com", RootCAs: h.ca.Pool()})
		if err := tc.Handshake(); err != nil {
			t.Fatal(err)
		}
		return conn.(*net.TCPConn), tc
	}

	_, clean := handshake()
	_ = clean.Close()
	time.Sleep(200 * time.Millisecond)
	if entries := h.auditEntries(); len(entries) != 0 {
		t.Fatalf("clean close audited as rejection: %+v", entries)
	}

	raw, _ := handshake()
	_ = raw.SetLinger(0)
	_ = raw.Close() // RST without a request, as curl does after failing verification
	want := "client rejected nexus CA for example.com"
	deadline := time.Now().Add(5 * time.Second)
	var entries []audit.Entry
	for time.Now().Before(deadline) {
		if entries = h.auditEntries(); len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(entries) != 1 || entries[0].Decision != "deny" || !strings.HasPrefix(entries[0].Reason, want) {
		t.Fatalf("audit = %+v, want one rejection", entries)
	}
	if !strings.Contains(h.stderr.String(), want) {
		t.Fatalf("missing stderr hint: %q", h.stderr.String())
	}
}
