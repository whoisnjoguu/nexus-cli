package control

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

// browserReq issues a request without the bearer token, as a browser would.
func browserReq(t *testing.T, s *Server, method, path, body string, mod func(*http.Request)) *http.Response {
	t.Helper()
	return rawReq(t, s, method, path, body, func(r *http.Request) {
		r.Header.Del("Authorization")
		if method != http.MethodGet && method != http.MethodHead {
			r.Header.Set("Origin", "http://"+s.Info().Addr)
		}
		if mod != nil {
			mod(r)
		}
	})
}

func mintCode(t *testing.T, s *Server) LoginCode {
	t.Helper()
	resp := rawReq(t, s, "POST", "/v1/ui/login-code", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login-code: %d", resp.StatusCode)
	}
	var lc LoginCode
	if err := json.NewDecoder(resp.Body).Decode(&lc); err != nil {
		t.Fatal(err)
	}
	return lc
}

type uiCreds struct {
	cookie *http.Cookie
	csrf   string
}

func (c uiCreds) apply(r *http.Request) {
	r.AddCookie(c.cookie)
	r.Header.Set(CSRFHeader, c.csrf)
}

func login(t *testing.T, s *Server) uiCreds {
	t.Helper()
	lc := mintCode(t, s)
	resp := browserReq(t, s, "POST", "/v1/ui/session", `{"code":"`+lc.Code+`"}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session: %d", resp.StatusCode)
	}
	var us UISession
	if err := json.NewDecoder(resp.Body).Decode(&us); err != nil || us.CSRF == "" {
		t.Fatalf("session body: %+v %v", us, err)
	}
	cs := resp.Cookies()
	if len(cs) != 1 {
		t.Fatalf("cookies: %v", cs)
	}
	return uiCreds{cookie: cs[0], csrf: us.CSRF}
}

func TestLoginCodeRequiresBearer(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	lc := mintCode(t, s)
	if len(lc.Code) < 32 || lc.URL != "http://"+s.Info().Addr+"/ui#login="+lc.Code || time.Until(lc.Expires) > LoginCodeTTL+time.Second {
		t.Fatalf("login code: %+v", lc)
	}
	if resp := browserReq(t, s, "POST", "/v1/ui/login-code", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous mint: %d", resp.StatusCode)
	}
	// A cookie session cannot mint further codes.
	c := login(t, s)
	if resp := browserReq(t, s, "POST", "/v1/ui/login-code", "", c.apply); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie mint: %d", resp.StatusCode)
	}
}

func TestLoginCodeSingleUseAndExpiry(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	lc := mintCode(t, s)
	body := `{"code":"` + lc.Code + `"}`
	if resp := browserReq(t, s, "POST", "/v1/ui/session", body, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("first use: %d", resp.StatusCode)
	}
	if resp := browserReq(t, s, "POST", "/v1/ui/session", body, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reuse: %d", resp.StatusCode)
	}
	if resp := browserReq(t, s, "POST", "/v1/ui/session", `{"code":"nope"}`, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bogus code: %d", resp.StatusCode)
	}

	// Expiry, using the auth store's clock.
	var mu sync.Mutex
	now := time.Now()
	s.ui.mu.Lock()
	s.ui.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s.ui.mu.Unlock()
	lc = mintCode(t, s)
	mu.Lock()
	now = now.Add(LoginCodeTTL + time.Second)
	mu.Unlock()
	if resp := browserReq(t, s, "POST", "/v1/ui/session", `{"code":"`+lc.Code+`"}`, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired code: %d", resp.StatusCode)
	}

	// Sessions expire too.
	c := login(t, s)
	if resp := browserReq(t, s, "GET", "/v1/ui/state", "", c.apply); resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh session: %d", resp.StatusCode)
	}
	mu.Lock()
	now = now.Add(SessionTTL + time.Second)
	mu.Unlock()
	if resp := browserReq(t, s, "GET", "/v1/ui/state", "", c.apply); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired session: %d", resp.StatusCode)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	lc := mintCode(t, s)
	resp := browserReq(t, s, "POST", "/v1/ui/session", `{"code":"`+lc.Code+`"}`, nil)
	sc := resp.Header.Get("Set-Cookie")
	_, port, _ := net.SplitHostPort(s.Info().Addr)
	for _, want := range []string{SessionCookiePrefix + port + "=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=43200"} {
		if !strings.Contains(sc, want) {
			t.Fatalf("Set-Cookie %q lacks %q", sc, want)
		}
	}
	if strings.Contains(sc, "Secure") || strings.Contains(sc, "Domain") {
		t.Fatalf("unexpected attribute: %q", sc)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("session response must not be cached")
	}
}

func TestSessionExchangeChecks(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	lc := mintCode(t, s)
	body := `{"code":"` + lc.Code + `"}`
	// No Origin (state-changing), foreign Origin, wrong content type: all rejected without
	// consuming the code.
	if resp := browserReq(t, s, "POST", "/v1/ui/session", body, func(r *http.Request) { r.Header.Del("Origin") }); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no origin: %d", resp.StatusCode)
	}
	if resp := browserReq(t, s, "POST", "/v1/ui/session", body, func(r *http.Request) { r.Header.Set("Origin", "http://evil.com") }); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("evil origin: %d", resp.StatusCode)
	}
	if resp := browserReq(t, s, "POST", "/v1/ui/session", body, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain: %d", resp.StatusCode)
	}
	if resp := browserReq(t, s, "POST", "/v1/ui/session", body, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("valid: %d", resp.StatusCode)
	}
}

func TestCookieHostOriginCSRF(t *testing.T) {
	s, b := startServer(t, time.Minute)
	c := login(t, s)
	_, port, _ := net.SplitHostPort(s.Info().Addr)

	// localhost:<port> is accepted as an alternative name for the UI.
	if resp := browserReq(t, s, "GET", "/v1/ui/state", "", func(r *http.Request) { c.apply(r); r.Host = "localhost:" + port }); resp.StatusCode != http.StatusOK {
		t.Fatalf("localhost host: %d", resp.StatusCode)
	}
	for _, host := range []string{"evil.com", "evil.com:" + port, "127.0.0.1", "localhost:1"} {
		resp := browserReq(t, s, "GET", "/v1/ui/state", "", func(r *http.Request) { c.apply(r); r.Host = host })
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("host %q: %d", host, resp.StatusCode)
		}
		// Even the public page is Host-checked.
		if resp := browserReq(t, s, "GET", "/ui", "", func(r *http.Request) { r.Host = host }); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("ui host %q: %d", host, resp.StatusCode)
		}
	}

	ch := enqueue(t, b, hitl.Request{ID: "r1", Tool: "POST"})
	decide := `{"decision":"once"}`
	cases := []struct {
		name string
		mod  func(*http.Request)
		want int
	}{
		{"evil origin", func(r *http.Request) { c.apply(r); r.Header.Set("Origin", "http://evil.com:"+port) }, http.StatusForbidden},
		{"null origin", func(r *http.Request) { c.apply(r); r.Header.Set("Origin", "null") }, http.StatusForbidden},
		{"https origin", func(r *http.Request) { c.apply(r); r.Header.Set("Origin", "https://127.0.0.1:"+port) }, http.StatusForbidden},
		{"no origin", func(r *http.Request) { c.apply(r); r.Header.Del("Origin") }, http.StatusForbidden},
		{"missing csrf", func(r *http.Request) { c.apply(r); r.Header.Del(CSRFHeader) }, http.StatusForbidden},
		{"wrong csrf", func(r *http.Request) { c.apply(r); r.Header.Set(CSRFHeader, c.csrf+"x") }, http.StatusForbidden},
		{"csrf in query only", func(r *http.Request) {
			c.apply(r)
			r.Header.Del(CSRFHeader)
			r.URL.RawQuery = "csrf=" + c.csrf
		}, http.StatusForbidden},
		{"no cookie", func(r *http.Request) { r.Header.Set(CSRFHeader, c.csrf) }, http.StatusUnauthorized},
		{"bogus cookie", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: c.cookie.Name, Value: "deadbeef"})
			r.Header.Set(CSRFHeader, c.csrf)
		}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		if resp := browserReq(t, s, "POST", "/v1/approvals/r1", decide, tc.mod); resp.StatusCode != tc.want {
			t.Fatalf("%s: got %d want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
	// Reads need CSRF too: the cookie alone is never enough.
	if resp := browserReq(t, s, "GET", "/v1/approvals", "", func(r *http.Request) { r.AddCookie(c.cookie) }); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie-only read: %d", resp.StatusCode)
	}
	if len(b.Pending()) != 1 {
		t.Fatal("request must still be pending")
	}

	// localhost origin works for the decision, which resolves the broker request.
	resp := browserReq(t, s, "POST", "/v1/approvals/r1", decide, func(r *http.Request) {
		c.apply(r)
		r.Host = "localhost:" + port
		r.Header.Set("Origin", "http://localhost:"+port)
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("cookie decide: %d", resp.StatusCode)
	}
	if d := <-ch; d != hitl.Once {
		t.Fatalf("decision %v", d)
	}
	if rec := b.Recent(); len(rec) != 1 || rec[0].By != "web" || rec[0].Decision != "once" {
		t.Fatalf("recent: %+v", rec)
	}
}

func TestBearerUnchangedAlongsideUI(t *testing.T) {
	s, b := startServer(t, time.Minute)
	c := login(t, s)
	ch := enqueue(t, b, hitl.Request{ID: "r2"})
	// Bearer + cookie: the bearer path applies and still rejects any Origin.
	if resp := rawReq(t, s, "GET", "/v1/approvals", "", func(r *http.Request) {
		c.apply(r)
		r.Header.Set("Origin", "http://"+s.Info().Addr)
	}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bearer with origin: %d", resp.StatusCode)
	}
	cl := NewClient(s.Info())
	defer cl.Close()
	if err := cl.Decide(context.Background(), "r2", hitl.Deny); err != nil {
		t.Fatal(err)
	}
	if d := <-ch; d != hitl.Deny {
		t.Fatalf("decision %v", d)
	}
	if rec := b.Recent(); rec[0].By != "cli" {
		t.Fatalf("by: %+v", rec[0])
	}
}

func TestUIAssetsAndHeaders(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	for path, want := range map[string]string{
		"/ui":         "text/html",
		"/ui/app.js":  "text/javascript",
		"/ui/app.css": "text/css",
	} {
		resp := browserReq(t, s, "GET", path, "", nil)
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), want) {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(resp.Body)
		if len(body) == 0 {
			t.Fatalf("%s: empty", path)
		}
		h := resp.Header
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" ||
			!strings.HasPrefix(h.Get("Content-Security-Policy"), "default-src 'self'; script-src 'self'; style-src 'self'") {
			t.Fatalf("%s headers: %v", path, h)
		}
		if path == "/ui" && (strings.Contains(string(body), "<script>") || strings.Contains(string(body), "<style") || strings.Contains(string(body), "http")) {
			t.Fatal("index.html must not contain inline scripts/styles or external URLs")
		}
	}
	// Security headers also apply to API errors.
	if resp := browserReq(t, s, "GET", "/v1/ui/state", "", nil); resp.Header.Get("Content-Security-Policy") == "" || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("api error: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestUIState(t *testing.T) {
	s, b := startServer(t, 30*time.Second)
	c := login(t, s)
	enqueue(t, b, hitl.Request{ID: "r3", AgentID: "agent-a", Tool: "POST", Target: "http://x"})
	resp := browserReq(t, s, "GET", "/v1/ui/state", "", c.apply)
	var st UIState
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.TimeoutMS != 30000 || len(st.Pending) != 1 || st.Pending[0].AgentID != "agent-a" || st.Endpoint.Token != "" || st.Endpoint.Kind != "dev" {
		t.Fatalf("state: %+v", st)
	}
	// Long-poll returns at once when the version moved on.
	start := time.Now()
	resp = browserReq(t, s, "GET", "/v1/ui/state?wait=5s&since=0", "", c.apply)
	if resp.StatusCode != http.StatusOK || time.Since(start) > 2*time.Second {
		t.Fatalf("long-poll: %d after %v", resp.StatusCode, time.Since(start))
	}
}

type sseEvent struct {
	name string
	data string
}

func readSSE(t *testing.T, resp *http.Response) <-chan sseEvent {
	t.Helper()
	out := make(chan sseEvent, 16)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(resp.Body)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			case line == "" && ev.name != "":
				out <- ev
				ev = sseEvent{}
			}
		}
	}()
	return out
}

func wantSSE(t *testing.T, ch <-chan sseEvent, name string) hitl.Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatalf("stream closed waiting for %s", name)
		}
		if ev.name != name {
			t.Fatalf("got event %q want %q (%s)", ev.name, name, ev.data)
		}
		var e hitl.Event
		_ = json.Unmarshal([]byte(ev.data), &e)
		return e
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s event", name)
	}
	return hitl.Event{}
}

func TestEventsSSE(t *testing.T) {
	for _, mode := range []string{"cookie", "bearer"} {
		t.Run(mode, func(t *testing.T) {
			s, b := startServer(t, time.Minute)
			var resp *http.Response
			if mode == "cookie" {
				c := login(t, s)
				resp = browserReq(t, s, "GET", "/v1/events?csrf="+c.csrf, "", func(r *http.Request) { r.AddCookie(c.cookie) })
			} else {
				resp = rawReq(t, s, "GET", "/v1/events", "", nil)
			}
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
				t.Fatalf("events: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
			}
			events := readSSE(t, resp)
			wantSSE(t, events, "hello")

			ch := enqueue(t, b, hitl.Request{ID: "e1", Tool: "POST", Target: "http://example.com/x"})
			if ev := wantSSE(t, events, "added"); ev.Request.ID != "e1" || ev.Request.Target != "http://example.com/x" {
				t.Fatalf("added: %+v", ev)
			}
			if err := b.DecideBy("e1", hitl.Always, "cli"); err != nil {
				t.Fatal(err)
			}
			<-ch
			if ev := wantSSE(t, events, "decided"); ev.Request.ID != "e1" || ev.Decision != "always" || ev.By != "cli" {
				t.Fatalf("decided: %+v", ev)
			}
		})
	}
}

func TestEventsSSEStreamsPastWriteTimeoutAndCloses(t *testing.T) {
	old := sseKeepalive
	sseKeepalive = 20 * time.Millisecond
	t.Cleanup(func() { sseKeepalive = old })
	s, _ := startServer(t, time.Minute)
	resp := rawReq(t, s, "GET", "/v1/events", "", nil)
	events := readSSE(t, resp)
	wantSSE(t, events, "hello")
	time.Sleep(100 * time.Millisecond) // a few keepalives
	go s.Close()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream not closed on server Close")
	}
}

func TestUISessionActive(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	if s.UISessionActive() || s.UIPageURL() != "http://"+s.Info().Addr+"/ui" {
		t.Fatal("no session yet")
	}
	c := login(t, s)
	if !s.UISessionActive() {
		t.Fatal("session should be active")
	}
	if resp := browserReq(t, s, "POST", "/v1/ui/logout", "", c.apply); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if s.UISessionActive() {
		t.Fatal("logout must end the session")
	}
	if resp := browserReq(t, s, "GET", "/v1/ui/state", "", c.apply); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", resp.StatusCode)
	}
}
