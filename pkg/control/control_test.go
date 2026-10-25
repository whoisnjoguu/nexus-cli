package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

func startServer(t *testing.T, timeout time.Duration) (*Server, *hitl.Broker) {
	t.Helper()
	t.Setenv("NEXUS_HOME", t.TempDir())
	b := hitl.NewBroker(timeout)
	s, err := Start(b, Info{Kind: "dev", Listen: "127.0.0.1:8080", Policy: "p.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, b
}

func rawReq(t *testing.T, s *Server, method, path, body string, mod func(*http.Request)) *http.Response {
	t.Helper()
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequest(method, "http://"+s.Info().Addr+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.Info().Token)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if mod != nil {
		mod(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func enqueue(t *testing.T, b *hitl.Broker, req hitl.Request) <-chan hitl.Decision {
	t.Helper()
	ch := make(chan hitl.Decision, 1)
	n := len(b.Pending())
	go func() { ch <- b.Approve(context.Background(), req) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(b.Pending()) != n+1 {
		if time.Now().After(deadline) {
			t.Fatal("request never queued")
		}
		time.Sleep(time.Millisecond)
	}
	return ch
}

func TestDir(t *testing.T) {
	t.Setenv("NEXUS_HOME", "/x/y")
	if d, _ := Dir(); d != filepath.Join("/x/y", "control") {
		t.Fatalf("got %s", d)
	}
	t.Setenv("NEXUS_HOME", "")
	home, _ := os.UserHomeDir()
	if d, _ := Dir(); d != filepath.Join(home, ".nexus", "control") {
		t.Fatalf("got %s", d)
	}
}

func TestStartWritesDiscoveryFile(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	info := s.Info()
	if info.PID != os.Getpid() || len(info.Token) != 64 || info.Started.IsZero() || !strings.HasPrefix(info.Addr, "127.0.0.1:") || info.CWD == "" {
		t.Fatalf("info not filled: %+v", info)
	}
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %v", fi.Mode().Perm())
		}
		di, _ := os.Stat(filepath.Dir(s.Path()))
		if di.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v", di.Mode().Perm())
		}
	}
	var onDisk Info
	b, _ := os.ReadFile(s.Path())
	if err := json.Unmarshal(b, &onDisk); err != nil || onDisk.Token != info.Token || onDisk.Kind != "dev" {
		t.Fatalf("file content: %s", b)
	}
	if name := filepath.Base(s.Path()); !strings.HasPrefix(name, strconv.Itoa(os.Getpid())+"-") || !strings.HasSuffix(name, ".json") {
		t.Fatal("unexpected file name")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Path()); !os.IsNotExist(err) {
		t.Fatal("discovery file not removed on Close")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := net.DialTimeout("tcp", info.Addr, time.Second); err == nil {
		t.Fatal("server still listening after Close")
	}
}

func TestAuth(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	for _, auth := range []string{"", "Bearer wrong", "Bearer " + s.Info().Token + "x", s.Info().Token, "Basic " + s.Info().Token} {
		for _, path := range []string{"/v1/status", "/v1/approvals"} {
			resp := rawReq(t, s, "GET", path, "", func(r *http.Request) {
				if auth == "" {
					r.Header.Del("Authorization")
				} else {
					r.Header.Set("Authorization", auth)
				}
			})
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("%s with %q: %d", path, auth, resp.StatusCode)
			}
		}
	}
	resp := rawReq(t, s, "POST", "/v1/approvals/x", `{"decision":"once"}`, func(r *http.Request) { r.Header.Del("Authorization") })
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST without auth: %d", resp.StatusCode)
	}
}

func TestHostAndOrigin(t *testing.T) {
	s, _ := startServer(t, time.Minute)
	_, port, _ := net.SplitHostPort(s.Info().Addr)
	for _, host := range []string{"localhost:" + port, "evil.com", "127.0.0.1", "evil.com:" + port} {
		resp := rawReq(t, s, "GET", "/v1/status", "", func(r *http.Request) { r.Host = host })
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("host %q: %d", host, resp.StatusCode)
		}
	}
	for _, origin := range []string{"http://127.0.0.1:" + port, "null", ""} {
		resp := rawReq(t, s, "GET", "/v1/status", "", func(r *http.Request) { r.Header["Origin"] = []string{origin} })
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("origin %q: %d", origin, resp.StatusCode)
		}
	}
}

func TestDecideValidation(t *testing.T) {
	s, b := startServer(t, time.Minute)
	got := enqueue(t, b, hitl.Request{ID: "abc"})

	resp := rawReq(t, s, "POST", "/v1/approvals/abc", `{"decision":"once"}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("content type: %d", resp.StatusCode)
	}
	resp = rawReq(t, s, "POST", "/v1/approvals/abc", `{"decision":"once"}`, func(r *http.Request) { r.Header.Del("Content-Type") })
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content type: %d", resp.StatusCode)
	}
	for _, body := range []string{`{"decision":"y"}`, `{"decision":"yes"}`, `{"decision":"Once"}`, `{"decision":""}`, `{}`, `not json`, `{"decision":"once","x":1}`, `{"decision":"once"}{}`, `{"decision":1}`} {
		resp = rawReq(t, s, "POST", "/v1/approvals/abc", body, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %s: %d", body, resp.StatusCode)
		}
	}
	resp = rawReq(t, s, "POST", "/v1/approvals/abc", `{"decision":"`+strings.Repeat("a", 5000)+`"}`, nil)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: %d", resp.StatusCode)
	}
	resp = rawReq(t, s, "POST", "/v1/approvals/nope", `{"decision":"once"}`, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id: %d", resp.StatusCode)
	}
	if len(b.Pending()) != 1 {
		t.Fatal("invalid requests must not decide anything")
	}
	resp = rawReq(t, s, "POST", "/v1/approvals/abc", `{"decision":"session"}`, func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") })
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("valid decide: %d", resp.StatusCode)
	}
	if d := <-got; d != hitl.Session {
		t.Fatalf("got %v", d)
	}
	resp = rawReq(t, s, "POST", "/v1/approvals/abc", `{"decision":"once"}`, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("decided twice: %d", resp.StatusCode)
	}
	resp = rawReq(t, s, "GET", "/v1/approvals?wait=banana", "", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad wait: %d", resp.StatusCode)
	}
}

func TestClientListDecideStatus(t *testing.T) {
	s, b := startServer(t, time.Minute)
	c := NewClient(s.Info())
	defer c.Close()
	ctx := context.Background()

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Token != "" || st.Kind != "dev" || st.Pending != 0 || st.PID != os.Getpid() || st.Policy != "p.yaml" {
		t.Fatalf("status: %+v", st)
	}
	resp := rawReq(t, s, "GET", "/v1/status", "", nil)
	var raw map[string]any
	json.NewDecoder(resp.Body).Decode(&raw)
	if _, ok := raw["token"]; ok {
		t.Fatal("status leaks token")
	}

	list, err := c.List(ctx, 0)
	if err != nil || list == nil || len(list) != 0 {
		t.Fatalf("empty list: %v %v", list, err)
	}

	r1 := enqueue(t, b, hitl.Request{Tool: "tools/call", Target: "fs.write", AgentID: "a1", Params: `{"x":1}`})
	r2 := enqueue(t, b, hitl.Request{Tool: "tools/call", Target: "fs.delete"})
	list, err = c.List(ctx, 0)
	if err != nil || len(list) != 2 || list[0].Target != "fs.write" || list[1].Target != "fs.delete" || list[0].ID == "" || list[0].Params != `{"x":1}` {
		t.Fatalf("list: %+v %v", list, err)
	}
	if st, _ := c.Status(ctx); st.Pending != 2 {
		t.Fatalf("pending count %d", st.Pending)
	}

	if err := c.Decide(ctx, list[0].ID, hitl.Always); err != nil {
		t.Fatal(err)
	}
	if d := <-r1; d != hitl.Always {
		t.Fatalf("got %v", d)
	}
	if err := c.Decide(ctx, list[0].ID, hitl.Once); !errors.Is(err, hitl.ErrUnknownRequest) {
		t.Fatalf("decide twice: %v", err)
	}
	if err := c.Decide(ctx, "../status", hitl.Once); !errors.Is(err, hitl.ErrUnknownRequest) {
		t.Fatalf("bad id: %v", err)
	}
	if err := c.Decide(ctx, list[1].ID, hitl.Decision(42)); err == nil {
		t.Fatal("invalid decision accepted")
	}
	if err := c.Decide(ctx, list[1].ID, hitl.Deny); err != nil {
		t.Fatal(err)
	}
	if d := <-r2; d != hitl.Deny {
		t.Fatalf("got %v", d)
	}

	bad := NewClient(Info{Addr: s.Info().Addr, Token: "nope"})
	if _, err := bad.Status(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad token: %v", err)
	}
}

func TestLongPoll(t *testing.T) {
	s, b := startServer(t, time.Minute)
	c := NewClient(s.Info())
	defer c.Close()
	ctx := context.Background()

	// Times out with no change.
	start := time.Now()
	list, err := c.List(ctx, 300*time.Millisecond)
	if err != nil || len(list) != 0 {
		t.Fatal(list, err)
	}
	if el := time.Since(start); el < 250*time.Millisecond {
		t.Fatalf("returned too early: %v", el)
	}

	// Returns on change well before the timeout.
	type res struct {
		list []hitl.Request
		err  error
	}
	done := make(chan res, 1)
	start = time.Now()
	go func() {
		l, err := c.List(ctx, 20*time.Second)
		done <- res{l, err}
	}()
	time.Sleep(100 * time.Millisecond)
	got := enqueue(t, b, hitl.Request{ID: "lp"})
	select {
	case r := <-done:
		if r.err != nil || len(r.list) != 1 || r.list[0].ID != "lp" {
			t.Fatalf("long poll: %+v", r)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("long poll too slow")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long poll did not return on change")
	}

	// A change that happens between two polls is not missed (version tracking).
	if err := b.Decide("lp", hitl.Once); err != nil {
		t.Fatal(err)
	}
	<-got
	start = time.Now()
	list, err = c.List(ctx, 20*time.Second)
	if err != nil || len(list) != 0 || time.Since(start) > 5*time.Second {
		t.Fatalf("missed change: %v %v %v", list, err, time.Since(start))
	}

	// Close releases an in-flight long-poll.
	go func() {
		l, err := c.List(ctx, 50*time.Second)
		done <- res{l, err}
	}()
	time.Sleep(100 * time.Millisecond)
	closed := time.Now()
	s.Close()
	select {
	case <-done:
		if time.Since(closed) > 3*time.Second {
			t.Fatal("close slow")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long poll not released by Close")
	}
}

func TestParseWait(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "25s": 25 * time.Second, "5": 5 * time.Second, "10m": 60 * time.Second} {
		got, err := parseWait(in)
		if err != nil || got != want {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"-1s", "x", "-3"} {
		if _, err := parseWait(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

func TestParseDecisionStrict(t *testing.T) {
	for s, want := range map[string]hitl.Decision{"once": hitl.Once, "session": hitl.Session, "always": hitl.Always, "deny": hitl.Deny} {
		if d, err := ParseDecisionStrict(s); err != nil || d != want {
			t.Fatalf("%s: %v %v", s, d, err)
		}
	}
	for _, s := range []string{"y", "yes", "allow", "ONCE", " once", ""} {
		if _, err := ParseDecisionStrict(s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestDiscover(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)

	if l, err := Discover(); err != nil || len(l) != 0 {
		t.Fatalf("missing dir: %v %v", l, err)
	}

	b := hitl.NewBroker(time.Minute)
	s1, err := Start(b, Info{Kind: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	time.Sleep(5 * time.Millisecond)
	s2, err := Start(b, Info{Kind: "mcp"})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	// A stale file pointing at a closed port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := ln.Addr().String()
	ln.Close()
	dir, _ := Dir()
	stale := filepath.Join(dir, "999999-dead.json")
	data, _ := json.Marshal(Info{PID: 999999, Addr: deadAddr, Token: "t", Kind: "dev", Started: time.Now()})
	if err := os.WriteFile(stale, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Junk files are skipped, not fatal.
	os.WriteFile(filepath.Join(dir, "junk.json"), []byte("{"), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)

	live, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 2 || live[0].Kind != "dev" || live[1].Kind != "mcp" || live[0].Token == "" {
		t.Fatalf("live: %+v", live)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale discovery file not removed")
	}

	// A closed server disappears.
	s1.Close()
	live, _ = Discover()
	if len(live) != 1 || live[0].Kind != "mcp" {
		t.Fatalf("after close: %+v", live)
	}
}
