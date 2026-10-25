package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

type httpClient struct {
	t     *testing.T
	base  string
	token string
	sid   string
}

func (c *httpClient) do(method string, body any, hdr map[string]string) *http.Response {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+"/mcp", rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.sid != "" {
		req.Header.Set("Mcp-Session-Id", c.sid)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s: %v", method, err)
	}
	return resp
}

func (c *httpClient) jsonBody(resp *http.Response) map[string]any {
	c.t.Helper()
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		c.t.Fatalf("decode: %v", err)
	}
	return m
}

func rpc(id int, method string, params any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
}

func startHTTPGateway(t *testing.T, cfg Config) (*Server, *httpClient) {
	t.Helper()
	cfg.In = strings.NewReader("")
	cfg.Log = &syncBuf{}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.HTTPHandler(HTTPOptions{Token: "tok"}))
	t.Cleanup(func() {
		srv.Close()
		ts.Close()
	})
	return srv, &httpClient{t: t, base: ts.URL, token: "tok"}
}

func (c *httpClient) initialize(caps map[string]any) {
	c.t.Helper()
	resp := c.do("POST", rpc(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": caps}), nil)
	if resp.StatusCode != 200 {
		c.t.Fatalf("initialize status %d", resp.StatusCode)
	}
	c.sid = resp.Header.Get("Mcp-Session-Id")
	m := c.jsonBody(resp)
	if m["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		c.t.Errorf("negotiated %v", m)
	}
	if len(c.sid) < 32 {
		c.t.Fatalf("weak session id %q", c.sid)
	}
	if r := c.do("POST", map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, nil); r.StatusCode != http.StatusAccepted {
		c.t.Fatalf("initialized status %d", r.StatusCode)
	}
}

func TestHTTPServeAuthOriginHost(t *testing.T) {
	_, c := startHTTPGateway(t, Config{})
	init := rpc(1, "initialize", map[string]any{"protocolVersion": LatestProtocolVersion, "capabilities": map[string]any{}})

	noAuth := *c
	noAuth.token = ""
	if r := noAuth.do("POST", init, nil); r.StatusCode != http.StatusUnauthorized || r.Header.Get("WWW-Authenticate") == "" {
		t.Errorf("no token: %d", r.StatusCode)
	}
	wrong := *c
	wrong.token = "nope"
	if r := wrong.do("POST", init, nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", r.StatusCode)
	}
	if r := c.do("POST", init, map[string]string{"Origin": "https://evil.example"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("evil origin: %d", r.StatusCode)
	}
	if r := c.do("POST", init, map[string]string{"Host": "evil.example:8765"}); r.StatusCode != http.StatusForbidden {
		t.Errorf("rebinding host: %d", r.StatusCode)
	}
	if r := c.do("POST", init, map[string]string{"Origin": "http://localhost:3000"}); r.StatusCode != http.StatusOK {
		t.Errorf("loopback origin: %d", r.StatusCode)
	}
	if r := c.do("POST", init, map[string]string{"Host": "localhost:8765"}); r.StatusCode != http.StatusOK {
		t.Errorf("localhost host: %d", r.StatusCode)
	}
	if r := c.do("PUT", init, nil); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", r.StatusCode)
	}
	req, _ := http.NewRequest("POST", c.base+"/other", nil)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusNotFound {
		t.Errorf("other path: %d", r.StatusCode)
	}
}

func TestHTTPServeSessionLifecycle(t *testing.T) {
	dir := t.TempDir()
	srv, c := startHTTPGateway(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})

	// Requests before initialize need a session.
	if r := c.do("POST", rpc(2, "tools/list", nil), nil); r.StatusCode != http.StatusBadRequest {
		t.Errorf("missing session: %d", r.StatusCode)
	}
	c.sid = "bogus"
	if r := c.do("POST", rpc(2, "tools/list", nil), nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("unknown session: %d", r.StatusCode)
	}
	c.sid = ""
	c.initialize(map[string]any{})

	r := c.do("POST", rpc(2, "tools/list", nil), map[string]string{"MCP-Protocol-Version": "2025-06-18"})
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("tools/list: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if !toolNames(c.jsonBody(r))["a__echo"] {
		t.Error("a__echo missing")
	}
	if r := c.do("POST", rpc(3, "tools/list", nil), map[string]string{"MCP-Protocol-Version": "1999-01-01"}); r.StatusCode != http.StatusBadRequest {
		t.Errorf("bad protocol header: %d", r.StatusCode)
	}
	if r := c.do("POST", []any{rpc(4, "ping", nil)}, nil); r.StatusCode != http.StatusBadRequest {
		t.Errorf("batch: %d", r.StatusCode)
	}

	// A second session is independent.
	c2 := *c
	c2.sid = ""
	c2.initialize(map[string]any{"elicitation": map[string]any{}})
	if c2.sid == c.sid {
		t.Fatal("session ids collide")
	}
	if len(srv.liveSessions()) != 2 {
		t.Errorf("live sessions = %d", len(srv.liveSessions()))
	}

	if r := c.do("DELETE", nil, nil); r.StatusCode != http.StatusOK {
		t.Errorf("DELETE: %d", r.StatusCode)
	}
	if r := c.do("POST", rpc(5, "tools/list", nil), nil); r.StatusCode != http.StatusNotFound {
		t.Errorf("after DELETE: %d", r.StatusCode)
	}
	if len(srv.liveSessions()) != 1 {
		t.Errorf("live sessions after DELETE = %d", len(srv.liveSessions()))
	}
}

type sseReader struct {
	ch chan sseEvent
}

func newSSEReader(body io.Reader) *sseReader {
	r := &sseReader{ch: make(chan sseEvent, 100)}
	go func() {
		_ = readSSE(body, func(ev sseEvent) bool {
			if ev.data != "" {
				r.ch <- ev
			}
			return true
		})
		close(r.ch)
	}()
	return r
}

func (r *sseReader) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case ev, ok := <-r.ch:
		if !ok {
			t.Fatal("stream ended")
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ev.data), &m); err != nil {
			t.Fatal(err)
		}
		return m
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for SSE event")
		return nil
	}
}

func TestHTTPServeElicitationOverSSE(t *testing.T) {
	dir := t.TempDir()
	_, c := startHTTPGateway(t, Config{Engine: policy.NewEngine(policy.DefaultPolicy()), Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	c.initialize(map[string]any{"elicitation": map[string]any{}})

	resp := c.do("POST", rpc(7, "tools/call", map[string]any{"name": "a__echo", "arguments": map[string]any{"z": 1}}), nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("expected SSE response, got %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	defer resp.Body.Close()
	sr := newSSEReader(resp.Body)
	el := sr.next(t)
	if el["method"] != "elicitation/create" {
		t.Fatalf("first event = %v", el)
	}
	ack := c.do("POST", map[string]any{"jsonrpc": "2.0", "id": el["id"], "result": map[string]any{"action": "accept", "content": map[string]any{"decision": "once"}}}, nil)
	if ack.StatusCode != http.StatusAccepted {
		t.Fatalf("elicitation response status %d", ack.StatusCode)
	}
	final := sr.next(t)
	if final["id"] != float64(7) || isErrorResult(final) || !strings.Contains(resultText(t, final), `"z":1`) {
		t.Fatalf("final = %v", final)
	}
}

func TestHTTPServeGETStream(t *testing.T) {
	dir := t.TempDir()
	_, c := startHTTPGateway(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	c.initialize(map[string]any{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Mcp-Session-Id", c.sid)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET: %v %v", err, resp)
	}
	defer resp.Body.Close()
	sr := newSSEReader(resp.Body)

	if r := c.do("GET", nil, map[string]string{"Accept": "text/event-stream"}); r.StatusCode != http.StatusConflict {
		t.Errorf("second GET stream: %d", r.StatusCode)
	}
	if r := c.do("GET", nil, map[string]string{"Accept": "application/json"}); r.StatusCode != http.StatusNotAcceptable {
		t.Errorf("GET without SSE accept: %d", r.StatusCode)
	}

	r := c.do("POST", rpc(9, "tools/call", map[string]any{"name": "a__change_tools", "arguments": map[string]any{}}), nil)
	r.Body.Close()
	if m := sr.next(t); m["method"] != "notifications/tools/list_changed" {
		t.Errorf("GET stream event = %v", m)
	}
}

func TestServeStreamableHTTP(t *testing.T) {
	srv, err := New(Config{In: strings.NewReader(""), Log: &syncBuf{}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	if err := srv.ServeStreamableHTTP(context.Background(), ln, HTTPOptions{}); err == nil {
		t.Fatal("empty token should be rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ServeStreamableHTTP(ctx, ln, HTTPOptions{Token: "t"}) }()
	c := &httpClient{t: t, base: "http://" + ln.Addr().String(), token: "t"}
	c.initialize(map[string]any{})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeStreamableHTTP did not stop")
	}
}

func TestHTTPServeDisconnectCancelsUpstream(t *testing.T) {
	dir := t.TempDir()
	_, c := startHTTPGateway(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	c.initialize(map[string]any{})

	ctx, cancel := context.WithCancel(context.Background())
	b, _ := json.Marshal(rpc(11, "tools/call", map[string]any{"name": "a__slow", "arguments": map[string]any{"ms": 30000}}))
	req, _ := http.NewRequestWithContext(ctx, "POST", c.base+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Mcp-Session-Id", c.sid)
	errc := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errc <- err
	}()
	eventually(t, 10*time.Second, "slow call reached upstream", func() bool {
		for _, l := range readLines(filepath.Join(dir, "a.calls")) {
			if l == "slow" {
				return true
			}
		}
		return false
	})
	cancel()
	<-errc
	eventually(t, 10*time.Second, "upstream cancellation", func() bool {
		for _, l := range readLines(filepath.Join(dir, "a.cancelled")) {
			if strings.HasSuffix(l, "cancelled by client") {
				return true
			}
		}
		return false
	})
}
