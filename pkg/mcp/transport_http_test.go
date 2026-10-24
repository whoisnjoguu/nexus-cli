package mcp

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

func startHTTPFake(t *testing.T, name string, sse bool) (*fakeHTTP, *httptest.Server) {
	t.Helper()
	f := newFakeHTTP(name, sse)
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	return f, ts
}

func TestHTTPUpstream(t *testing.T) {
	for _, mode := range []string{"json", "sse"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("FAKE_TOKEN", "s3cret")
			f, ts := startHTTPFake(t, "h", mode == "sse")
			spec := UpstreamSpec{Name: "h", URL: ts.URL, Headers: map[string]string{"Authorization": "Bearer ${FAKE_TOKEN}"}}
			once := hitl.ApproverFunc(func(context.Context, hitl.Request) hitl.Decision { return hitl.Once })
			g := startGW(t, Config{Approver: once, Upstreams: []UpstreamSpec{spec}})
			g.initialize(map[string]any{"sampling": map[string]any{}})
			g.c.setHandler(func(m map[string]any) (any, map[string]any) {
				return map[string]any{"role": "assistant", "content": map[string]any{"type": "text", "text": "from-client"}}, nil
			})

			if st := g.srv.Status()[0]; st.State != stateUp || st.Transport != "http" || st.Tools != 12 {
				t.Fatalf("status = %+v", st)
			}
			if got := resultText(t, g.callTool("h__echo", map[string]any{"q": "x"})); !strings.Contains(got, `"q":"x"`) {
				t.Errorf("echo = %q", got)
			}
			// Server→client request: on the POST's SSE stream (sse) or the GET stream (json).
			if got := resultText(t, g.callTool("h__sample", map[string]any{})); !strings.Contains(got, "from-client") {
				t.Errorf("sample = %q", got)
			}
			if mode == "sse" {
				_, ch := g.c.start("tools/call", map[string]any{"name": "h__progress", "arguments": map[string]any{}, "_meta": map[string]any{"progressToken": 7}})
				m := g.c.waitFor(5*time.Second, "progress", isMethod("notifications/progress"))
				if m["params"].(map[string]any)["progressToken"] != float64(7) {
					t.Errorf("progress = %v", m)
				}
				g.c.await(ch, 5*time.Second)
			}
			// Unsolicited notifications on the GET stream.
			g.callTool("h__change_tools", map[string]any{})
			eventually(t, 5*time.Second, "extra tool via GET-stream list_changed", func() bool {
				return toolNames(g.c.call("tools/list", map[string]any{}))["h__extra"]
			})

			f.mu.Lock()
			for _, h := range f.protoHdrs {
				if h != LatestProtocolVersion {
					t.Errorf("MCP-Protocol-Version header = %q", h)
				}
			}
			for _, a := range f.authHeader {
				if a != "Bearer s3cret" {
					t.Errorf("Authorization = %q", a)
				}
			}
			f.mu.Unlock()

			g.srv.Close()
			f.mu.Lock()
			deleted := f.deleted
			f.mu.Unlock()
			if !deleted {
				t.Error("session not DELETEd on close")
			}
		})
	}
}

func TestHTTPUpstreamGETReconnect(t *testing.T) {
	f, ts := startHTTPFake(t, "h", false)
	f.mu.Lock()
	f.dropFirst = true
	f.mu.Unlock()
	g := startGW(t, Config{Upstreams: []UpstreamSpec{{Name: "h", URL: ts.URL}}})
	g.initialize(nil)
	g.callTool("h__change_tools", map[string]any{})
	g.c.waitFor(5*time.Second, "list_changed", isMethod("notifications/tools/list_changed"))
	eventually(t, 5*time.Second, "reconnect with Last-Event-ID", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, id := range f.lastEvents {
			if id == "ev-1" {
				return true
			}
		}
		return false
	})
}

func TestHTTPUpstreamSessionExpiryRestarts(t *testing.T) {
	f, ts := startHTTPFake(t, "h", false)
	g := startGW(t, Config{Upstreams: []UpstreamSpec{{Name: "h", URL: ts.URL}}, tune: fastRestarts})
	g.initialize(nil)
	f.mu.Lock()
	f.sessionID = "sess-new"
	f.mu.Unlock()
	r := g.callTool("h__echo", map[string]any{})
	if !isErrorResult(r) || !strings.Contains(resultText(t, r), "session expired") {
		t.Fatalf("expected session expiry error: %v", r)
	}
	eventually(t, 10*time.Second, "re-initialized", func() bool {
		st := g.srv.Status()[0]
		return st.State == stateUp && st.Restarts >= 1
	})
	if isErrorResult(g.callTool("h__echo", map[string]any{})) {
		t.Fatal("echo after re-initialize failed")
	}
}

func TestHTTPUpstreamUnreachable(t *testing.T) {
	g := startGW(t, Config{DisableRestart: true, Upstreams: []UpstreamSpec{{Name: "h", URL: "http://127.0.0.1:1/mcp"}}})
	g.initialize(nil)
	if st := g.srv.Status()[0]; st.State != stateDown || st.LastError == "" {
		t.Errorf("status = %+v", st)
	}
}

func TestReadSSE(t *testing.T) {
	in := ": comment\nid: 1\nevent: message\ndata: {\"a\":\ndata: 1}\n\nretry: 500\n\ndata: last\n"
	var got []sseEvent
	if err := readSSE(strings.NewReader(in), func(ev sseEvent) bool { got = append(got, ev); return true }); err != nil {
		t.Fatal(err)
	}
	// An unterminated event at EOF is discarded, as the SSE spec requires.
	if len(got) != 2 || got[0].id != "1" || got[0].data != "{\"a\":\n1}" || got[1].retry != 500*time.Millisecond {
		t.Errorf("events = %+v", got)
	}
}

func TestExpandEnvRefs(t *testing.T) {
	t.Setenv("NX_TOK", "abc")
	if got := expandEnvRefs("Bearer ${NX_TOK} $NX_TOK ${NX_MISSING}"); got != "Bearer abc $NX_TOK " {
		t.Errorf("got %q", got)
	}
}
