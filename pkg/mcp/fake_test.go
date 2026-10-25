package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain doubles as a scripted fake MCP server (helper-process pattern): when re-executed with
// NEXUS_FAKE_MCP=1 the test binary speaks MCP over stdio instead of running tests.
func TestMain(m *testing.M) {
	if os.Getenv("NEXUS_FAKE_MCP") == "1" {
		runFakeStdio()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeCore implements a small MCP server whose behaviour is scripted by tool names.
type fakeCore struct {
	name  string
	dir   string
	proto string // forced protocolVersion answer ("" = echo request)

	mu        sync.Mutex
	extraTool bool
	seq       int
	pending   map[string]chan map[string]any
	cancels   map[string]chan string
	def       func(any) // unsolicited messages
}

func newFakeCore(name, dir string) *fakeCore {
	return &fakeCore{
		name:    name,
		dir:     dir,
		pending: make(map[string]chan map[string]any),
		cancels: make(map[string]chan string),
	}
}

func (f *fakeCore) appendFile(suffix, line string) {
	if f.dir == "" {
		return
	}
	fh, err := os.OpenFile(filepath.Join(f.dir, f.name+suffix), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer fh.Close()
	fmt.Fprintln(fh, line)
}

func runFakeStdio() {
	f := newFakeCore(os.Getenv("FAKE_NAME"), os.Getenv("FAKE_DIR"))
	f.proto = os.Getenv("FAKE_PROTO")
	if f.dir != "" {
		if _, err := os.Stat(filepath.Join(f.dir, f.name+".crashstart")); err == nil {
			f.appendFile(".starts", "crash")
			os.Exit(1)
		}
	}
	f.appendFile(".starts", "ok")
	w := &writerSink{w: os.Stdout}
	out := func(v any) { _ = w.send(v) }
	f.def = out
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		if _, isReq := m["id"]; isReq && m["method"] != nil {
			go f.request(m, out)
			continue
		}
		f.handle(m, out)
	}
}

// handle processes notifications and responses.
func (f *fakeCore) handle(m map[string]any, out func(any)) {
	method, _ := m["method"].(string)
	if method == "" {
		key := fmt.Sprint(m["id"])
		f.mu.Lock()
		ch := f.pending[key]
		f.mu.Unlock()
		if ch != nil {
			ch <- m
		}
		return
	}
	params, _ := m["params"].(map[string]any)
	switch method {
	case "notifications/cancelled":
		key := fmt.Sprint(params["requestId"])
		f.mu.Lock()
		ch := f.cancels[key]
		f.mu.Unlock()
		reason, _ := params["reason"].(string)
		f.appendFile(".cancelled", key+" "+reason)
		if ch != nil {
			select {
			case ch <- reason:
			default:
			}
		}
	case "notifications/roots/list_changed":
		f.appendFile(".events", "roots_changed")
	}
}

func (f *fakeCore) clientRequest(method string, params any, out func(any)) map[string]any {
	f.mu.Lock()
	f.seq++
	id := "srv-" + strconv.Itoa(f.seq)
	ch := make(chan map[string]any, 1)
	f.pending[id] = ch
	f.mu.Unlock()
	out(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	select {
	case r := <-ch:
		return r
	case <-time.After(20 * time.Second):
		return map[string]any{"error": "timeout"}
	}
}

func text(s string) map[string]any {
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": s}}}
}

func mustMarshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func page(items []any, params map[string]any, size int, key string) map[string]any {
	start := 0
	if c, ok := params["cursor"].(string); ok && c != "" {
		start, _ = strconv.Atoi(c)
	}
	end := start + size
	if end > len(items) {
		end = len(items)
	}
	res := map[string]any{key: items[start:end]}
	if end < len(items) {
		res["nextCursor"] = strconv.Itoa(end)
	}
	return res
}

// request answers a client request, writing every related message (and the response) to out.
func (f *fakeCore) request(m map[string]any, out func(any)) {
	id := m["id"]
	method, _ := m["method"].(string)
	params, _ := m["params"].(map[string]any)
	result, rerr := f.dispatch(id, method, params, out)
	if result == nil && rerr == nil {
		return // no response (cancelled)
	}
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rerr != nil {
		resp["error"] = rerr
	} else {
		resp["result"] = result
	}
	out(resp)
	if method == "resources/subscribe" && f.def != nil {
		f.def(map[string]any{"jsonrpc": "2.0", "method": "notifications/resources/updated", "params": map[string]any{"uri": params["uri"]}})
	}
}

func (f *fakeCore) tools() []any {
	names := []string{"echo", "slow", "progress", "sample", "roots", "elicit", "change_tools", "crash", "fetch", "write_file", "ping_client", "whoami"}
	f.mu.Lock()
	if f.extraTool {
		names = append(names, "extra")
	}
	f.mu.Unlock()
	var out []any
	for _, n := range names {
		out = append(out, map[string]any{"name": n, "description": "fake " + n, "inputSchema": map[string]any{"type": "object"}})
	}
	return out
}

func (f *fakeCore) dispatch(id any, method string, params map[string]any, out func(any)) (any, any) {
	switch method {
	case "initialize":
		f.appendFile(".init", mustMarshal(params))
		pv, _ := params["protocolVersion"].(string)
		if f.proto != "" {
			pv = f.proto
		}
		return map[string]any{
			"protocolVersion": pv,
			"capabilities": map[string]any{
				"tools":       map[string]any{"listChanged": true},
				"resources":   map[string]any{"subscribe": true, "listChanged": true},
				"prompts":     map[string]any{"listChanged": true},
				"completions": map[string]any{},
				"logging":     map[string]any{},
			},
			"serverInfo": map[string]any{"name": "fake-" + f.name, "version": "1.0"},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return page(f.tools(), params, 4, "tools"), nil
	case "tools/call":
		return f.toolCall(id, params, out)
	case "resources/list":
		var items []any
		for i := 1; i <= 5; i++ {
			items = append(items, map[string]any{"uri": fmt.Sprintf("fake://%s/r%d", f.name, i), "name": fmt.Sprintf("r%d", i)})
		}
		return page(items, params, 2, "resources"), nil
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": []any{map[string]any{"uriTemplate": "fake://" + f.name + "/{id}", "name": "tmpl"}}}, nil
	case "resources/read":
		uri, _ := params["uri"].(string)
		if !strings.HasPrefix(uri, "fake://"+f.name+"/") {
			return nil, map[string]any{"code": -32002, "message": "resource not found"}
		}
		return map[string]any{"contents": []any{map[string]any{"uri": uri, "text": "content of " + uri + " from " + f.name}}}, nil
	case "resources/subscribe", "resources/unsubscribe":
		f.appendFile(".events", method+" "+fmt.Sprint(params["uri"]))
		return map[string]any{}, nil
	case "prompts/list":
		items := []any{map[string]any{"name": "p1"}, map[string]any{"name": "p2"}, map[string]any{"name": "p3"}}
		return page(items, params, 2, "prompts"), nil
	case "prompts/get":
		name, _ := params["name"].(string)
		if name != "p1" && name != "p2" && name != "p3" {
			return nil, map[string]any{"code": -32602, "message": "unknown prompt " + name}
		}
		return map[string]any{"messages": []any{map[string]any{"role": "user", "content": map[string]any{
			"type": "text", "text": f.name + ":" + name + ":" + mustMarshal(params["arguments"]),
		}}}}, nil
	case "completion/complete":
		return map[string]any{"completion": map[string]any{"values": []any{f.name + "-a"}, "total": 1, "hasMore": false}}, nil
	case "logging/setLevel":
		f.appendFile(".events", "level "+fmt.Sprint(params["level"]))
		return map[string]any{}, nil
	}
	return nil, map[string]any{"code": -32601, "message": "method not found: " + method}
}

func (f *fakeCore) toolCall(id any, params map[string]any, out func(any)) (any, any) {
	name, _ := params["name"].(string)
	args, _ := params["arguments"].(map[string]any)
	meta, _ := params["_meta"].(map[string]any)
	switch name {
	case "echo":
		return text(fmt.Sprintf("%s args=%s meta=%s", f.name, mustMarshal(args), mustMarshal(meta))), nil
	case "write_file":
		return text("wrote " + fmt.Sprint(args["path"])), nil
	case "fetch":
		return text("fetched " + fmt.Sprint(args["url"])), nil
	case "slow":
		ms := 20000
		if v, ok := args["ms"].(float64); ok {
			ms = int(v)
		}
		key := fmt.Sprint(id)
		ch := make(chan string, 1)
		f.mu.Lock()
		f.cancels[key] = ch
		f.mu.Unlock()
		f.appendFile(".calls", "slow")
		select {
		case <-ch:
			return nil, nil
		case <-time.After(time.Duration(ms) * time.Millisecond):
			return text("slow done"), nil
		}
	case "progress":
		tok := meta["progressToken"]
		for i := 1; i <= 3; i++ {
			out(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"progressToken": tok, "progress": i, "total": 3}})
		}
		out(map[string]any{"jsonrpc": "2.0", "method": "notifications/message", "params": map[string]any{"level": "info", "data": "hello from " + f.name}})
		return text("progress done"), nil
	case "sample":
		r := f.clientRequest("sampling/createMessage", map[string]any{
			"messages":  []any{map[string]any{"role": "user", "content": map[string]any{"type": "text", "text": "hi"}}},
			"maxTokens": 10,
		}, out)
		return text("sample-result: " + mustMarshal(r)), nil
	case "roots":
		return text("roots-result: " + mustMarshal(f.clientRequest("roots/list", map[string]any{}, out))), nil
	case "elicit":
		return text("elicit-result: " + mustMarshal(f.clientRequest("elicitation/create", map[string]any{"message": "name?", "requestedSchema": map[string]any{"type": "object"}}, out))), nil
	case "ping_client":
		return text("ping-result: " + mustMarshal(f.clientRequest("ping", nil, out))), nil
	case "change_tools":
		f.mu.Lock()
		f.extraTool = true
		f.mu.Unlock()
		if f.def != nil {
			f.def(map[string]any{"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
		}
		return text("changed"), nil
	case "whoami":
		wd, _ := os.Getwd()
		return text(wd + "|" + os.Getenv("FAKE_EXTRA")), nil
	case "extra":
		return text("extra ok"), nil
	case "crash":
		os.Exit(3)
	}
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": "unknown tool " + name}}, "isError": true}, nil
}

// fakeHTTP serves a fakeCore over Streamable HTTP, in JSON or SSE response mode.
type fakeHTTP struct {
	core *fakeCore
	sse  bool

	mu         sync.Mutex
	sessionID  string
	getCh      chan []byte
	getCount   int
	lastEvents []string
	protoHdrs  []string
	deleted    bool
	dropFirst  bool // close the first GET stream after one event to exercise reconnect
	authHeader []string
	noGet      bool
	evSeq      int
}

func newFakeHTTP(name string, sse bool) *fakeHTTP {
	f := &fakeHTTP{core: newFakeCore(name, ""), sse: sse, sessionID: "sess-" + name, getCh: make(chan []byte, 100)}
	f.core.def = f.toGet
	return f
}

func (f *fakeHTTP) toGet(v any) {
	b, _ := json.Marshal(v)
	select {
	case f.getCh <- b:
	default:
	}
}

func (f *fakeHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.authHeader = append(f.authHeader, r.Header.Get("Authorization"))
	f.mu.Unlock()
	switch r.Method {
	case http.MethodDelete:
		f.mu.Lock()
		f.deleted = r.Header.Get("Mcp-Session-Id") == f.sessionID
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodGet:
		f.serveGet(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	method, _ := m["method"].(string)
	if method == "initialize" {
		w.Header().Set("Mcp-Session-Id", f.sessionID)
	} else {
		if r.Header.Get("Mcp-Session-Id") != f.sessionID {
			http.Error(w, "bad session", http.StatusNotFound)
			return
		}
		f.mu.Lock()
		f.protoHdrs = append(f.protoHdrs, r.Header.Get("MCP-Protocol-Version"))
		f.mu.Unlock()
	}
	_, hasID := m["id"]
	if method == "" || !hasID {
		f.core.handle(m, f.toGet)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	id := m["id"]
	isFinal := func(v any) bool {
		mm, ok := v.(map[string]any)
		return ok && mm["method"] == nil && fmt.Sprint(mm["id"]) == fmt.Sprint(id)
	}
	if f.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		var wmu sync.Mutex
		fl := w.(http.Flusher)
		f.core.request(m, func(v any) {
			wmu.Lock()
			defer wmu.Unlock()
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
			fl.Flush()
		})
		return
	}
	final := make(chan any, 1)
	done := make(chan struct{})
	go func() {
		f.core.request(m, func(v any) {
			if isFinal(v) {
				final <- v
				return
			}
			f.toGet(v)
		})
		close(done)
	}()
	var v any
	select {
	case v = <-final:
	case <-done:
		select {
		case v = <-final:
		default:
			w.WriteHeader(http.StatusAccepted)
			return
		}
	case <-r.Context().Done():
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeHTTP) serveGet(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if f.noGet {
		f.mu.Unlock()
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	f.getCount++
	n := f.getCount
	f.lastEvents = append(f.lastEvents, r.Header.Get("Last-Event-ID"))
	drop := f.dropFirst && n == 1
	f.mu.Unlock()
	if r.Header.Get("Mcp-Session-Id") != f.sessionID {
		http.Error(w, "bad session", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fl := w.(http.Flusher)
	fmt.Fprint(w, "retry: 20\n\n")
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-f.getCh:
			f.mu.Lock()
			f.evSeq++
			seq := f.evSeq
			f.mu.Unlock()
			fmt.Fprintf(w, "id: ev-%d\ndata: %s\n\n", seq, b)
			fl.Flush()
			if drop {
				return
			}
		}
	}
}

// --- client-side harness for the gateway ---------------------------------------------------

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// tclient is a scripted MCP client talking to the gateway over pipes.
type tclient struct {
	t      *testing.T
	w      io.WriteCloser
	wmu    sync.Mutex
	seq    int
	mu     sync.Mutex
	waits  map[string]chan map[string]any
	others chan map[string]any
	// onRequest answers server→client requests; nil result + nil err means "don't answer".
	onRequest func(m map[string]any) (any, map[string]any)
}

func newTClient(t *testing.T, w io.WriteCloser, r io.Reader) *tclient {
	c := &tclient{t: t, w: w, waits: make(map[string]chan map[string]any), others: make(chan map[string]any, 1000)}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			c.dispatch(m)
		}
	}()
	return c
}

func (c *tclient) dispatch(m map[string]any) {
	_, hasMethod := m["method"]
	if !hasMethod {
		key := fmt.Sprint(m["id"])
		c.mu.Lock()
		ch := c.waits[key]
		delete(c.waits, key)
		c.mu.Unlock()
		if ch != nil {
			ch <- m
			return
		}
	}
	if _, hasID := m["id"]; hasMethod && hasID {
		c.mu.Lock()
		h := c.onRequest
		c.mu.Unlock()
		if h != nil {
			go func() {
				res, rerr := h(m)
				if res == nil && rerr == nil {
					return
				}
				resp := map[string]any{"jsonrpc": "2.0", "id": m["id"]}
				if rerr != nil {
					resp["error"] = rerr
				} else {
					resp["result"] = res
				}
				c.send(resp)
			}()
		}
	}
	select {
	case c.others <- m:
	default:
	}
}

func (c *tclient) setHandler(h func(m map[string]any) (any, map[string]any)) {
	c.mu.Lock()
	c.onRequest = h
	c.mu.Unlock()
}

func (c *tclient) send(v any) {
	b, _ := json.Marshal(v)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, _ = c.w.Write(append(b, '\n'))
}

// start sends a request and returns its id and a channel for the response.
func (c *tclient) start(method string, params any) (int, chan map[string]any) {
	c.mu.Lock()
	c.seq++
	id := c.seq
	ch := make(chan map[string]any, 1)
	c.waits[strconv.Itoa(id)] = ch
	c.mu.Unlock()
	c.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return id, ch
}

func (c *tclient) call(method string, params any) map[string]any {
	c.t.Helper()
	_, ch := c.start(method, params)
	return c.await(ch, 15*time.Second)
}

func (c *tclient) await(ch chan map[string]any, d time.Duration) map[string]any {
	c.t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(d):
		c.t.Fatal("timed out waiting for response")
		return nil
	}
}

// waitFor consumes unsolicited messages until pred matches.
func (c *tclient) waitFor(d time.Duration, desc string, pred func(map[string]any) bool) map[string]any {
	c.t.Helper()
	deadline := time.After(d)
	for {
		select {
		case m := <-c.others:
			if pred(m) {
				return m
			}
		case <-deadline:
			c.t.Fatalf("timed out waiting for %s", desc)
			return nil
		}
	}
}

func isMethod(method string) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["method"] == method }
}

func resultText(t *testing.T, resp map[string]any) string {
	t.Helper()
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", resp)
	}
	first, _ := content[0].(map[string]any)
	s, _ := first["text"].(string)
	return s
}

func isErrorResult(resp map[string]any) bool {
	res, _ := resp["result"].(map[string]any)
	b, _ := res["isError"].(bool)
	return b
}

// gw is a gateway under test with a stdio client.
type gw struct {
	srv  *Server
	c    *tclient
	logs *syncBuf
	dir  string
	done chan struct{}
	inW  io.WriteCloser
}

func fakeSpec(t *testing.T, dir, name string) UpstreamSpec {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return UpstreamSpec{Name: name, Command: exe, Args: []string{"-test.run=^$"}, Env: map[string]string{
		"NEXUS_FAKE_MCP": "1", "FAKE_NAME": name, "FAKE_DIR": dir,
		"GORACE": "atexit_sleep_ms=0", // the race runtime otherwise sleeps 1s on exit
	}}
}

func fastRestarts(s *Server) {
	s.restartMin = 20 * time.Millisecond
	s.restartMax = 80 * time.Millisecond
}

// startGW starts a gateway with cfg (In/Out/Log are replaced) and serves stdio.
func startGW(t *testing.T, cfg Config) *gw {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	logs := &syncBuf{}
	cfg.In, cfg.Out, cfg.Log = inR, outW, logs
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g := &gw{srv: srv, logs: logs, done: make(chan struct{}), inW: inW}
	g.c = newTClient(t, inW, outR)
	go func() {
		_ = srv.Serve()
		close(g.done)
	}()
	t.Cleanup(func() {
		_ = inW.Close()
		select {
		case <-g.done:
		case <-time.After(10 * time.Second):
			t.Errorf("Serve did not return")
		}
		srv.Close()
		_ = outW.Close()
		if t.Failed() {
			t.Logf("gateway logs:\n%s", logs.String())
		}
	})
	return g
}

func (g *gw) initialize(caps map[string]any) map[string]any {
	g.c.t.Helper()
	if caps == nil {
		caps = map[string]any{}
	}
	r := g.c.call("initialize", map[string]any{"protocolVersion": LatestProtocolVersion, "capabilities": caps, "clientInfo": map[string]any{"name": "test", "version": "1"}})
	g.c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return r
}

func (g *gw) callTool(name string, args any) map[string]any {
	g.c.t.Helper()
	return g.c.call("tools/call", map[string]any{"name": name, "arguments": args})
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// waitUpstreamCall waits until the fake upstream name has started handling tool.
func waitUpstreamCall(t *testing.T, dir, name, tool string) {
	t.Helper()
	eventually(t, 10*time.Second, name+" handling "+tool, func() bool {
		for _, l := range readLines(filepath.Join(dir, name+".calls")) {
			if l == tool {
				return true
			}
		}
		return false
	})
}

func eventually(t *testing.T, d time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}
