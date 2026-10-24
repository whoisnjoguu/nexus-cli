package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

// These tests run the real binary (the test binary re-executed through TestMCPHelperProcess in
// "serve" mode, which executes any nexus-cli command line) as separate processes, so state that
// must survive a process boundary (replay guard, audit chain, discovery files) is exercised
// for real.

// e2eHome is an isolated HOME/USERPROFILE/NEXUS_HOME shared by the test and its subprocesses.
type e2eHome struct {
	t     *testing.T
	nexus string
	env   []string
}

func newE2EHome(t *testing.T) *e2eHome {
	t.Helper()
	if testing.Short() {
		t.Skip("spawns processes")
	}
	home := t.TempDir()
	nh := filepath.Join(home, ".nexus")
	// The parent reads discovery files and the audit log from the same NEXUS_HOME.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("NEXUS_HOME", nh)
	t.Setenv("NEXUS_POLICY", "")
	t.Setenv("NEXUS_KEY_BACKEND", "file")
	env := []string{mcpHelperEnv + "=serve", "HOME=" + home, "USERPROFILE=" + home, "NEXUS_HOME=" + nh,
		"NEXUS_POLICY=", "NEXUS_KEY_BACKEND=file", "NEXUS_RUN=", helperEnv + "="}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HOME", "USERPROFILE", "NEXUS_HOME", "NEXUS_POLICY", "NEXUS_KEY_BACKEND", "NEXUS_RUN", helperEnv, mcpHelperEnv,
			"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		env = append(env, kv)
	}
	return &e2eHome{t: t, nexus: nh, env: env}
}

func (h *e2eHome) command(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestMCPHelperProcess$", "--"}, args...)...)
	c.Env = h.env
	return c
}

// run executes one nexus-cli command to completion.
func (h *e2eHome) run(args ...string) (stdout, stderr string, err error) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := h.command(ctx, args...)
	var o, e strings.Builder
	c.Stdout, c.Stderr = &o, &e
	err = c.Run()
	return o.String(), e.String(), err
}

func (h *e2eHome) mint(key string, extra ...string) string {
	h.t.Helper()
	out, errOut, err := h.run(append([]string{"identity", "mint", "--agent-id", "e2e", "--user-id", "alice@example.com",
		"--scopes", "repo:read", "--key", key, "-q"}, extra...)...)
	if err != nil {
		h.t.Fatalf("identity mint: %v\n%s", err, errOut)
	}
	tok := strings.TrimSpace(out)
	if strings.Count(tok, ".") != 2 {
		h.t.Fatalf("mint printed %q", out)
	}
	return tok
}

// nexusProc is a long-running nexus-cli subprocess (dev).
type nexusProc struct {
	cmd      *exec.Cmd
	out, err *syncBuffer
	done     chan error
	addr     string
	stopOnce sync.Once
}

var listenRe = regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`)

func (h *e2eHome) startDev(args ...string) *nexusProc {
	h.t.Helper()
	p := &nexusProc{out: &syncBuffer{}, err: &syncBuffer{}, done: make(chan error, 1)}
	p.cmd = h.command(context.Background(), append([]string{"dev", "--port", "0", "--mitm", "off"}, args...)...)
	p.cmd.Stdout, p.cmd.Stderr = p.out, p.err
	if err := p.cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	h.t.Cleanup(p.stop)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.done:
			h.t.Fatalf("dev exited early: %v\nstdout:\n%s\nstderr:\n%s", err, p.out.String(), p.err.String())
		default:
		}
		if m := listenRe.FindStringSubmatch(p.out.String()); m != nil && strings.Contains(p.out.String(), "approvals:") {
			p.addr = m[1]
			return p
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.stop()
	h.t.Fatalf("dev did not start\nstdout:\n%s\nstderr:\n%s", p.out.String(), p.err.String())
	return nil
}

// stop shuts dev down: an interrupt where the OS supports signalling another process, else a kill.
func (p *nexusProc) stop() {
	p.stopOnce.Do(func() {
		if runtime.GOOS != "windows" {
			_ = p.cmd.Process.Signal(os.Interrupt)
			select {
			case <-p.done:
				return
			case <-time.After(10 * time.Second):
			}
		}
		_ = p.cmd.Process.Kill()
		<-p.done
	})
}

func (p *nexusProc) controlClient(t *testing.T) *control.Client {
	t.Helper()
	var infos []control.Info
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		infos, _ = control.Discover()
		for _, in := range infos {
			if in.PID == p.cmd.Process.Pid {
				c := control.NewClient(in)
				t.Cleanup(c.Close)
				return c
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no control endpoint for pid %d: %+v", p.cmd.Process.Pid, infos)
	return nil
}

// proxied sends method url through the proxy at addr. An empty token sends no credentials.
func proxied(t *testing.T, addr, token, method, target string) int {
	t.Helper()
	pu := &url.URL{Scheme: "http", Host: addr}
	if token != "" {
		pu.User = url.UserPassword("agent", token)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

type e2eUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	hits []string
}

func newE2EUpstream(t *testing.T) *e2eUpstream {
	u := &e2eUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hits = append(u.hits, r.Method+" "+r.URL.Path)
		u.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *e2eUpstream) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.hits...)
}

const e2eDevPolicy = `agent: e2e
default_action: deny
tools:
  - match: {method: GET, host: 127.0.0.1, path: /allowed}
    action: allow
  - match: {method: GET, host: 127.0.0.1, path: /denied}
    action: %s
  - match: {method: POST, host: 127.0.0.1, path: /hitl}
    action: hitl
`

func writeE2EPolicy(t *testing.T, path, deniedAction string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(fmt.Sprintf(e2eDevPolicy, deniedAction)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestE2EDevSubprocess drives `nexus-cli dev` as a real process: identity mint, proxy
// allow/deny/default-deny, authentication, single-use replay across a restart, HITL answered
// by `nexus-cli approve`, SDK checks, policy hot reload and `nexus-cli audit verify`.
func TestE2EDevSubprocess(t *testing.T) {
	h := newE2EHome(t)
	dir := t.TempDir()
	pol, key := filepath.Join(dir, "nexus.yaml"), filepath.Join(dir, "ed25519.key")
	writeE2EPolicy(t, pol, "deny")
	up := newE2EUpstream(t)
	base := up.URL

	tok := h.mint(key)
	single := h.mint(key, "--single-use")
	devArgs := []string{"--policy", pol, "--key", key, "--approval-timeout", "20s"}
	dev := h.startDev(devArgs...)

	// Policy decisions through the proxy.
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/allowed", http.StatusOK},
		{http.MethodGet, "/denied", http.StatusForbidden},
		{http.MethodGet, "/unlisted", http.StatusForbidden},
		{http.MethodDelete, "/allowed", http.StatusForbidden},
	} {
		if got := proxied(t, dev.addr, tok, c.method, base+c.path); got != c.want {
			t.Errorf("%s %s = %d, want %d", c.method, c.path, got, c.want)
		}
	}
	// Authentication: missing, garbage and foreign-signed tokens never reach the upstream.
	other := filepath.Join(dir, "other.key")
	foreign := h.mint(other)
	for name, bad := range map[string]string{"missing": "", "garbage": "not.a.jwt", "foreign": foreign, "truncated": tok[:len(tok)-4]} {
		if got := proxied(t, dev.addr, bad, http.MethodGet, base+"/allowed?auth="+name); got == http.StatusOK || got < 400 {
			t.Errorf("%s token: status %d", name, got)
		}
	}
	// Single-use tokens.
	if got := proxied(t, dev.addr, single, http.MethodGet, base+"/allowed?single=1"); got != http.StatusOK {
		t.Fatalf("single-use first use = %d", got)
	}
	if got := proxied(t, dev.addr, single, http.MethodGet, base+"/allowed?single=2"); got == http.StatusOK {
		t.Fatal("single-use token accepted twice")
	}

	// HITL through the proxy, answered by `nexus-cli approve` subprocesses.
	ctl := dev.controlClient(t)
	for _, c := range []struct {
		decision string
		want     int
	}{{"once", http.StatusOK}, {"deny", http.StatusForbidden}} {
		got := make(chan int, 1)
		go func() { got <- proxied(t, dev.addr, tok, http.MethodPost, base+"/hitl") }()
		var id string
		waitUntil(t, "pending approval", func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			reqs, err := ctl.List(ctx, 0)
			if err == nil && len(reqs) > 0 {
				id = reqs[0].ID
			}
			return id != ""
		})
		if out, errOut, err := h.run("approve", id, "--decision", c.decision); err != nil {
			t.Fatalf("approve %s: %v\n%s%s", c.decision, err, out, errOut)
		}
		select {
		case code := <-got:
			if code != c.want {
				t.Fatalf("hitl answered %s = %d, want %d", c.decision, code, c.want)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("hitl call not released after approve %s", c.decision)
		}
	}

	// SDK checks against the same process (--require-auth is on by default).
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, c := range []struct {
		name string
		req  control.CheckRequest
		want string
	}{
		{"allow", control.CheckRequest{Method: "get", Host: "127.0.0.1", Path: "/allowed", Token: tok}, "allow"},
		{"deny", control.CheckRequest{Method: "GET", Host: "127.0.0.1", Path: "/denied", Token: tok}, "deny"},
		{"default", control.CheckRequest{Tool: "shell", Token: tok}, "deny"},
		{"no token", control.CheckRequest{Method: "GET", Host: "127.0.0.1", Path: "/allowed"}, "deny"},
		{"foreign token", control.CheckRequest{Method: "GET", Host: "127.0.0.1", Path: "/allowed", Token: foreign}, "deny"},
	} {
		res, err := ctl.Check(ctx, c.req)
		if err != nil {
			t.Fatalf("check %s: %v", c.name, err)
		}
		if res.Decision != c.want {
			t.Errorf("check %s = %+v, want %s", c.name, res, c.want)
		}
	}

	// The replay guard is persistent: a restarted dev still rejects the spent single-use token.
	dev.stop()
	if infos, _ := control.Discover(); runtime.GOOS != "windows" && len(infos) != 0 {
		t.Errorf("discovery files left after shutdown: %+v", infos)
	}
	dev = h.startDev(devArgs...)
	if got := proxied(t, dev.addr, single, http.MethodGet, base+"/allowed?single=3"); got == http.StatusOK {
		t.Fatal("single-use token accepted again after restart")
	}
	if got := proxied(t, dev.addr, tok, http.MethodGet, base+"/allowed?restart=1"); got != http.StatusOK {
		t.Fatalf("reusable token after restart = %d", got)
	}

	// Hot reload (file polling, so it works on every OS) flips /denied to allow.
	writeE2EPolicy(t, pol, "allow")
	waitUntil(t, "policy reload", func() bool { return strings.Contains(dev.err.String(), "policy reloaded") })
	if got := proxied(t, dev.addr, tok, http.MethodGet, base+"/denied"); got != http.StatusOK {
		t.Fatalf("after reload /denied = %d\nstderr:\n%s", got, dev.err.String())
	}
	dev.stop()

	want := []string{"GET /allowed", "GET /allowed", "POST /hitl", "GET /allowed", "GET /denied"}
	if got := up.seen(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("upstream saw %v, want %v", got, want)
	}

	out, errOut, err := h.run("audit", "verify")
	if err != nil {
		t.Fatalf("audit verify: %v\n%s%s", err, out, errOut)
	}
	ents, err := audit.ReadAll(filepath.Join(h.nexus, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, e := range ents {
		path := e.Target // host[:port]/path for HTTP decisions
		if i := strings.Index(path, "/"); i >= 0 {
			path = path[i:]
		}
		count[e.Decision+" "+e.Tool+" "+path]++
	}
	for k, n := range map[string]int{
		"allow GET /allowed": 4,
		"deny GET /denied":   1,
		"deny GET /unlisted": 1,
		"allow POST /hitl":   1,
		"deny POST /hitl":    1,
		"allow GET /denied":  1,
	} {
		if count[k] < n {
			t.Errorf("audit has %d %q entries, want at least %d (all: %v)", count[k], k, n, count)
		}
	}
}

// TestE2EMCPTaintEscalatesSDKCheck: a tainting MCP tool call through `mcp serve` makes a later
// SDK egress check (POST /v1/check on the same process) escalate to a human.
func TestE2EMCPTaintEscalatesSDKCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	ws, nh := t.TempDir(), t.TempDir()
	t.Setenv("NEXUS_HOME", nh)
	exe, _ := json.Marshal(os.Args[0])
	pol := fmt.Sprintf(`default_action: deny
escalate_when_tainted: true
egress:
  allow: [api.good.com]
tools:
  - match: {tool: "fake__read_file"}
    action: allow
    taints: [secrets]
  - match: {method: GET}
    action: allow
mcp:
  upstreams:
    - name: fake
      command: %s
      args: ["-test.run=^TestMCPHelperProcess$"]
      env: {%s: upstream}
`, exe, mcpHelperEnv)
	if err := os.WriteFile(filepath.Join(ws, "nexus.yaml"), []byte(pol), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := startMCPServe(t, ws, nh)
	if err != nil {
		t.Fatal(err)
	}
	var info control.Info
	waitUntil(t, "mcp control endpoint", func() bool {
		infos, _ := control.Discover()
		for _, in := range infos {
			if in.PID == c.cmd.Process.Pid {
				info = in
				return true
			}
		}
		return false
	})
	ctl := control.NewClient(info)
	defer ctl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	check := func(host string) control.CheckResponse {
		t.Helper()
		res, err := ctl.Check(ctx, control.CheckRequest{Method: "GET", Host: host, Path: "/", Wait: "0"})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	if res := check("api.other.com"); res.Decision != "allow" {
		t.Fatalf("before taint: %+v", res)
	}
	if ok, text := c.tool("fake__read_file", map[string]any{"path": "/tmp/x"}); !ok {
		t.Fatalf("tainting tool call refused: %q", text)
	}
	res := check("api.other.com")
	if res.Decision != "pending" || res.ApprovalID == "" {
		t.Fatalf("tainted egress to a non-allowlisted host = %+v, want pending", res)
	}
	if err := ctl.Decide(ctx, res.ApprovalID, hitl.Deny); err != nil {
		t.Fatal(err)
	}
	final, err := ctl.CheckStatus(ctx, res.ApprovalID, 5*time.Second)
	if err != nil || final.Decision != "deny" {
		t.Fatalf("after deny: %+v %v", final, err)
	}
	if res := check("api.good.com"); res.Decision != "allow" {
		t.Fatalf("tainted egress to an allowlisted host = %+v", res)
	}
}
