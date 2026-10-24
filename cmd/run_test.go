package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/ca"
	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/proxy"
)

const helperEnv = "NEXUS_TEST_HELPER"

// TestHelperProcess is the child launched by `nexus-cli run` in these tests. It is a no-op unless
// NEXUS_TEST_HELPER is set. Commands (after "--"):
//
//	exit <code>          exit with code
//	env                  print the gate-related environment as JSON
//	fetch <method> <url> ...  request each URL through HTTPS_PROXY/HTTP_PROXY, print "<url> <status>"
//	control              print the kinds of running control endpoints
func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		os.Exit(90)
	}
	switch args[0] {
	case "exit":
		code, _ := strconv.Atoi(args[1])
		os.Exit(code)
	case "env":
		keys := append([]string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy",
			"NODE_USE_ENV_PROXY", "NEXUS_PROXY_URL", "NEXUS_RUN", "NODE_EXTRA_CA_CERTS"}, caBundleEnv...)
		out := map[string]string{}
		for _, k := range keys {
			if v, ok := os.LookupEnv(k); ok {
				out[k] = v
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		os.Exit(0)
	case "fetch":
		method := args[1]
		pool := x509.NewCertPool()
		if f := os.Getenv("SSL_CERT_FILE"); f != "" {
			if pem, err := os.ReadFile(f); err == nil {
				pool.AppendCertsFromPEM(pem)
			}
		}
		// Go never proxies loopback/example names via ProxyFromEnvironment quirks, so read the
		// variables explicitly as any proxy-aware client would.
		proxyFor := func(r *http.Request) (*url.URL, error) {
			v := os.Getenv("HTTP_PROXY")
			if r.URL.Scheme == "https" {
				v = os.Getenv("HTTPS_PROXY")
			}
			return url.Parse(v)
		}
		c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
			Proxy: proxyFor, TLSClientConfig: &tls.Config{RootCAs: pool},
		}}
		for _, u := range args[2:] {
			req, _ := http.NewRequest(method, u, nil)
			resp, err := c.Do(req)
			if err != nil {
				fmt.Printf("%s ERR %v\n", u, err)
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			fmt.Printf("%s %d\n", u, resp.StatusCode)
		}
		os.Exit(0)
	case "control":
		infos, err := control.Discover()
		if err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		for _, in := range infos {
			fmt.Println("kind=" + in.Kind + " listen=" + in.Listen)
		}
		os.Exit(0)
	}
	os.Exit(91)
}

// runEnv isolates a `nexus-cli run` test: fresh HOME/NEXUS_HOME, a policy file, a key and fake
// upstreams for example.com (plain HTTP on :80, TLS on :443) reached via upstreamTransportHook.
type runEnv struct {
	t       *testing.T
	dir     string
	home    string
	nexus   string
	policy  string
	key     string
	mu      sync.Mutex
	paths   []string
	plain   *httptest.Server
	secure  *httptest.Server
	stdout  *syncBuffer
	stderr  *syncBuffer
	testBin string
}

const runTestPolicy = `agent: test
default_action: deny
tools:
  - match: {method: GET, host: example.com, path: /allowed}
    action: allow
    scope: repo:read
  - match: {method: GET, host: example.com, path: /denied}
    action: deny
  - match: {method: POST, host: example.com, path: /hitl}
    action: hitl
`

func newRunEnv(t *testing.T) *runEnv {
	t.Helper()
	e := &runEnv{t: t, dir: t.TempDir(), home: t.TempDir(), nexus: t.TempDir(), testBin: os.Args[0]}
	t.Setenv("HOME", e.home)
	t.Setenv("NEXUS_HOME", e.nexus)
	t.Setenv("NEXUS_RUN", "")
	t.Setenv(helperEnv, "1")
	e.policy = filepath.Join(e.dir, "nexus.yaml")
	e.key = filepath.Join(e.dir, "ed25519.key")
	if err := os.WriteFile(e.policy, []byte(runTestPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.paths = append(e.paths, r.Method+" "+r.URL.Path+" agent="+r.Header.Get("X-Nexus-Agent-ID"))
		e.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	})
	e.plain = httptest.NewServer(h)
	e.secure = httptest.NewUnstartedServer(h)
	e.secure.Config.ErrorLog = log.New(io.Discard, "", 0)
	e.secure.StartTLS()
	t.Cleanup(e.plain.Close)
	t.Cleanup(e.secure.Close)

	tr := e.secure.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		target := e.secure.Listener.Addr().String()
		if strings.HasSuffix(addr, ":80") {
			target = e.plain.Listener.Addr().String()
		}
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
	upstreamTransportHook = tr
	t.Cleanup(func() { upstreamTransportHook = nil })

	resetFlags(t, runCmd.Flags())
	t.Cleanup(func() { resetFlags(t, runCmd.Flags()) })
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	return e
}

// run executes `nexus-cli run <flags> -- <test binary> <helper args...>`.
func (e *runEnv) run(flags []string, helper ...string) error {
	e.t.Helper()
	resetFlags(e.t, runCmd.Flags())
	e.stdout, e.stderr = &syncBuffer{}, &syncBuffer{}
	rootCmd.SetOut(e.stdout)
	rootCmd.SetErr(e.stderr)
	args := append([]string{"run", "--policy", e.policy, "--key", e.key, "--user-id", "alice@example.com"}, flags...)
	if len(helper) > 0 {
		args = append(args, "--", e.testBin, "-test.run=^TestHelperProcess$", "--")
		args = append(args, helper...)
	}
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func (e *runEnv) upstreamPaths() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.paths...)
}

func (e *runEnv) childEnv(flags ...string) map[string]string {
	e.t.Helper()
	if err := e.run(flags, "env"); err != nil {
		e.t.Fatalf("run env: %v; stderr=%s", err, e.stderr.String())
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(lastJSONLine(e.stdout.String())), &got); err != nil {
		e.t.Fatalf("child env output %q: %v", e.stdout.String(), err)
	}
	return got
}

func lastJSONLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "{") {
			return lines[i]
		}
	}
	return ""
}

func TestRunPropagatesExitCode(t *testing.T) {
	e := newRunEnv(t)
	err := e.run([]string{"--mitm", "off", "--no-audit"}, "exit", "7")
	if code, ok := ExitCode(err); !ok || code != 7 {
		t.Fatalf("run exit 7: err=%v code=%d ok=%v", err, code, ok)
	}
	if err := e.run([]string{"--mitm", "off", "--no-audit"}, "exit", "0"); err != nil {
		t.Fatalf("run exit 0 = %v", err)
	}
	if !strings.Contains(e.stderr.String(), "[nexus] gating "+filepath.Base(os.Args[0])+" via 127.0.0.1:") ||
		!strings.Contains(e.stderr.String(), "approve prompts with: nexus-cli approve") {
		t.Fatalf("missing gating banner: %q", e.stderr.String())
	}
}

func TestRunCommandNotFound(t *testing.T) {
	e := newRunEnv(t)
	resetFlags(t, runCmd.Flags())
	e.stdout, e.stderr = &syncBuffer{}, &syncBuffer{}
	rootCmd.SetOut(e.stdout)
	rootCmd.SetErr(e.stderr)
	rootCmd.SetArgs([]string{"run", "--policy", e.policy, "--key", e.key, "--user-id", "a", "--no-audit", "--mitm", "off",
		"--", filepath.Join(e.dir, "does-not-exist")})
	err := rootCmd.Execute()
	if code, ok := ExitCode(err); !ok || code != 127 {
		t.Fatalf("missing command: err=%v code=%d", err, code)
	}
}

func TestRunSetsGateEnvWithMITM(t *testing.T) {
	e := newRunEnv(t)
	got := e.childEnv("--mitm", "on", "--no-audit")

	c, err := ca.Load(filepath.Join(e.nexus, "ca"))
	if err != nil {
		t.Fatalf("--mitm on should create the CA: %v", err)
	}
	pu, err := url.Parse(got["HTTPS_PROXY"])
	if err != nil || pu.Scheme != "http" || pu.User.Username() != "nexus" || !strings.HasPrefix(pu.Host, "127.0.0.1:") {
		t.Fatalf("HTTPS_PROXY = %q", got["HTTPS_PROXY"])
	}
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "https_proxy", "NEXUS_PROXY_URL"} {
		if got[k] != got["HTTPS_PROXY"] {
			t.Errorf("%s = %q, want %q", k, got[k], got["HTTPS_PROXY"])
		}
	}
	if got["NO_PROXY"] != "localhost,127.0.0.1,::1" || got["no_proxy"] != got["NO_PROXY"] {
		t.Errorf("NO_PROXY = %q / %q", got["NO_PROXY"], got["no_proxy"])
	}
	if got["NODE_USE_ENV_PROXY"] != "1" || got["NEXUS_RUN"] != "1" {
		t.Errorf("NODE_USE_ENV_PROXY=%q NEXUS_RUN=%q", got["NODE_USE_ENV_PROXY"], got["NEXUS_RUN"])
	}
	for _, k := range caBundleEnv {
		if got[k] != c.BundlePath() {
			t.Errorf("%s = %q, want %q", k, got[k], c.BundlePath())
		}
	}
	if got["NODE_EXTRA_CA_CERTS"] != c.CertPath() {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q, want %q", got["NODE_EXTRA_CA_CERTS"], c.CertPath())
	}
	bundle, err := os.ReadFile(c.BundlePath())
	if err != nil || !bytes.Contains(bundle, c.CertPEM()) {
		t.Fatalf("bundle %s missing the nexus CA: %v", c.BundlePath(), err)
	}

	// The token is ours: default agent id is the command's base name, scopes default to the
	// policy's required scopes, and act_as is the --user-id fallback.
	pass, _ := pu.User.Password()
	signer, err := jwt.LoadOrCreateSigner(e.key)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := signer.Verifier().Verify(pass)
	if err != nil {
		t.Fatalf("child token does not verify: %v", err)
	}
	if claims.AgentID != strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") || claims.ActAs != "alice@example.com" ||
		strings.Join(claims.Scopes, ",") != "repo:read" {
		t.Fatalf("claims = %+v", claims)
	}
	if ttl := claims.ExpiresAt.Sub(claims.IssuedAt.Time); ttl != 12*time.Hour {
		t.Fatalf("default token ttl = %s, want 12h", ttl)
	}
}

func TestRunMITMOffSetsNoCAVars(t *testing.T) {
	e := newRunEnv(t)
	for _, k := range append([]string{"NODE_EXTRA_CA_CERTS"}, caBundleEnv...) {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	got := e.childEnv("--mitm", "auto", "--no-audit", "--agent-id", "bot", "--scopes", "a,b", "--ttl", "1h", "--no-proxy", "internal.local")
	for _, k := range append([]string{"NODE_EXTRA_CA_CERTS"}, caBundleEnv...) {
		if v, ok := got[k]; ok {
			t.Errorf("%s set without MITM: %q", k, v)
		}
	}
	if got["NO_PROXY"] != "internal.local" {
		t.Errorf("NO_PROXY = %q", got["NO_PROXY"])
	}
	if _, err := os.Stat(filepath.Join(e.nexus, "ca")); err == nil {
		t.Error("--mitm auto must not create a CA")
	}
	pu, _ := url.Parse(got["HTTP_PROXY"])
	pass, _ := pu.User.Password()
	signer, _ := jwt.LoadOrCreateSigner(e.key)
	claims, err := signer.Verifier().Verify(pass)
	if err != nil || claims.AgentID != "bot" || strings.Join(claims.Scopes, ",") != "a,b" ||
		claims.ExpiresAt.Sub(claims.IssuedAt.Time) != time.Hour {
		t.Fatalf("claims = %+v err=%v", claims, err)
	}
	if !strings.Contains(e.stderr.String(), "HTTPS interception off") {
		t.Errorf("missing interception-off note: %q", e.stderr.String())
	}
}

func TestRunEnforcesPolicyAndAudits(t *testing.T) {
	e := newRunEnv(t)
	err := e.run([]string{"--mitm", "on", "--agent-id", "test-agent"}, "fetch", "GET",
		"https://example.com/allowed", "https://example.com/denied", "https://example.com/other",
		"http://example.com/allowed", "http://example.com/denied")
	if err != nil {
		t.Fatalf("run: %v; stderr=%s", err, e.stderr.String())
	}
	out := e.stdout.String()
	for _, want := range []string{
		"https://example.com/allowed 200",
		"https://example.com/denied 403",
		"https://example.com/other 403",
		"http://example.com/allowed 200",
		"http://example.com/denied 403",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("child output missing %q:\n%s", want, out)
		}
	}
	paths := e.upstreamPaths()
	if strings.Join(paths, "|") != "GET /allowed agent=test-agent|GET /allowed agent=test-agent" {
		t.Fatalf("upstream saw %v", paths)
	}

	entries, err := audit.Tail(filepath.Join(e.nexus, "audit.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, en := range entries {
		if en.Agent != "test-agent" || en.ActAs != "alice@example.com" {
			t.Fatalf("audit attribution = %+v", en)
		}
		got = append(got, en.Decision+" "+en.Tool+" "+en.Target)
	}
	want := []string{
		"allow GET example.com/allowed",
		"deny GET example.com/denied",
		"deny GET example.com/other",
		"allow GET example.com/allowed",
		"deny GET example.com/denied",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit = %v\nwant %v", got, want)
	}
}

func TestRunApprovalViaControlAPI(t *testing.T) {
	e := newRunEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	approved := make(chan string, 1)
	go func() {
		for ctx.Err() == nil {
			infos, _ := control.Discover()
			for _, in := range infos {
				if in.Kind != "run" {
					continue
				}
				c := control.NewClient(in)
				reqs, err := c.List(ctx, 0)
				if err == nil && len(reqs) > 0 {
					_ = c.Decide(ctx, reqs[0].ID, hitl.Once)
					approved <- reqs[0].Target
					c.Close()
					return
				}
				c.Close()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	if err := e.run([]string{"--mitm", "on", "--no-audit", "--approval-timeout", "20s"}, "fetch", "POST", "https://example.com/hitl"); err != nil {
		t.Fatalf("run: %v", err)
	}
	select {
	case target := <-approved:
		if target != "example.com/hitl" {
			t.Fatalf("approved target = %q", target)
		}
	default:
		t.Fatal("approval request never reached the control API")
	}
	if !strings.Contains(e.stdout.String(), "https://example.com/hitl 200") {
		t.Fatalf("approved call did not succeed: %s", e.stdout.String())
	}
	if !strings.Contains(e.stderr.String(), "[nexus] approval needed: POST example.com/hitl") {
		t.Fatalf("missing approval notice on stderr: %q", e.stderr.String())
	}
	if infos, _ := control.Discover(); len(infos) != 0 {
		t.Fatalf("control endpoint left behind after run: %+v", infos)
	}
}

func TestRunRegistersControlEndpoint(t *testing.T) {
	e := newRunEnv(t)
	if err := e.run([]string{"--mitm", "off", "--no-audit"}, "control"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.stdout.String(), "kind=run listen=127.0.0.1:") {
		t.Fatalf("child did not see a run control endpoint: %q", e.stdout.String())
	}
	if infos, _ := control.Discover(); len(infos) != 0 {
		t.Fatalf("control endpoint not removed: %+v", infos)
	}
}

func TestRunPrintEnvRequiresAttach(t *testing.T) {
	e := newRunEnv(t)
	err := e.run([]string{"--print-env"})
	if err == nil || !strings.Contains(err.Error(), "--print-env requires --attach") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunMissingCommand(t *testing.T) {
	e := newRunEnv(t)
	if err := e.run(nil); err == nil || !strings.Contains(err.Error(), "missing command") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunRefusesNesting(t *testing.T) {
	e := newRunEnv(t)
	t.Setenv("NEXUS_RUN", "1")
	err := e.run(nil, "exit", "0")
	if err == nil || !strings.Contains(err.Error(), "refusing to nest gates") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunInvalidFlags(t *testing.T) {
	e := newRunEnv(t)
	for _, f := range [][]string{{"--mitm", "maybe"}, {"--ttl", "0s"}, {"--approval-timeout", "0s"}} {
		if err := e.run(f, "exit", "0"); err == nil {
			t.Errorf("run %v: expected error", f)
		}
	}
}

// startAttachTarget serves a dev-like proxy signed by key, optionally intercepting with the CA in
// NEXUS_HOME.
func startAttachTarget(t *testing.T, key string, mitm bool) string {
	t.Helper()
	signer, err := jwt.LoadOrCreateSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := proxy.Config{RequireAuth: true, Verifier: signer.Verifier(), Engine: policy.NewEngine(policy.DefaultPolicy())}
	if mitm {
		dir, _ := ca.DefaultDir()
		if cfg.MITM, err = ca.LoadOrCreate(dir); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.New(cfg).Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String()
}

func TestRunAttachPrintEnv(t *testing.T) {
	e := newRunEnv(t)
	addr := startAttachTarget(t, e.key, true)
	t.Setenv("NEXUS_RUN", "1") // nesting is fine when attaching
	if err := e.run([]string{"--attach", addr, "--print-env"}); err != nil {
		t.Fatalf("print-env: %v; stderr=%s", err, e.stderr.String())
	}
	out := e.stdout.String()
	c, _ := ca.Load(filepath.Join(e.nexus, "ca"))
	for _, want := range []string{
		"export HTTPS_PROXY='http://nexus:",
		"@" + addr + "'\n",
		"export NO_PROXY='localhost,127.0.0.1,::1'\n",
		"export NEXUS_RUN='1'\n",
		"export SSL_CERT_FILE='" + c.BundlePath() + "'\n",
		"export NODE_EXTRA_CA_CERTS='" + c.CertPath() + "'\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("print-env missing %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(line, "export ") {
			t.Errorf("non-export line in print-env output: %q", line)
		}
	}
}

func TestRunAttachRunsChildThroughDev(t *testing.T) {
	e := newRunEnv(t)
	addr := startAttachTarget(t, e.key, false)
	got := e.childEnv("--attach", addr)
	if !strings.HasSuffix(got["HTTP_PROXY"], "@"+addr) {
		t.Fatalf("HTTP_PROXY = %q, want the attached proxy %s", got["HTTP_PROXY"], addr)
	}
	if _, ok := got["SSL_CERT_FILE"]; ok && got["SSL_CERT_FILE"] != os.Getenv("SSL_CERT_FILE") {
		t.Fatalf("CA vars set for a non-intercepting proxy: %v", got)
	}
}

func TestRunAttachRejectsForeignKeyAndMissingProxy(t *testing.T) {
	e := newRunEnv(t)
	addr := startAttachTarget(t, filepath.Join(e.dir, "other.key"), false)
	err := e.run([]string{"--attach", addr, "--print-env"})
	if err == nil || !strings.Contains(err.Error(), "different signing key") {
		t.Fatalf("foreign key: err = %v", err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	if err := e.run([]string{"--attach", dead, "--print-env"}); err == nil || !strings.Contains(err.Error(), "no nexus proxy") {
		t.Fatalf("dead proxy: err = %v", err)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"plain":       `'plain'`,
		"it's":        `'it'\''s'`,
		"$(rm -rf /)": `'$(rm -rf /)'`,
		"":            `''`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestMergeEnvOverrides(t *testing.T) {
	got := mergeEnv([]string{"PATH=/bin", "HTTP_PROXY=http://old", "KEEP=1"}, [][2]string{{"HTTP_PROXY", "http://new"}, {"NEXUS_RUN", "1"}})
	joined := strings.Join(got, ";")
	if strings.Contains(joined, "http://old") || !strings.Contains(joined, "HTTP_PROXY=http://new") ||
		!strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "KEEP=1") || !strings.Contains(joined, "NEXUS_RUN=1") {
		t.Fatalf("mergeEnv = %v", got)
	}
}

func TestPolicyScopesUnion(t *testing.T) {
	p := policy.Policy{Tools: []policy.Rule{{Scope: "write"}, {Scope: "read"}, {Scope: "write"}, {}}}
	if got := strings.Join(policyScopes(p), ","); got != "read,write" {
		t.Fatalf("policyScopes = %q", got)
	}
}

func TestRunHonoursAuditConfig(t *testing.T) {
	e := newRunEnv(t)
	var mu sync.Mutex
	var received []string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sink-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, string(body))
		mu.Unlock()
	}))
	defer sink.Close()
	t.Setenv("TEST_SINK_TOKEN", "sink-secret")

	logPath := filepath.Join(e.dir, "custom", "audit.jsonl")
	cfg := runTestPolicy + `audit:
  path: ` + logPath + `
  sign: true
  sinks:
    - type: webhook
      url: ` + sink.URL + `
      headers:
        Authorization: "Bearer ${TEST_SINK_TOKEN}"
`
	if err := os.WriteFile(e.policy, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.run([]string{"--mitm", "off"}, "fetch", "GET", "http://example.com/allowed", "http://example.com/denied"); err != nil {
		t.Fatalf("run: %v; stderr=%s", err, e.stderr.String())
	}

	if _, err := os.Stat(filepath.Join(e.nexus, "audit.jsonl")); err == nil {
		t.Fatal("audit written to the default path despite audit.path")
	}
	pub, err := audit.LoadPublicKeys(filepath.Join(e.nexus, "audit.pub"))
	if err != nil {
		t.Fatalf("audit.pub: %v", err)
	}
	res, err := audit.VerifyWithOptions(logPath, audit.VerifyOptions{PublicKeys: pub, RequireSigned: true})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Entries != 2 || !res.SigsChecked || res.Signed != 2 {
		t.Fatalf("verify result = %+v", res)
	}
	// Close() on shutdown must have flushed the webhook batch.
	mu.Lock()
	defer mu.Unlock()
	all := strings.Join(received, "\n")
	if !strings.Contains(all, "example.com/allowed") || !strings.Contains(all, "example.com/denied") {
		t.Fatalf("webhook received %q", all)
	}
}
