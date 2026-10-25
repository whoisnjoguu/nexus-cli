package sdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/gate"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

type daemon struct {
	srv    *control.Server
	broker *hitl.Broker
	signer *jwt.TokenSigner
}

func startDaemon(t *testing.T, kind string) *daemon {
	t.Helper()
	b := hitl.NewBroker(5 * time.Second)
	srv, err := control.Start(b, control.Info{Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	signer, err := jwt.NewTokenSigner()
	if err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(gate.Config{
		Engine: policy.NewEngine(policy.Policy{
			DefaultAction: policy.ActionDeny,
			Tools: []policy.Rule{
				{Match: policy.Match{Tool: "read"}, Action: policy.ActionAllow},
				{Match: policy.Match{Tool: "write", Args: map[string]string{"path": "/w/**"}}, Action: policy.ActionAllow},
				{Match: policy.Match{Tool: "write"}, Action: policy.ActionHITL},
				{Match: policy.Match{Method: "GET"}, Action: policy.ActionAllow},
			},
		}),
		Approver: b,
		Verifier: signer.Verifier(),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.SetChecker(g)
	return &daemon{srv: srv, broker: b, signer: signer}
}

func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("NEXUS_HOME", t.TempDir())
	for _, k := range []string{EnvControlURL, EnvControlToken, EnvToken, EnvProxyURL} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestClientCheckRequire(t *testing.T) {
	isolate(t)
	d := startDaemon(t, "dev")
	c, err := Connect(ConnectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()

	res, err := c.Check(ctx, CheckRequest{Tool: "read"})
	if err != nil || !res.Allowed() || res.Source != "policy" {
		t.Fatalf("read: %+v %v", res, err)
	}
	if err := c.Require(ctx, CheckRequest{Tool: "write", Args: []byte(`{"path":"/w/a"}`)}); err != nil {
		t.Fatalf("write in /w: %v", err)
	}
	err = c.Require(ctx, CheckRequest{Tool: "delete"})
	var de *DeniedError
	if !errors.As(err, &de) || de.Response.Decision != "deny" || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("require deny: %v", err)
	}

	// HITL: pending, visible in Approvals, decided, then polled.
	res, err = c.Check(ctx, CheckRequest{Tool: "write", Wait: "0"})
	if err != nil || res.Decision != "pending" {
		t.Fatalf("pending: %+v %v", res, err)
	}
	ap, err := c.Approvals(ctx)
	if err != nil || len(ap) != 1 || ap[0].ID != res.ApprovalID {
		t.Fatalf("approvals: %+v %v", ap, err)
	}
	if err := c.Decide(ctx, res.ApprovalID, hitl.Once); err != nil {
		t.Fatal(err)
	}
	got, err := c.Poll(ctx, res.ApprovalID, 2*time.Second)
	if err != nil || !got.Allowed() || got.Reason != "approved once" {
		t.Fatalf("poll: %+v %v", got, err)
	}

	// Blocking HITL denied by a human.
	go func() {
		for len(d.broker.Pending()) == 0 {
			time.Sleep(2 * time.Millisecond)
		}
		_ = d.broker.Decide(d.broker.Pending()[0].ID, hitl.Deny)
	}()
	if err := c.Require(ctx, CheckRequest{Tool: "write"}); !errors.As(err, &de) || de.Response.Source != "approve" {
		t.Fatalf("hitl deny: %v", err)
	}

	st, err := c.Status(ctx)
	if err != nil || st.Kind != "dev" || st.Token != "" {
		t.Fatalf("status: %+v %v", st, err)
	}
}

func TestClientAsGate(t *testing.T) {
	isolate(t)
	startDaemon(t, "run")
	c, err := Connect(ConnectOptions{Kind: "run"})
	if err != nil {
		t.Fatal(err)
	}
	if dec, err := c.Authorize(context.Background(), ToolCall{Tool: "write", Args: map[string]any{"path": "/w/x"}}); err != nil || !dec.Allowed {
		t.Fatalf("authorize: %+v %v", dec, err)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer up.Close()
	hc := &http.Client{Transport: &GateTransport{Gate: c, Agent: "a"}}
	resp, err := hc.Get(up.URL + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	req, _ := http.NewRequest(http.MethodPost, up.URL+"/x", nil)
	if _, err := hc.Do(req); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("POST should be denied: %v", err)
	}
}

func TestConnectDiscovery(t *testing.T) {
	isolate(t)
	if _, err := Connect(ConnectOptions{}); !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("no daemon: %v", err)
	}
	dev := startDaemon(t, "dev")
	time.Sleep(10 * time.Millisecond)
	mcp := startDaemon(t, "mcp")

	c, err := Connect(ConnectOptions{})
	if err != nil || c.Info().Addr != mcp.srv.Info().Addr {
		t.Fatalf("newest: %+v %v", c, err)
	}
	if c, err := Connect(ConnectOptions{Kind: "dev"}); err != nil || c.Info().Addr != dev.srv.Info().Addr {
		t.Fatalf("kind: %v", err)
	}
	if _, err := Connect(ConnectOptions{Kind: "run"}); !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("kind run: %v", err)
	}
	if _, err := Connect(ConnectOptions{PID: os.Getpid() + 1}); !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("pid: %v", err)
	}

	// A stale discovery file (nothing listening) is skipped.
	dir, _ := control.Dir()
	stale := `{"pid":1,"addr":"127.0.0.1:1","token":"x","kind":"dev","started":"2999-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "1-dead.json"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := Connect(ConnectOptions{Kind: "dev"}); err != nil || c.Info().Addr != dev.srv.Info().Addr {
		t.Fatalf("stale: %v", err)
	}

	// Environment wins over files and carries the agent token.
	tok, _ := dev.signer.Mint(jwt.MintOptions{AgentID: "env-bot", UserID: "u", TTL: time.Minute})
	t.Setenv(EnvControlURL, "http://"+dev.srv.Info().Addr)
	t.Setenv(EnvControlToken, dev.srv.Info().Token)
	t.Setenv(EnvProxyURL, "http://nexus:"+tok+"@127.0.0.1:9")
	c, err = Connect(ConnectOptions{Kind: "mcp"})
	if err != nil || c.Info().Addr != dev.srv.Info().Addr || c.Token != tok {
		t.Fatalf("env: %+v %v", c, err)
	}
	if res, err := c.Check(context.Background(), CheckRequest{Tool: "read"}); err != nil || !res.Allowed() {
		t.Fatalf("env check: %+v %v", res, err)
	}
	t.Setenv(EnvControlToken, "")
	if _, err := Connect(ConnectOptions{}); err == nil {
		t.Fatal("URL without token should fail")
	}
	t.Setenv(EnvControlToken, "x")
	t.Setenv(EnvControlURL, "ftp://x")
	if _, err := Connect(ConnectOptions{}); err == nil {
		t.Fatal("bad URL should fail")
	}
	t.Setenv(EnvControlURL, "http://"+dev.srv.Info().Addr)
	c, _ = Connect(ConnectOptions{})
	if _, err := c.Check(context.Background(), CheckRequest{Tool: "read"}); !errors.Is(err, control.ErrUnauthorized) {
		t.Fatalf("bad control token: %v", err)
	}
}
