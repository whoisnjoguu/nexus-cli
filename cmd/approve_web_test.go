package cmd

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

var loginURLRe = regexp.MustCompile(`http://127\.0\.0\.1:\d+/ui#login=([0-9a-f]+)`)

func stubBrowser(t *testing.T, err error) *[]string {
	t.Helper()
	var opened []string
	old := openBrowser
	openBrowser = func(u string) error { opened = append(opened, u); return err }
	t.Cleanup(func() { openBrowser = old })
	return &opened
}

func TestApproveWebNoOpen(t *testing.T) {
	s, _ := startApproveEndpoint(t)
	opened := stubBrowser(t, nil)
	out, err := runApprove(t, "--web", "--no-open")
	if err != nil {
		t.Fatal(err)
	}
	m := loginURLRe.FindStringSubmatch(out)
	if m == nil || !strings.Contains(m[0], s.Info().Addr) || !strings.Contains(out, "dev · pid") {
		t.Fatalf("output: %q", out)
	}
	if len(*opened) != 0 {
		t.Fatal("--no-open must not open a browser")
	}
	// The printed code is a valid one-time login code for that endpoint.
	req, _ := http.NewRequest("POST", "http://"+s.Info().Addr+"/v1/ui/session", strings.NewReader(`{"code":"`+m[1]+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+s.Info().Addr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 1 {
		t.Fatalf("session exchange: %d", resp.StatusCode)
	}
}

func TestApproveWebOpensBrowser(t *testing.T) {
	startApproveEndpoint(t)
	opened := stubBrowser(t, nil)
	out, err := runApprove(t, "--web")
	if err != nil || len(*opened) != 1 || !loginURLRe.MatchString((*opened)[0]) || !strings.Contains(out, "opened in your browser") {
		t.Fatalf("%q %v %v", out, *opened, err)
	}
	opened = stubBrowser(t, errors.New("no display"))
	out, err = runApprove(t, "--web")
	if err != nil || !strings.Contains(out, "could not open a browser (no display)") || !loginURLRe.MatchString(out) {
		t.Fatalf("%q %v", out, err)
	}
}

func TestApproveWebSelection(t *testing.T) {
	s1, _ := startApproveEndpoint(t) // sets NEXUS_HOME
	b2 := hitl.NewBroker(time.Minute)
	s2, err := control.Start(b2, control.Info{Kind: "mcp"})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	stubBrowser(t, nil)

	// Both endpoints are in this process, so they share a PID; --pid matches the first one found.
	if _, err := runApprove(t, "--web", "--no-open", "--pid", "999999"); err == nil || !strings.Contains(err.Error(), "no running endpoint with pid 999999") {
		t.Fatalf("bad pid: %v", err)
	}
	out, err := runApprove(t, "--web", "--no-open", "--pid", strconv.Itoa(s1.Info().PID))
	if err != nil || !loginURLRe.MatchString(out) {
		t.Fatalf("%q %v", out, err)
	}

	// Without --pid: the endpoint with the oldest pending request wins.
	queue(t, b2, hitl.Request{ID: "p", Created: time.Now().Add(-time.Hour)})
	out, err = runApprove(t, "--web", "--no-open")
	if err != nil || !strings.Contains(out, "2 endpoints running") || !strings.Contains(out, s2.Info().Addr) {
		t.Fatalf("%q %v", out, err)
	}
	_ = b2.Decide("p", hitl.Deny)

	infos, _ := control.Discover()
	if got, _ := pickWebEndpoint(context.Background(), infos, 0); got.Addr != infos[len(infos)-1].Addr {
		t.Fatal("without pending requests the newest endpoint should be used")
	}
}

func TestApproveWebErrors(t *testing.T) {
	t.Setenv("NEXUS_HOME", t.TempDir())
	if _, err := runApprove(t, "--web", "--no-open"); err == nil || !strings.Contains(err.Error(), "no running nexus-cli endpoints") {
		t.Fatalf("no endpoints: %v", err)
	}
	for _, args := range [][]string{{"--web", "--list"}, {"--web", "abc", "--decision", "once"}, {"--no-open"}, {"--pid", "1"}} {
		if _, err := runApprove(t, args...); err == nil {
			t.Fatalf("%v should fail", args)
		}
	}
}

func TestBrowserCommand(t *testing.T) {
	u := "http://127.0.0.1:1/ui#login=abc"
	for goos, want := range map[string]string{
		"linux":   "xdg-open " + u,
		"darwin":  "open " + u,
		"windows": "rundll32 url.dll,FileProtocolHandler " + u,
		"plan9":   "",
	} {
		name, args := browserCommand(goos, u)
		if got := strings.TrimSpace(name + " " + strings.Join(args, " ")); got != want {
			t.Errorf("%s: %q", goos, got)
		}
	}
}

func TestWatchModelBell(t *testing.T) {
	_, b := startApproveEndpoint(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newWatchModel(ctx, control.Discover)
	defer m.closeAll()
	rings := 0
	m.bell = func() { rings++ }

	infos, _ := control.Discover()
	tm, _ := m.Update(watchDiscoveredMsg{infos: infos})
	m = tm.(watchModel)
	key := endpointKey(infos[0])
	poll := func() {
		t.Helper()
		tm, _ := m.Update(m.pollCmd(key, m.eps[key], 0, 0)())
		m = tm.(watchModel)
	}

	poll()
	if rings != 0 {
		t.Fatal("empty queue must not ring")
	}
	queue(t, b, hitl.Request{ID: "r1"})
	poll()
	if rings != 1 {
		t.Fatalf("new request: %d rings", rings)
	}
	poll()
	if rings != 1 {
		t.Fatal("same request must not ring again")
	}
	queue(t, b, hitl.Request{ID: "r2"})
	poll()
	if rings != 2 {
		t.Fatalf("second request: %d rings", rings)
	}

	// A failed (non-404) decision keeps the request visible for a retry.
	tm, _ = m.Update(watchDecidedMsg{key: key, id: "r1", d: hitl.Once, err: errors.New("connection reset")})
	m = tm.(watchModel)
	if len(m.eps[key].pending) != 2 {
		t.Fatal("request dropped after a failed decision")
	}
	tm, _ = m.Update(watchDecidedMsg{key: key, id: "r1", d: hitl.Once, err: hitl.ErrUnknownRequest})
	m = tm.(watchModel)
	if len(m.eps[key].pending) != 1 {
		t.Fatal("already-decided request should be dropped")
	}
	_ = b.Decide("r1", hitl.Deny)
	_ = b.Decide("r2", hitl.Deny)
}
