package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

func startApproveEndpoint(t *testing.T) (*control.Server, *hitl.Broker) {
	t.Helper()
	t.Setenv("NEXUS_HOME", t.TempDir())
	b := hitl.NewBroker(time.Minute)
	s, err := control.Start(b, control.Info{Kind: "dev", CWD: "/work/repo"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, b
}

func queue(t *testing.T, b *hitl.Broker, req hitl.Request) <-chan hitl.Decision {
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

func runApprove(t *testing.T, args ...string) (string, error) {
	t.Helper()
	c := newApproveCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetArgs(args)
	err := c.Execute()
	return out.String(), err
}

func TestApproveListNoEndpoints(t *testing.T) {
	t.Setenv("NEXUS_HOME", t.TempDir())
	out, err := runApprove(t, "--list")
	if err != nil || !strings.Contains(out, "no running nexus-cli endpoints") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestApproveList(t *testing.T) {
	s, b := startApproveEndpoint(t)
	out, err := runApprove(t, "--list")
	if err != nil || !strings.Contains(out, "no pending approval requests") {
		t.Fatalf("%q %v", out, err)
	}
	queue(t, b, hitl.Request{ID: "req-1", AgentID: "agent-x", ActAsUser: "alice", Tool: "tools/call", Target: "fs.write", Reason: "high risk"})
	queue(t, b, hitl.Request{ID: "req-2", Tool: "tools/call", Target: "fs.delete"})
	out, err = runApprove(t, "--list")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"ID", "TARGET", "req-1", "agent-x", "alice", "fs.write", "high risk", "req-2", "fs.delete", "dev/"} {
		if !strings.Contains(out, s) {
			t.Errorf("list output missing %q:\n%s", s, out)
		}
	}
	if strings.Index(out, "req-1") > strings.Index(out, "req-2") {
		t.Errorf("not oldest first:\n%s", out)
	}
	if strings.Contains(out, s.Info().Token) {
		t.Error("token leaked in output")
	}
	_ = b.Decide("req-1", hitl.Deny)
	_ = b.Decide("req-2", hitl.Deny)
}

func TestApproveDecide(t *testing.T) {
	_, b := startApproveEndpoint(t)
	for _, tc := range []struct {
		flag string
		want hitl.Decision
	}{{"once", hitl.Once}, {"session", hitl.Session}, {"always", hitl.Always}, {"deny", hitl.Deny}} {
		got := queue(t, b, hitl.Request{ID: "id-" + tc.flag})
		out, err := runApprove(t, "id-"+tc.flag, "--decision", tc.flag)
		if err != nil {
			t.Fatalf("%s: %v", tc.flag, err)
		}
		if !strings.Contains(out, "id-"+tc.flag) || !strings.Contains(out, tc.flag) {
			t.Fatalf("output %q", out)
		}
		if d := <-got; d != tc.want {
			t.Fatalf("%s: got %v", tc.flag, d)
		}
	}
}

func TestApproveDecideErrors(t *testing.T) {
	_, b := startApproveEndpoint(t)
	got := queue(t, b, hitl.Request{ID: "abc"})

	cases := [][]string{
		{"abc"},                          // missing --decision
		{"abc", "--decision", "y"},       // lenient alias rejected
		{"abc", "--decision", "yes"},     // lenient alias rejected
		{"abc", "--decision", "ONCE"},    // case-sensitive
		{"--decision", "once"},           // no id
		{"--list", "abc"},                // conflicting
		{"--list", "--decision", "once"}, // conflicting
		{"a", "b", "--decision", "once"}, // too many args
	}
	for _, args := range cases {
		if _, err := runApprove(t, args...); err == nil {
			t.Fatalf("%v: expected error", args)
		}
	}
	if _, err := runApprove(t, "missing", "--decision", "once"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown id: %v", err)
	}
	if len(b.Pending()) != 1 {
		t.Fatal("invalid invocations must not decide")
	}
	if _, err := runApprove(t, "abc", "--decision", "deny"); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d != hitl.Deny {
		t.Fatalf("got %v", d)
	}
}

func TestApproveCommandRegistered(t *testing.T) {
	c, _, err := rootCmd.Find([]string{"approve"})
	if err != nil || c.Name() != "approve" {
		t.Fatalf("approve not registered: %v", err)
	}
}

func TestWatchModel(t *testing.T) {
	s, b := startApproveEndpoint(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := newWatchModel(ctx, control.Discover)
	defer m.closeAll()
	if v := m.View(); !strings.Contains(v, "waiting for approval requests… (q to quit)") {
		t.Fatalf("idle view: %q", v)
	}

	infos, err := control.Discover()
	if err != nil || len(infos) != 1 {
		t.Fatal(infos, err)
	}
	tm, cmd := m.Update(watchDiscoveredMsg{infos: infos})
	m = tm.(watchModel)
	if cmd == nil || len(m.eps) != 1 {
		t.Fatal("endpoint not added")
	}
	key := endpointKey(infos[0])
	ep := m.eps[key]

	got := queue(t, b, hitl.Request{ID: "older", Tool: "tools/call", Target: "fs.write", Created: time.Now().Add(-time.Minute)})
	queue(t, b, hitl.Request{ID: "newer", Target: "fs.read"})

	// Execute the endpoint's first poll against the live server.
	msg := m.pollCmd(key, ep, 0, 0)()
	tm, _ = m.Update(msg)
	m = tm.(watchModel)
	v := m.View()
	for _, want := range []string{"fs.write", "1 more pending", "dev · pid", "/work/repo", "request older"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}

	// Unknown keys and stale poll generations are ignored.
	if _, c := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")}); c != nil {
		t.Fatal("x should do nothing")
	}
	tm, _ = m.Update(watchPolledMsg{key: key, gen: ep.gen - 1})
	m = tm.(watchModel)
	if len(m.eps[key].pending) != 2 {
		t.Fatal("stale poll applied")
	}

	tm, cmd = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")})
	m = tm.(watchModel)
	if cmd == nil || !m.busy {
		t.Fatal("decision not sent")
	}
	// While busy, further keys are ignored.
	if _, c := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")}); c != nil {
		t.Fatal("double decision while busy")
	}
	tm, _ = m.Update(cmd())
	m = tm.(watchModel)
	if d := <-got; d != hitl.Session {
		t.Fatalf("got %v", d)
	}
	if !strings.Contains(m.View(), "older → session") || !strings.Contains(m.View(), "fs.read") {
		t.Fatalf("view after decision:\n%s", m.View())
	}

	// Endpoint disappears from discovery.
	_ = b.Decide("newer", hitl.Deny)
	s.Close()
	tm, _ = m.Update(watchDiscoveredMsg{})
	m = tm.(watchModel)
	if len(m.eps) != 0 || !strings.Contains(m.View(), "waiting for approval requests") {
		t.Fatal("endpoint not removed")
	}

	if _, c := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}); c == nil {
		t.Fatal("q should quit")
	}
}
