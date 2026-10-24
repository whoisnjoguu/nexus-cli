package policy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
)

type memAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (m *memAudit) Log(e audit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

func (m *memAudit) all() []audit.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]audit.Entry(nil), m.entries...)
}

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

func strictLoad(data []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, err
	}
	return p, Check(p)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

const (
	polAllowX = "tools:\n  - match: {tool: x}\n    action: allow\n"
	polDenyX  = "tools:\n  - match: {tool: x}\n    action: deny\n"
)

func newTestWatcher(t *testing.T, initial string) (*Watcher, *Engine, string, *memAudit, *syncBuf) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := strictLoad([]byte(initial))
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(p)
	al, errb := &memAudit{}, &syncBuf{}
	w := NewWatcher(WatcherConfig{Path: path, Engine: e, Load: strictLoad, InitialSum: Sum([]byte(initial)),
		Interval: 10 * time.Millisecond, Audit: al, Stderr: errb})
	t.Cleanup(w.Close)
	return w, e, path, al, errb
}

func toolAction(e *Engine, tool string) Action {
	return e.Evaluate(Request{SessionID: "s", Tool: tool}).Action
}

func TestWatcherReloadsOnChange(t *testing.T) {
	w, e, path, al, errb := newTestWatcher(t, polAllowX)
	w.Start()
	if toolAction(e, "x") != ActionAllow {
		t.Fatal("initial policy not applied")
	}
	if err := os.WriteFile(path, []byte(polDenyX), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "reload", func() bool { return toolAction(e, "x") == ActionDeny })
	waitFor(t, "audit", func() bool { return len(al.all()) == 1 })
	ent := al.all()[0]
	if ent.Tool != "policy/reload" || ent.Decision != "allow" || ent.Target != path+"#sha256:"+ShortSum(Sum([]byte(polDenyX))) {
		t.Fatalf("audit entry = %+v", ent)
	}
	if !strings.Contains(errb.String(), "[nexus] policy reloaded from") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestWatcherKeepsOldPolicyOnInvalidChange(t *testing.T) {
	w, e, path, al, errb := newTestWatcher(t, polAllowX)
	w.Start()
	bad := "tools:\n  - match: {tool: x}\n    action: alow\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "failure audit", func() bool { return len(al.all()) == 1 })
	ent := al.all()[0]
	if ent.Decision != "deny" || !strings.Contains(ent.Reason, "unknown action") || !strings.HasSuffix(ent.Target, ShortSum(Sum([]byte(bad)))) {
		t.Fatalf("audit = %+v", ent)
	}
	if !strings.Contains(errb.String(), "[nexus] policy reload failed:") {
		t.Fatalf("stderr = %q", errb.String())
	}
	if toolAction(e, "x") != ActionAllow {
		t.Fatal("old policy not kept")
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(al.all()); n != 1 {
		t.Fatalf("failure reported %d times, want once", n)
	}
	// Unknown keys are rejected too.
	if err := os.WriteFile(path, []byte(polAllowX+"bogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "second failure", func() bool { return len(al.all()) == 2 })
	if toolAction(e, "x") != ActionAllow {
		t.Fatal("old policy not kept after unknown key")
	}
	// Deleting the file keeps the policy as well.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "missing report", func() bool { return len(al.all()) == 3 })
	if toolAction(e, "x") != ActionAllow {
		t.Fatal("old policy not kept after delete")
	}
}

func TestWatcherDepChangeRetriesRejectedContent(t *testing.T) {
	dir := t.TempDir()
	path, gate := filepath.Join(dir, "nexus.yaml"), filepath.Join(dir, "gate")
	if err := os.WriteFile(path, []byte(polAllowX), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Policy{})
	load := func(data []byte) (Policy, error) {
		if _, err := os.Stat(gate); err != nil {
			return Policy{}, errors.New("not approved")
		}
		return strictLoad(data)
	}
	w := NewWatcher(WatcherConfig{Path: path, Engine: e, Load: load, Deps: []string{gate}, Interval: 10 * time.Millisecond, Stderr: &syncBuf{}})
	t.Cleanup(w.Close)
	w.Start()
	time.Sleep(50 * time.Millisecond)
	if toolAction(e, "x") == ActionAllow {
		t.Fatal("loaded unapproved content")
	}
	if err := os.WriteFile(gate, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "retry after dep change", func() bool { return toolAction(e, "x") == ActionAllow })
}

func TestSetPolicySemantics(t *testing.T) {
	p := Policy{EscalateWhenTainted: true, Egress: Egress{Allow: []string{"ok.example"}}, Tools: []Rule{
		{Match: Match{Tool: "read_db"}, Action: ActionAllow, Taints: []string{"db"}},
		{Match: Match{Tool: "pay"}, Action: ActionAllow, OneTime: true},
		{Match: Match{Tool: "write"}, Action: ActionHITL},
		{Match: Match{Method: "POST"}, Action: ActionAllow},
	}}
	e := NewEngine(p)
	s := "agent|user"
	e.Evaluate(Request{SessionID: s, Tool: "read_db"})
	if d := e.Evaluate(Request{SessionID: s, Tool: "pay"}); d.Action != ActionAllow {
		t.Fatal(d)
	}
	wreq := Request{SessionID: s, Tool: "write"}
	e.GrantSession(wreq, e.Evaluate(wreq))
	if !e.SessionGranted(wreq) {
		t.Fatal("grant not recorded")
	}

	p2 := p
	p2.Tools = append([]Rule(nil), p.Tools...)
	p2.Tools = append(p2.Tools, Rule{Match: Match{Tool: "pay2"}, Action: ActionAllow, OneTime: true})
	p2.DefaultAction = ""
	e.SetPolicy(p2)

	if e.Policy().DefaultAction != ActionDeny {
		t.Fatal("SetPolicy did not default the action")
	}
	if e.SessionGranted(wreq) {
		t.Fatal("session grants must be cleared on reload")
	}
	if d := e.Evaluate(Request{SessionID: s, Tool: "pay"}); d.Action != ActionDeny {
		t.Fatalf("one_time consumption lost across reload: %s", d.Action)
	}
	if d := e.Evaluate(Request{SessionID: s, Method: "POST", Host: "evil.example", Path: "/"}); !d.TaintEscalated {
		t.Fatalf("taint lost across reload: %+v", d)
	}
	if d := e.Evaluate(Request{SessionID: s, Tool: "pay2"}); d.Action != ActionAllow {
		t.Fatalf("new one_time rule = %s", d.Action)
	}
}

func TestWatcherAbsentAtStartIsSilentThenLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nexus.yaml")
	e := NewEngine(Policy{})
	al, errb := &memAudit{}, &syncBuf{}
	w := NewWatcher(WatcherConfig{Path: path, Engine: e, Load: strictLoad, Interval: 10 * time.Millisecond, Audit: al, Stderr: errb})
	t.Cleanup(w.Close)
	w.Start()
	time.Sleep(60 * time.Millisecond)
	if n := len(al.all()); n != 0 || errb.String() != "" {
		t.Fatalf("absent-at-start file reported: %d entries, stderr %q", n, errb.String())
	}
	if toolAction(e, "x") == ActionAllow {
		t.Fatal("empty policy allowed x")
	}
	if err := os.WriteFile(path, []byte(polAllowX), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "load after create", func() bool { return toolAction(e, "x") == ActionAllow })
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "missing report", func() bool {
		return strings.Contains(errb.String(), "is missing or unreadable (keeping the current policy)")
	})
	if strings.Contains(errb.String(), "keeping the current policy; keeping") {
		t.Fatalf("duplicated suffix: %q", errb.String())
	}
}
