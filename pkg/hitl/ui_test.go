package hitl

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func key(s string) tea.KeyMsg {
	if s == "ctrl+c" {
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestModelKeys(t *testing.T) {
	cases := map[string]Decision{"y": Once, "s": Session, "a": Always, "n": Deny, "q": Deny, "ctrl+c": Deny, "A": Always}
	for k, want := range cases {
		ch := make(chan Decision, 1)
		m, cmd := NewModel(ApprovalRequest{ResponseCh: ch}).Update(key(k))
		if cmd == nil {
			t.Fatalf("%s: expected quit cmd", k)
		}
		if d, ok := m.(Model).Decision(); !ok || d != want {
			t.Fatalf("%s: got %v,%v", k, d, ok)
		}
		if d := <-ch; d != want {
			t.Fatalf("%s: channel got %v", k, d)
		}
	}
	// Unrelated keys do nothing.
	m, cmd := NewModel(ApprovalRequest{}).Update(key("x"))
	if _, ok := m.(Model).Decision(); ok || cmd != nil {
		t.Fatal("x should be ignored")
	}
}

func TestModelAnswerDoesNotBlockWithoutReader(t *testing.T) {
	ch := make(chan Decision) // unbuffered, nobody reading
	done := make(chan struct{})
	go func() {
		NewModel(ApprovalRequest{ResponseCh: ch}).Update(key("y"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("answer blocked on ResponseCh")
	}
	// A late reader still gets the decision.
	select {
	case d := <-ch:
		if d != Once {
			t.Fatalf("got %v", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("decision never delivered")
	}
}

func TestModelAbortAndTimeout(t *testing.T) {
	m, _ := NewModel(ApprovalRequest{}).Update(abortMsg{})
	if d, ok := m.(Model).Decision(); !ok || d != Deny {
		t.Fatal("abort should deny")
	}
	if !strings.Contains(m.View(), "withdrawn") {
		t.Fatalf("view: %q", m.View())
	}
	m, _ = NewModel(ApprovalRequest{}).Update(abortMsg{timedOut: true})
	if !strings.Contains(m.View(), "Timed out") {
		t.Fatalf("view: %q", m.View())
	}
	// Abort after an answer keeps the answer.
	m, _ = NewModel(ApprovalRequest{}).Update(key("s"))
	m, _ = m.Update(abortMsg{})
	if d, _ := m.(Model).Decision(); d != Session {
		t.Fatalf("got %v", d)
	}
	// Keys after an answer are ignored.
	m, _ = m.Update(key("n"))
	if d, _ := m.(Model).Decision(); d != Session {
		t.Fatalf("got %v", d)
	}

	now := time.Now()
	tm := NewModel(ApprovalRequest{})
	tm.deadline = now.Add(10 * time.Second)
	tm.now = func() time.Time { return now }
	if tm.Init() == nil {
		t.Fatal("deadline prompt should tick")
	}
	if !strings.Contains(tm.View(), "auto-deny in 10s") {
		t.Fatalf("view: %q", tm.View())
	}
	r, cmd := tm.Update(tickMsg(now))
	if _, ok := r.(Model).Decision(); ok || cmd == nil {
		t.Fatal("tick before deadline should reschedule")
	}
	tm.now = func() time.Time { return now.Add(11 * time.Second) }
	r, _ = tm.Update(tickMsg(now))
	if d, ok := r.(Model).Decision(); !ok || d != Deny || !strings.Contains(r.View(), "Timed out") {
		t.Fatal("tick past deadline should deny")
	}
	if NewModel(ApprovalRequest{}).Init() != nil {
		t.Fatal("classic prompt should not tick")
	}
}

func TestViewContent(t *testing.T) {
	m := NewModel(ApprovalRequest{AgentID: "ag", ActAsUser: "bob", ToolName: "tool", TargetURI: "tgt", Reason: "why",
		Params: "\x1b[31mred\x1b[0m" + strings.Repeat("x", 1000)})
	m.pending = func() int { return 3 }
	v := m.View()
	for _, s := range []string{"ag", "bob", "tool", "tgt", "why", "3 more pending", "…", "[Y] once"} {
		if !strings.Contains(v, s) {
			t.Errorf("view missing %q", s)
		}
	}
	if strings.Contains(v, "\x1b[31mred") {
		t.Error("escape sequence from params not sanitized")
	}
	if strings.Count(v, "x") > MaxParamsDisplay+5 {
		t.Error("params not truncated")
	}
}

func TestSanitizeTruncate(t *testing.T) {
	if got := Sanitize("a\nb\x1bc\td"); got != "a b c d" {
		t.Fatalf("got %q", got)
	}
	if got := Truncate("héllo", 2); got != "hé…" {
		t.Fatalf("got %q", got)
	}
	if got := Truncate("hi", 5); got != "hi" {
		t.Fatalf("got %q", got)
	}
}

func TestRenderPromptMeta(t *testing.T) {
	v := RenderPrompt(Request{Tool: "t"}, PromptView{Source: "dev · pid 1", Age: 3 * time.Second, Pending: 1})
	for _, s := range []string{"dev · pid 1", "waiting 3s", "1 more pending"} {
		if !strings.Contains(v, s) {
			t.Errorf("missing %q in %q", s, v)
		}
	}
}
