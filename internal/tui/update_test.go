package tui

import (
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "ctrl+s":
		return tea.KeyMsg{Type: tea.KeyCtrlS}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// press feeds keys to the model, rendering after each one so View is exercised in every state.
func press(t *testing.T, m model, keys ...string) (model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	for _, k := range keys {
		var tm tea.Model
		tm, cmd = m.Update(key(k))
		m = tm.(model)
		if m.View() == "" {
			t.Fatalf("empty view after %q", k)
		}
	}
	return m, cmd
}

func typeText(t *testing.T, m model, s string) model {
	t.Helper()
	for _, r := range s {
		m, _ = press(t, m, string(r))
	}
	return m
}

func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func TestEditorKeyFlow(t *testing.T) {
	m := newModel(Options{
		Policy: policy.Policy{Agent: "a", Egress: policy.Egress{Allow: []string{"one.com", "two.com"}}},
		Providers: []principal.ProviderInfo{
			{Name: "github", AuthType: "oauth2", Scopes: []string{"repo", "read:user"}},
			{Name: "slack", AuthType: "oauth2"},
		},
	})
	if m.Init() != nil {
		t.Fatal("Init returned a command")
	}
	tm, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = tm.(model)

	// Providers: allow github with the second scope, cycle its credential to deny; deny slack with a hitl credential.
	m, _ = press(t, m, "a", "enter", "down", "space", "esc", "c", "c", "c", "down", "d", "c", "q")
	if m.scopeMode {
		t.Fatal("q did not leave scope mode")
	}
	m, _ = press(t, m, "up", "h", "down", "down", "down")

	// Tools: add two rules, set actions, delete the first.
	m, _ = press(t, m, "tab", "n")
	m = typeText(t, m, "fs__write*")
	m, _ = press(t, m, "enter", "d", "n")
	m = typeText(t, m, "net__*")
	m, _ = press(t, m, "enter", "down", "a", "n")
	m = typeText(t, m, "discarded")
	m, _ = press(t, m, "esc", "n", "enter", "up", "x", "h")

	// Egress: add a host and remove the first entry.
	m, _ = press(t, m, "tab", "n")
	m = typeText(t, m, "three.com")
	m, _ = press(t, m, "enter", "x", "down", "down", "down", "up")

	// Defaults: hitl default, escalate toggled; keys on the wrong row do nothing.
	m, _ = press(t, m, "tab", "h", "down", "a", "space", "down", "up")
	if !m.dirty {
		t.Fatal("edits did not mark the model dirty")
	}
	m, _ = press(t, m, "tab", "shift+tab", "shift+tab", "tab")
	if m.section != secDefaults {
		t.Fatalf("section = %d", m.section)
	}

	m, cmd := press(t, m, "ctrl+s")
	if !m.saved || !isQuit(cmd) {
		t.Fatal("ctrl+s did not save and quit")
	}
	got := m.build()
	want := policy.Policy{
		Agent:               "a",
		Egress:              policy.Egress{Allow: []string{"two.com", "three.com"}},
		DefaultAction:       policy.ActionHITL,
		EscalateWhenTainted: true,
		Tools:               []policy.Rule{{Match: policy.Match{Tool: "net__*"}, Action: policy.ActionHITL}},
		Providers: map[string]policy.ProviderRule{
			"github": {Access: policy.ActionHITL, Credential: policy.ActionDeny, Scopes: []string{"read:user"}},
			"slack":  {Access: policy.ActionDeny, Credential: policy.ActionHITL},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("built policy\n got %+v\nwant %+v", got, want)
	}
	if err := policy.Check(got); err != nil {
		t.Fatalf("editor produced an invalid policy: %v", err)
	}
}

func TestEditorQuitWithoutSaving(t *testing.T) {
	m := newModel(Options{})
	m, cmd := press(t, m, "a", "x", "ctrl+c")
	if m.saved || !isQuit(cmd) {
		t.Fatal("ctrl+c must quit without saving")
	}
	if !strings.Contains(m.View(), "Providers") {
		t.Fatal("view lacks the section rail")
	}
}

// Saving from the editor must not widen the policy: tool rules keep their constraints and every
// rule keeps its first-match position.
func TestBuildPreservesRuleFieldsAndOrder(t *testing.T) {
	in := policy.Policy{
		Egress: policy.Egress{Allow: []string{"a.com"}, Passthrough: []string{"pinned.example.com"}},
		Tools: []policy.Rule{
			{Match: policy.Match{Tool: "fs__write_file", Args: map[string]string{"path": "/srv/**"}}, Action: policy.ActionAllow, OneTime: true},
			{Match: policy.Match{Provider: "github"}, Action: policy.ActionDeny},
			{Match: policy.Match{Tool: "fs__read*"}, Action: policy.ActionAllow, Scope: "fs:read", Taints: []string{"secret"}},
			{Match: policy.Match{Host: "api.internal", Path: "/**"}, Action: policy.ActionAllow, Inject: true},
			{Match: policy.Match{Tool: "fs__*"}, Action: policy.ActionDeny},
		},
	}
	m := newModel(Options{Policy: in})
	if got := m.build(); !reflect.DeepEqual(got.Tools, in.Tools) || !reflect.DeepEqual(got.Egress, in.Egress) {
		t.Fatalf("untouched round trip changed the policy:\n got %+v %+v\nwant %+v %+v", got.Tools, got.Egress, in.Tools, in.Egress)
	}

	// Change the read rule to hitl, delete the catch-all, add a new rule.
	m, _ = press(t, m, "tab", "down", "h", "down", "x", "n")
	m = typeText(t, m, "net__fetch")
	m, _ = press(t, m, "enter")
	got := m.build().Tools
	want := []policy.Rule{
		in.Tools[0],
		in.Tools[1],
		{Match: policy.Match{Tool: "fs__read*"}, Action: policy.ActionHITL, Scope: "fs:read", Taints: []string{"secret"}},
		in.Tools[3],
		{Match: policy.Match{Tool: "net__fetch"}, Action: policy.ActionHITL},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("edited rules\n got %+v\nwant %+v", got, want)
	}
}

func TestViewRendersEverySection(t *testing.T) {
	var scopes []string
	for i := 0; i < 40; i++ {
		scopes = append(scopes, "scope"+fmtCount(i))
	}
	m := newModel(Options{
		Policy:    policy.Policy{Tools: []policy.Rule{{Match: policy.Match{Tool: "t"}, Action: policy.ActionDeny}}, Egress: policy.Egress{Allow: []string{"h.com"}}},
		Providers: []principal.ProviderInfo{{Name: "big", AuthType: "oauth2", Scopes: scopes}},
	})
	for _, size := range []tea.WindowSizeMsg{{Width: 0, Height: 0}, {Width: 30, Height: 10}, {Width: 200, Height: 60}} {
		tm, _ := m.Update(size)
		m = tm.(model)
		for s := 0; s < len(sectionNames); s++ {
			m.section = s
			if v := m.View(); !strings.Contains(v, sectionNames[s]) {
				t.Fatalf("section %s not rendered at %v", sectionNames[s], size)
			}
		}
	}
	m.section = secProviders
	m, _ = press(t, m, "enter")
	for i := 0; i < 45; i++ {
		m, _ = press(t, m, "down")
	}
	if m.scopeCursor != len(scopes)-1 || !strings.Contains(m.View(), "scope39") {
		t.Fatalf("scope cursor %d not clamped/visible", m.scopeCursor)
	}
	if m.Update(struct{}{}); m.View() == "" {
		t.Fatal("unknown message broke the view")
	}
	for _, a := range []string{"allow", "hitl", "deny", ""} {
		if actionBadge(a) == "" {
			t.Fatalf("empty badge for %q", a)
		}
	}
}
