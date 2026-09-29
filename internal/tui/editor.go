// Package tui provides the interactive policy editor (nexus-cli policy edit).
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

// Options configures the editor.
type Options struct {
	Policy    policy.Policy
	Providers []principal.ProviderInfo // Gateway catalog for scope selection (may be empty)
}

const (
	secProviders = iota
	secTools
	secEgress
	secDefaults
)

var sectionNames = []string{"Providers", "Tools", "Egress", "Defaults"}

type providerRow struct {
	name       string
	authType   string
	access     string // "", allow, hitl, deny
	credential string // "", allow, hitl, deny
	allScopes  []string
	selected   map[string]bool
}

type toolRow struct {
	pattern string
	action  string
}

type model struct {
	orig policy.Policy

	providers []providerRow
	tools     []toolRow
	egress    []string
	defAction string
	escalate  bool

	section int
	cursor  int

	scopeMode   bool
	scopeCursor int

	input     textinput.Model
	inputMode bool
	inputKind int // secTools or secEgress

	dirty bool
	saved bool
	w, h  int
}

// Run launches the editor and returns the edited policy and whether the user saved.
func Run(opts Options) (policy.Policy, bool, error) {
	m := newModel(opts)
	p := tea.NewProgram(m, tea.WithAltScreen())
	res, err := p.Run()
	if err != nil {
		return opts.Policy, false, err
	}
	fm := res.(model)
	if !fm.saved {
		return opts.Policy, false, nil
	}
	return fm.build(), true, nil
}

func newModel(opts Options) model {
	ti := textinput.New()
	ti.Placeholder = "type value, enter to add"
	ti.CharLimit = 200

	m := model{
		orig:      opts.Policy,
		egress:    append([]string{}, opts.Policy.Egress.Allow...),
		defAction: string(orZero(opts.Policy.DefaultAction, "deny")),
		escalate:  opts.Policy.EscalateWhenTainted,
		input:     ti,
	}

	// Providers: seed from the Gateway catalog, overlaying any saved rules.
	seen := map[string]bool{}
	for _, pi := range opts.Providers {
		row := providerRow{name: pi.Name, authType: pi.AuthType, allScopes: pi.Scopes, selected: map[string]bool{}}
		if pr, ok := opts.Policy.Providers[pi.Name]; ok {
			row.access = string(pr.Access)
			row.credential = string(pr.Credential)
			for _, s := range pr.Scopes {
				row.selected[s] = true
			}
		}
		m.providers = append(m.providers, row)
		seen[pi.Name] = true
	}
	// Include saved providers not present in the catalog (offline).
	for name, pr := range opts.Policy.Providers {
		if seen[name] {
			continue
		}
		row := providerRow{name: name, access: string(pr.Access), credential: string(pr.Credential), selected: map[string]bool{}}
		row.allScopes = append(row.allScopes, pr.Scopes...)
		for _, s := range pr.Scopes {
			row.selected[s] = true
		}
		m.providers = append(m.providers, row)
	}

	// Tools: only tool-name rules are editable here; host/path rules are preserved on save.
	for _, r := range opts.Policy.Tools {
		if r.Match.Tool != "" && r.Match.Provider == "" {
			m.tools = append(m.tools, toolRow{pattern: r.Match.Tool, action: string(orZero(r.Action, "hitl"))})
		}
	}
	return m
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		if m.inputMode {
			return m.updateInput(msg)
		}
		return m.updateNormal(msg)
	}
	return m, nil
}

func (m model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		val := strings.TrimSpace(m.input.Value())
		if val != "" {
			if m.inputKind == secTools {
				m.tools = append(m.tools, toolRow{pattern: val, action: "hitl"})
			} else {
				m.egress = append(m.egress, val)
			}
			m.dirty = true
		}
		m.inputMode = false
		m.input.Blur()
		m.input.SetValue("")
		return m, nil
	case "esc":
		m.inputMode = false
		m.input.Blur()
		m.input.SetValue("")
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) updateNormal(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		if m.scopeMode {
			m.scopeMode = false
			return m, nil
		}
		return m, tea.Quit
	case "esc":
		if m.scopeMode {
			m.scopeMode = false
		}
		return m, nil
	case "ctrl+s":
		m.saved = true
		return m, tea.Quit
	case "tab", "right":
		if !m.scopeMode {
			m.section = (m.section + 1) % len(sectionNames)
			m.cursor = 0
		}
		return m, nil
	case "shift+tab", "left":
		if !m.scopeMode {
			m.section = (m.section - 1 + len(sectionNames)) % len(sectionNames)
			m.cursor = 0
		}
		return m, nil
	}

	// Section-specific keys.
	switch m.section {
	case secProviders:
		return m.updateProviders(msg)
	case secTools:
		return m.updateTools(msg)
	case secEgress:
		return m.updateEgress(msg)
	case secDefaults:
		return m.updateDefaults(msg)
	}
	return m, nil
}

func (m model) updateProviders(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if len(m.providers) == 0 {
		return m, nil
	}
	row := &m.providers[m.cursor]
	if m.scopeMode {
		switch msg.String() {
		case "up", "k":
			if m.scopeCursor > 0 {
				m.scopeCursor--
			}
		case "down", "j":
			if m.scopeCursor < len(row.allScopes)-1 {
				m.scopeCursor++
			}
		case " ", "space":
			if len(row.allScopes) > 0 {
				s := row.allScopes[m.scopeCursor]
				row.selected[s] = !row.selected[s]
				m.dirty = true
			}
		case "enter":
			m.scopeMode = false
		}
		return m, nil
	}
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.providers)-1 {
			m.cursor++
		}
	case "a":
		row.access = "allow"
		m.dirty = true
	case "d":
		row.access = "deny"
		m.dirty = true
	case "h":
		row.access = "hitl"
		m.dirty = true
	case "c":
		row.credential = cycle(row.credential)
		m.dirty = true
	case "enter", " ", "space":
		m.scopeMode = true
		m.scopeCursor = 0
	}
	return m, nil
}

func (m model) updateTools(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.tools)-1 {
			m.cursor++
		}
	case "n":
		m.inputMode = true
		m.inputKind = secTools
		m.input.Focus()
	case "x":
		if len(m.tools) > 0 {
			m.tools = append(m.tools[:m.cursor], m.tools[m.cursor+1:]...)
			if m.cursor >= len(m.tools) && m.cursor > 0 {
				m.cursor--
			}
			m.dirty = true
		}
	case "a":
		m.setToolAction("allow")
	case "d":
		m.setToolAction("deny")
	}
	// 'h' collides with deny? No — for tools use explicit keys; map 'h' to hitl only if not navigation.
	if msg.String() == "h" {
		m.setToolAction("hitl")
	}
	return m, nil
}

func (m *model) setToolAction(a string) {
	if len(m.tools) > 0 {
		m.tools[m.cursor].action = a
		m.dirty = true
	}
}

func (m model) updateEgress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.egress)-1 {
			m.cursor++
		}
	case "n":
		m.inputMode = true
		m.inputKind = secEgress
		m.input.Focus()
	case "x":
		if len(m.egress) > 0 {
			m.egress = append(m.egress[:m.cursor], m.egress[m.cursor+1:]...)
			if m.cursor >= len(m.egress) && m.cursor > 0 {
				m.cursor--
			}
			m.dirty = true
		}
	}
	return m, nil
}

func (m model) updateDefaults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < 1 {
			m.cursor++
		}
	case "a":
		if m.cursor == 0 {
			m.defAction = "allow"
			m.dirty = true
		}
	case "d":
		if m.cursor == 0 {
			m.defAction = "deny"
			m.dirty = true
		}
	case "h":
		if m.cursor == 0 {
			m.defAction = "hitl"
			m.dirty = true
		}
	case " ", "space":
		if m.cursor == 1 {
			m.escalate = !m.escalate
			m.dirty = true
		}
	}
	return m, nil
}

// build converts editor state back into a policy, preserving host/path rules from the original.
func (m model) build() policy.Policy {
	p := policy.Policy{
		Agent:               m.orig.Agent,
		Egress:              policy.Egress{Allow: m.egress},
		DefaultAction:       policy.Action(m.defAction),
		EscalateWhenTainted: m.escalate,
		Providers:           map[string]policy.ProviderRule{},
	}
	// Preserve non-tool, non-provider rules (host/path egress rules).
	for _, r := range m.orig.Tools {
		if r.Match.Tool == "" && r.Match.Provider == "" {
			p.Tools = append(p.Tools, r)
		}
	}
	for _, t := range m.tools {
		p.Tools = append(p.Tools, policy.Rule{Match: policy.Match{Tool: t.pattern}, Action: policy.Action(t.action)})
	}
	for _, pr := range m.providers {
		if pr.access == "" && pr.credential == "" && len(selectedScopes(pr)) == 0 {
			continue // untouched provider
		}
		rule := policy.ProviderRule{Access: policy.Action(pr.access), Credential: policy.Action(pr.credential), Scopes: selectedScopes(pr)}
		p.Providers[pr.name] = rule
	}
	if len(p.Providers) == 0 {
		p.Providers = nil
	}
	return p
}

func selectedScopes(pr providerRow) []string {
	var out []string
	for _, s := range pr.allScopes {
		if pr.selected[s] {
			out = append(out, s)
		}
	}
	return out
}

func cycle(a string) string {
	switch a {
	case "", "deny":
		return "hitl"
	case "hitl":
		return "allow"
	default:
		return "deny"
	}
}

func orZero[T ~string](v T, fallback string) T {
	if v == "" {
		return T(fallback)
	}
	return v
}

func fmtCount(n int) string { return fmt.Sprintf("%d", n) }

// ensure lipgloss import is used even if View trims (it is used in View).
var _ = lipgloss.Width
