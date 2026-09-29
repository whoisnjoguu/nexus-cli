package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m model) View() string {
	title := titleStyle.Render("nexus · policy editor")
	file := subtleStyle.Render("nexus.yaml")
	if m.dirty {
		file = file + " " + dirtyStyle.Render("● unsaved")
	}
	header := lipgloss.JoinHorizontal(lipgloss.Center, title, "  ", file)

	rail := m.renderRail()
	pane := paneStyle.Width(m.paneWidth()).Render(m.renderSection())
	body := lipgloss.JoinHorizontal(lipgloss.Top, rail, " ", pane)

	return lipgloss.JoinVertical(lipgloss.Left, header, "", body, "", m.renderHelp())
}

func (m model) paneWidth() int {
	w := m.w - 22
	if w < 40 {
		w = 60
	}
	return w
}

func (m model) renderRail() string {
	var lines []string
	for i, name := range sectionNames {
		if i == m.section {
			lines = append(lines, railActive.Render("▸ "+name))
		} else {
			lines = append(lines, railItem.Render("  "+name))
		}
	}
	return railStyle.Render(strings.Join(lines, "\n"))
}

func (m model) renderSection() string {
	switch m.section {
	case secProviders:
		return m.renderProviders()
	case secTools:
		return m.renderTools()
	case secEgress:
		return m.renderEgress()
	case secDefaults:
		return m.renderDefaults()
	}
	return ""
}

func (m model) renderProviders() string {
	if len(m.providers) == 0 {
		return subtleStyle.Render("No providers. Pass --gateway to load the catalog, or add rules manually.")
	}
	var b strings.Builder
	b.WriteString(subtleStyle.Render("Provider access — a allow · h hitl · d deny · c credential · enter scopes"))
	b.WriteString("\n\n")

	start, end := window(m.cursor, len(m.providers), 12)
	for i := start; i < end; i++ {
		pr := m.providers[i]
		cursor := "  "
		nameStyle := rowStyle
		if i == m.cursor {
			cursor = rowCursor.Render("▸ ")
			nameStyle = rowCursor
		}
		access := pr.access
		if access == "" {
			access = "hitl"
		}
		cred := pr.credential
		if cred == "" {
			cred = "deny"
		}
		line := fmt.Sprintf(
			"%s%-18s %s  %s  cred %s  %s",
			cursor,
			nameStyle.Render(pr.name),
			subtleStyle.Render("["+pr.authType+"]"),
			actionBadge(access),
			actionBadge(cred),
			subtleStyle.Render(fmt.Sprintf("(%s/%s scopes)", fmtCount(len(selectedScopes(pr))), fmtCount(len(pr.allScopes)))),
		)
		b.WriteString(line + "\n")
		if m.scopeMode && i == m.cursor {
			b.WriteString(m.renderScopes(pr))
		}
	}
	return b.String()
}

func (m model) renderScopes(pr providerRow) string {
	if len(pr.allScopes) == 0 {
		return subtleStyle.Render("    (no scopes advertised for this provider)\n")
	}
	var b strings.Builder
	b.WriteString(subtleStyle.Render("    space toggle · enter/esc done") + "\n")
	start, end := window(m.scopeCursor, len(pr.allScopes), 8)
	for i := start; i < end; i++ {
		s := pr.allScopes[i]
		box := "▢"
		if pr.selected[s] {
			box = lipgloss.NewStyle().Foreground(colAllow).Render("▣")
		}
		cur := "  "
		st := subtleStyle
		if i == m.scopeCursor {
			cur = rowCursor.Render("▸ ")
			st = rowStyle
		}
		b.WriteString(fmt.Sprintf("    %s%s %s\n", cur, box, st.Render(s)))
	}
	return b.String()
}

func (m model) renderTools() string {
	var b strings.Builder
	b.WriteString(subtleStyle.Render("MCP tool rules — a allow · h hitl · d deny · n new · x delete"))
	b.WriteString("\n\n")
	if m.inputMode && m.inputKind == secTools {
		b.WriteString("  new tool pattern: " + m.input.View() + "\n\n")
	}
	if len(m.tools) == 0 {
		b.WriteString(subtleStyle.Render("  (no tool rules — press n to add, e.g. fs__write* or execute_shell)\n"))
		return b.String()
	}
	for i, t := range m.tools {
		cursor := "  "
		if i == m.cursor {
			cursor = rowCursor.Render("▸ ")
		}
		b.WriteString(fmt.Sprintf("%s%-28s %s\n", cursor, rowStyle.Render(t.pattern), actionBadge(t.action)))
	}
	return b.String()
}

func (m model) renderEgress() string {
	var b strings.Builder
	b.WriteString(subtleStyle.Render("Egress allowlist — n new host · x delete"))
	b.WriteString("\n\n")
	if m.inputMode && m.inputKind == secEgress {
		b.WriteString("  new host: " + m.input.View() + "\n\n")
	}
	if len(m.egress) == 0 {
		b.WriteString(subtleStyle.Render("  (empty — everything denied unless a rule allows it)\n"))
		return b.String()
	}
	for i, h := range m.egress {
		cursor := "  "
		if i == m.cursor {
			cursor = rowCursor.Render("▸ ")
		}
		b.WriteString(fmt.Sprintf("%s%s\n", cursor, rowStyle.Render(h)))
	}
	return b.String()
}

func (m model) renderDefaults() string {
	var b strings.Builder
	b.WriteString(subtleStyle.Render("Defaults — a/h/d set default · space toggle taint escalation"))
	b.WriteString("\n\n")

	c0, c1 := "  ", "  "
	if m.cursor == 0 {
		c0 = rowCursor.Render("▸ ")
	}
	if m.cursor == 1 {
		c1 = rowCursor.Render("▸ ")
	}
	b.WriteString(fmt.Sprintf("%sdefault action   %s\n", c0, actionBadge(m.defAction)))
	esc := "off"
	if m.escalate {
		esc = "on"
	}
	b.WriteString(fmt.Sprintf("%sescalate on taint  %s\n", c1, rowStyle.Render(esc)))
	return b.String()
}

func (m model) renderHelp() string {
	keys := "↑↓ move · tab section · a/h/d action · space toggle · ctrl+s save · q quit"
	if m.scopeMode {
		keys = "↑↓ scope · space toggle · enter/esc done · q back"
	}
	if m.inputMode {
		keys = "type value · enter add · esc cancel"
	}
	return helpStyle.Render(keys)
}

// window returns a [start,end) slice window of size n centered on cursor within total.
func window(cursor, total, n int) (int, int) {
	if total <= n {
		return 0, total
	}
	start := cursor - n/2
	if start < 0 {
		start = 0
	}
	end := start + n
	if end > total {
		end = total
		start = end - n
	}
	return start, end
}
