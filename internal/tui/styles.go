package tui

import "github.com/charmbracelet/lipgloss"

// A compact, unixporn-flavored palette (Catppuccin-ish) for the policy editor.
var (
	colBase    = lipgloss.Color("#1e1e2e")
	colText    = lipgloss.Color("#cdd6f4")
	colSubtle  = lipgloss.Color("#6c7086")
	colAccent  = lipgloss.Color("#89b4fa")
	colAllow   = lipgloss.Color("#a6e3a1")
	colHITL    = lipgloss.Color("#f9e2af")
	colDeny    = lipgloss.Color("#f38ba8")
	colBorder  = lipgloss.Color("#585b70")
	colFocus   = lipgloss.Color("#cba6f7")
	colWarnBg  = lipgloss.Color("#f38ba8")
	colTitleBg = lipgloss.Color("#313244")
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(colText).Background(colTitleBg).Padding(0, 1)
	dirtyStyle = lipgloss.NewStyle().Bold(true).Foreground(colWarnBg)

	railStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).Padding(0, 1).Width(16)
	railItem   = lipgloss.NewStyle().Foreground(colSubtle).Padding(0, 1)
	railActive = lipgloss.NewStyle().Foreground(colBase).Background(colAccent).Bold(true).Padding(0, 1)

	paneStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colBorder).Padding(0, 1)

	rowStyle    = lipgloss.NewStyle().Foreground(colText)
	rowCursor   = lipgloss.NewStyle().Foreground(colFocus).Bold(true)
	subtleStyle = lipgloss.NewStyle().Foreground(colSubtle)
	helpStyle   = lipgloss.NewStyle().Foreground(colSubtle).Padding(0, 1)
)

// actionBadge renders an allow/hitl/deny pill in its semantic color.
func actionBadge(action string) string {
	c := colSubtle
	switch action {
	case "allow":
		c = colAllow
	case "hitl":
		c = colHITL
	case "deny":
		c = colDeny
	}
	return lipgloss.NewStyle().Foreground(colBase).Background(c).Bold(true).Padding(0, 1).Render(pad(action))
}

func pad(s string) string {
	for len(s) < 5 {
		s += " "
	}
	return s
}
