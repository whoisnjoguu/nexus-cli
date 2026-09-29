// Package hitl renders the human-in-the-loop approval prompt for intercepted tool calls.
package hitl

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Decision is the outcome of a human-in-the-loop prompt.
type Decision int

const (
	Deny    Decision = iota // block this call
	Once                    // allow just this call
	Session                 // allow this shape of call for the rest of the session
	Always                  // allow forever (persisted to the policy)
)

// Allowed reports whether the decision permits execution.
func (d Decision) Allowed() bool { return d != Deny }

type ApprovalRequest struct {
	AgentID    string
	ActAsUser  string
	ToolName   string
	TargetURI  string
	Params     string
	Reason     string
	ResponseCh chan Decision
}

type Model struct {
	req      ApprovalRequest
	decision Decision
	answered bool
}

func NewModel(req ApprovalRequest) Model {
	return Model{req: req}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			return m.answer(Once)
		case "s", "S":
			return m.answer(Session)
		case "a", "A":
			return m.answer(Always)
		case "n", "N", "q", "ctrl+c":
			return m.answer(Deny)
		}
	}
	return m, nil
}

func (m Model) answer(d Decision) (tea.Model, tea.Cmd) {
	m.decision = d
	m.answered = true
	m.req.ResponseCh <- d
	return m, tea.Quit
}

func (m Model) View() string {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("203")).
		Padding(1, 2).
		Width(70)

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Bold(true)

	if m.answered {
		switch m.decision {
		case Deny:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✖ Blocked\n")
		case Session:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("✔ Approved for this session\n")
		case Always:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("✔ Approved & saved to policy\n")
		default:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("✔ Approved (once)\n")
		}
	}

	prompt := lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Render(
		"[Y] once   [S] this session   [A] always (save)   [N] deny",
	)

	content := fmt.Sprintf(
		"%s\n\n%s %s\n%s %s\n%s %s\n%s %s\n%s %s\n%s %s\n\n%s",
		headerStyle.Render("⚠️  [Nexus] Approve tool call?"),
		labelStyle.Render("Agent ID:    "), valStyle.Render(m.req.AgentID),
		labelStyle.Render("Act-As User: "), valStyle.Render(m.req.ActAsUser),
		labelStyle.Render("Tool/Method: "), valStyle.Render(m.req.ToolName),
		labelStyle.Render("Target:      "), valStyle.Render(m.req.TargetURI),
		labelStyle.Render("Reason:      "), valStyle.Render(m.req.Reason),
		labelStyle.Render("Payload:     "), valStyle.Render(m.req.Params),
		prompt,
	)

	return boxStyle.Render(content) + "\n"
}
