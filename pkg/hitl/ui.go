// Package hitl renders the human-in-the-loop approval prompt for intercepted tool calls.
package hitl

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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

// MaxParamsDisplay is the number of runes of the call payload shown in a prompt.
const MaxParamsDisplay = 500

type ApprovalRequest struct {
	AgentID    string
	ActAsUser  string
	ToolName   string
	TargetURI  string
	Params     string
	Reason     string
	ResponseCh chan Decision
}

// outcome explains why a prompt ended without a human keypress.
type outcome int

const (
	outcomeAnswered outcome = iota
	outcomeTimeout
	outcomeWithdrawn
)

// tickMsg drives the countdown of a prompt with a deadline.
type tickMsg time.Time

// abortMsg withdraws a prompt (timeout or cancellation); it resolves to Deny unless already answered.
type abortMsg struct{ timedOut bool }

type Model struct {
	req      ApprovalRequest
	decision Decision
	answered bool

	// Optional prompt features used by TTYApprover; zero values reproduce the classic prompt.
	deadline time.Time
	pending  func() int
	now      func() time.Time
	outcome  outcome
}

func NewModel(req ApprovalRequest) Model {
	return Model{req: req}
}

// Decision reports the decision taken and whether the prompt has been resolved.
func (m Model) Decision() (Decision, bool) { return m.decision, m.answered }

func (m Model) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m Model) Init() tea.Cmd {
	if m.deadline.IsZero() && m.pending == nil {
		return nil
	}
	return tick()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.answered {
			return m, nil
		}
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
	case tickMsg:
		if m.answered {
			return m, nil
		}
		if !m.deadline.IsZero() && !m.clock().Before(m.deadline) {
			m.outcome = outcomeTimeout
			return m.answer(Deny)
		}
		return m, tick()
	case abortMsg:
		if m.answered {
			return m, tea.Quit
		}
		m.outcome = outcomeWithdrawn
		if msg.timedOut {
			m.outcome = outcomeTimeout
		}
		return m.answer(Deny)
	}
	return m, nil
}

func (m Model) answer(d Decision) (tea.Model, tea.Cmd) {
	m.decision = d
	m.answered = true
	if ch := m.req.ResponseCh; ch != nil {
		// Never block the UI loop: deliver immediately if a receiver is waiting (or the channel is
		// buffered), otherwise hand off to a goroutine that gives up if nobody ever reads.
		select {
		case ch <- d:
		default:
			go func() {
				select {
				case ch <- d:
				case <-time.After(5 * time.Second):
				}
			}()
		}
	}
	return m, tea.Quit
}

func (m Model) View() string {
	if m.answered {
		switch {
		case m.outcome == outcomeTimeout:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✖ Timed out — blocked\n")
		case m.outcome == outcomeWithdrawn:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✖ Prompt withdrawn (decided elsewhere or request cancelled)\n")
		case m.decision == Deny:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("✖ Blocked\n")
		case m.decision == Session:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("✔ Approved for this session\n")
		case m.decision == Always:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("✔ Approved & saved to policy\n")
		default:
			return lipgloss.NewStyle().Foreground(lipgloss.Color("82")).Render("✔ Approved (once)\n")
		}
	}

	var pv PromptView
	if !m.deadline.IsZero() {
		pv.Remaining = m.deadline.Sub(m.clock())
		if pv.Remaining < time.Second {
			pv.Remaining = time.Second
		}
	}
	if m.pending != nil {
		pv.Pending = m.pending()
	}
	return RenderPrompt(Request{
		AgentID:   m.req.AgentID,
		ActAsUser: m.req.ActAsUser,
		Tool:      m.req.ToolName,
		Target:    m.req.TargetURI,
		Params:    m.req.Params,
		Reason:    m.req.Reason,
	}, pv)
}

// PromptView carries optional context rendered alongside a request in the approval box.
type PromptView struct {
	Source    string        // where the request came from (e.g. "dev · pid 123 · /repo"); hidden when empty
	Pending   int           // additional requests queued behind this one; hidden when <= 0
	Remaining time.Duration // countdown until the request auto-denies; hidden when <= 0
	Age       time.Duration // how long the request has been waiting; hidden when <= 0
}

// RenderPrompt renders the approval box for req. Untrusted fields are stripped of control
// characters (no terminal escape injection) and the payload is truncated to MaxParamsDisplay runes.
func RenderPrompt(req Request, pv PromptView) string {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("203")).
		Padding(1, 2).
		Width(70)

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("255")).Bold(true)
	metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	prompt := lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Render(
		"[Y] once   [S] this session   [A] always (save)   [N] deny",
	)

	var b strings.Builder
	b.WriteString(headerStyle.Render("⚠️  [Nexus] Approve tool call?"))
	b.WriteString("\n")
	var meta []string
	if pv.Source != "" {
		meta = append(meta, Sanitize(pv.Source))
	}
	if pv.Age > 0 {
		meta = append(meta, "waiting "+pv.Age.Round(time.Second).String())
	}
	if pv.Remaining > 0 {
		meta = append(meta, fmt.Sprintf("auto-deny in %ds", int((pv.Remaining+time.Second-1)/time.Second)))
	}
	if pv.Pending > 0 {
		meta = append(meta, fmt.Sprintf("%d more pending", pv.Pending))
	}
	if len(meta) > 0 {
		b.WriteString(metaStyle.Render(strings.Join(meta, " · ")))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	row := func(label, val string) {
		b.WriteString(labelStyle.Render(label))
		b.WriteString(" ")
		b.WriteString(valStyle.Render(val))
		b.WriteString("\n")
	}
	row("Agent ID:    ", Sanitize(req.AgentID))
	row("Act-As User: ", Sanitize(req.ActAsUser))
	row("Tool/Method: ", Sanitize(req.Tool))
	row("Target:      ", Sanitize(req.Target))
	row("Reason:      ", Sanitize(req.Reason))
	row("Payload:     ", Truncate(Sanitize(req.Params), MaxParamsDisplay))
	b.WriteString("\n")
	b.WriteString(prompt)

	return boxStyle.Render(b.String()) + "\n"
}

// Sanitize replaces control characters (including ANSI escape introducers and newlines) with
// spaces so untrusted agent input cannot manipulate the terminal.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

// Truncate shortens s to at most n runes, marking the cut with an ellipsis.
func Truncate(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}
