package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/control"
	"github.com/whoisnjoguu/nexus-cli/pkg/hitl"
)

const (
	approveRediscoverEvery = 3 * time.Second
	approvePollWait        = 25 * time.Second
	approveRetryDelay      = 2 * time.Second
)

var approveCmd = newApproveCmd()

func init() {
	rootCmd.AddCommand(approveCmd)
}

func newApproveCmd() *cobra.Command {
	var (
		list     bool
		decision string
		web      bool
		noOpen   bool
		pid      int
		quiet    bool
	)
	c := &cobra.Command{
		Use:   "approve [request-id]",
		Short: "Approve or deny pending human-in-the-loop requests from another terminal",
		Long: `Answer HITL approval prompts of running nexus-cli processes (dev, run, mcp) out of band.

Without arguments, opens an interactive watcher that shows the oldest pending request across all
local endpoints: press y (once), s (this session), a (always, saved to policy) or n (deny); q quits.
The watcher rings the terminal bell when a new request arrives (--quiet disables it).

--web opens the local approvals web UI of one endpoint in your browser using a one-time login link
(valid 60s). With several endpoints running, pick one with --pid; otherwise the endpoint with the
oldest pending request (or the most recently started one) is used.

  nexus-cli approve                          # interactive watcher
  nexus-cli approve --list                   # print pending requests and exit
  nexus-cli approve <id> --decision once     # decide one request (once|session|always|deny)
  nexus-cli approve --web                    # open the web UI in a browser
  nexus-cli approve --web --no-open          # just print the one-time URL`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			out := cmd.OutOrStdout()
			if noOpen && !web {
				return errors.New("--no-open requires --web")
			}
			if pid != 0 && !web {
				return errors.New("--pid requires --web")
			}
			switch {
			case web:
				if list || len(args) > 0 || decision != "" {
					return errors.New("--web cannot be combined with --list, a request id or --decision")
				}
				return approveWeb(ctx, out, pid, !noOpen)
			case list:
				if len(args) > 0 || decision != "" {
					return errors.New("--list cannot be combined with a request id or --decision")
				}
				return approveList(ctx, out)
			case len(args) == 1:
				if decision == "" {
					return errors.New("--decision (once|session|always|deny) is required with a request id")
				}
				d, err := control.ParseDecisionStrict(decision)
				if err != nil {
					return err
				}
				return approveDecide(ctx, out, args[0], d)
			case decision != "":
				return errors.New("--decision requires a request id (see `nexus-cli approve --list`)")
			default:
				return approveWatch(ctx, out, !quiet)
			}
		},
	}
	c.Flags().BoolVar(&list, "list", false, "Print pending approval requests and exit")
	c.Flags().StringVar(&decision, "decision", "", "Decision for <request-id>: once, session, always, or deny")
	c.Flags().BoolVar(&web, "web", false, "Open the approvals web UI in a browser (one-time login link)")
	c.Flags().BoolVar(&noOpen, "no-open", false, "With --web, print the URL instead of opening a browser")
	c.Flags().IntVar(&pid, "pid", 0, "With --web, the process ID of the endpoint to open (see 'nexus-cli approve --list')")
	c.Flags().BoolVarP(&quiet, "quiet", "q", false, "Do not ring the terminal bell when new requests arrive")
	return c
}

type endpointRequest struct {
	info control.Info
	req  hitl.Request
}

// collectPending lists pending requests across all live endpoints, oldest first.
func collectPending(ctx context.Context) ([]control.Info, []endpointRequest, error) {
	infos, err := control.Discover()
	if err != nil {
		return nil, nil, err
	}
	var all []endpointRequest
	for _, info := range infos {
		c := control.NewClient(info)
		reqs, err := c.List(ctx, 0)
		c.Close()
		if err != nil {
			continue // endpoint went away between discovery and listing
		}
		for _, r := range reqs {
			all = append(all, endpointRequest{info, r})
		}
	}
	sortEndpointRequests(all)
	return infos, all, nil
}

func sortEndpointRequests(all []endpointRequest) {
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].req.Created.Equal(all[j].req.Created) {
			return all[i].req.Created.Before(all[j].req.Created)
		}
		return all[i].req.ID < all[j].req.ID
	})
}

func approveList(ctx context.Context, out io.Writer) error {
	infos, all, err := collectPending(ctx)
	if err != nil {
		return err
	}
	if len(infos) == 0 {
		fmt.Fprintln(out, "no running nexus-cli endpoints found")
		return nil
	}
	if len(all) == 0 {
		fmt.Fprintln(out, "no pending approval requests")
		return nil
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tAGE\tSOURCE\tAGENT\tACT-AS\tTOOL\tTARGET\tREASON")
	now := time.Now()
	for _, er := range all {
		r := er.req
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			cell(r.ID, 32),
			now.Sub(r.Created).Round(time.Second),
			fmt.Sprintf("%s/%d", cell(er.info.Kind, 8), er.info.PID),
			cell(r.AgentID, 24), cell(r.ActAsUser, 24), cell(r.Tool, 24), cell(r.Target, 40), cell(r.Reason, 48))
	}
	return tw.Flush()
}

func cell(s string, n int) string {
	s = strings.TrimSpace(hitl.Truncate(hitl.Sanitize(s), n))
	if s == "" {
		return "-"
	}
	return s
}

func approveDecide(ctx context.Context, out io.Writer, id string, d hitl.Decision) error {
	_, all, err := collectPending(ctx)
	if err != nil {
		return err
	}
	for _, er := range all {
		if er.req.ID != id {
			continue
		}
		c := control.NewClient(er.info)
		defer c.Close()
		if err := c.Decide(ctx, id, d); err != nil {
			if errors.Is(err, hitl.ErrUnknownRequest) {
				return fmt.Errorf("approval request %q is no longer pending", id)
			}
			return err
		}
		fmt.Fprintf(out, "%s %s → %s\n", decisionMark(d), id, d)
		return nil
	}
	return fmt.Errorf("approval request %q not found (see `nexus-cli approve --list`)", id)
}

func decisionMark(d hitl.Decision) string {
	if d.Allowed() {
		return "✔"
	}
	return "✖"
}

// ---- interactive watcher ----

func approveWatch(ctx context.Context, out io.Writer, bell bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m := newWatchModel(ctx, control.Discover)
	// The renderer writes whole frames; serialising writes keeps the bell from splitting one.
	lw := &lockedWriter{w: out}
	if bell {
		m.bell = func() { _, _ = lw.Write([]byte("\a")) }
	}
	_, err := tea.NewProgram(m, tea.WithContext(ctx), tea.WithOutput(lw)).Run()
	m.closeAll()
	if errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil {
		return nil
	}
	return err
}

type watchEndpoint struct {
	info    control.Info
	client  *control.Client
	gen     int
	pending []hitl.Request
	err     error
}

type watchModel struct {
	ctx      context.Context
	discover func() ([]control.Info, error)
	eps      map[string]*watchEndpoint
	gen      *int // shared across copies of the (value) model
	now      time.Time
	status   string
	busy     bool
	discErr  error
	bell     func()                     // rings the terminal bell; nil when quiet
	seen     map[string]map[string]bool // endpoint key → request IDs already shown (shared)
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

type (
	watchDiscoveredMsg struct {
		infos []control.Info
		err   error
	}
	watchPolledMsg struct {
		key  string
		gen  int
		reqs []hitl.Request
		err  error
	}
	watchDecidedMsg struct {
		key string
		id  string
		d   hitl.Decision
		err error
	}
	watchTickMsg   time.Time
	watchRediscMsg struct{}
)

func newWatchModel(ctx context.Context, discover func() ([]control.Info, error)) watchModel {
	return watchModel{ctx: ctx, discover: discover, eps: map[string]*watchEndpoint{}, gen: new(int), now: time.Now(), seen: map[string]map[string]bool{}}
}

func endpointKey(i control.Info) string { return fmt.Sprintf("%s|%d|%s", i.Addr, i.PID, i.Token) }

func (m watchModel) closeAll() {
	for _, ep := range m.eps {
		ep.client.Close()
	}
}

func (m watchModel) Init() tea.Cmd {
	return tea.Batch(m.discoverCmd(), watchTick())
}

func watchTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return watchTickMsg(t) })
}

func (m watchModel) discoverCmd() tea.Cmd {
	return func() tea.Msg {
		infos, err := m.discover()
		return watchDiscoveredMsg{infos, err}
	}
}

func (m watchModel) pollCmd(key string, ep *watchEndpoint, wait, delay time.Duration) tea.Cmd {
	ctx, client, gen := m.ctx, ep.client, ep.gen
	return func() tea.Msg {
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil
			}
		}
		reqs, err := client.List(ctx, wait)
		if ctx.Err() != nil {
			return nil
		}
		return watchPolledMsg{key, gen, reqs, err}
	}
}

func (m watchModel) decideCmd(key string, ep *watchEndpoint, id string, d hitl.Decision) tea.Cmd {
	ctx, client := m.ctx, ep.client
	return func() tea.Msg {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return watchDecidedMsg{key, id, d, client.Decide(cctx, id, d)}
	}
}

// current returns the oldest pending request across endpoints and how many others are queued.
func (m watchModel) current() (key string, ep *watchEndpoint, req hitl.Request, more int, ok bool) {
	total := 0
	for k, e := range m.eps {
		for _, r := range e.pending {
			total++
			if !ok || r.Created.Before(req.Created) || (r.Created.Equal(req.Created) && r.ID < req.ID) {
				key, ep, req, ok = k, e, r, true
			}
		}
	}
	if !ok {
		return "", nil, hitl.Request{}, 0, false
	}
	return key, ep, req, total - 1, true
}

func (m watchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		}
		d, ok := map[string]hitl.Decision{"y": hitl.Once, "s": hitl.Session, "a": hitl.Always, "n": hitl.Deny}[strings.ToLower(msg.String())]
		if !ok || m.busy {
			return m, nil
		}
		key, ep, req, _, found := m.current()
		if !found {
			return m, nil
		}
		m.busy = true
		m.status = fmt.Sprintf("sending %s for %s…", d, req.ID)
		return m, m.decideCmd(key, ep, req.ID, d)

	case watchDecidedMsg:
		m.busy = false
		if msg.err != nil {
			if errors.Is(msg.err, hitl.ErrUnknownRequest) {
				m.status = fmt.Sprintf("✖ %s was already decided, timed out, or cancelled", msg.id)
			} else {
				m.status = fmt.Sprintf("✖ %s: %v", msg.id, msg.err)
			}
		} else {
			m.status = fmt.Sprintf("%s %s → %s", decisionMark(msg.d), msg.id, msg.d)
		}
		// Keep the request on screen if the decision may not have reached the endpoint (e.g. a
		// network error) so it can be retried; the long-poll would not resend an unchanged queue.
		if ep, ok := m.eps[msg.key]; ok && (msg.err == nil || errors.Is(msg.err, hitl.ErrUnknownRequest)) {
			ep.pending = slicesDeleteID(ep.pending, msg.id)
		}
		return m, nil

	case watchDiscoveredMsg:
		m.discErr = msg.err
		var cmds []tea.Cmd
		seen := map[string]bool{}
		for _, info := range msg.infos {
			key := endpointKey(info)
			seen[key] = true
			if _, ok := m.eps[key]; ok {
				continue
			}
			*m.gen++
			ep := &watchEndpoint{info: info, client: control.NewClient(info), gen: *m.gen}
			m.eps[key] = ep
			cmds = append(cmds, m.pollCmd(key, ep, 0, 0))
		}
		if msg.err == nil {
			for key, ep := range m.eps {
				if !seen[key] {
					ep.client.Close()
					delete(m.eps, key)
				}
			}
		}
		cmds = append(cmds, tea.Tick(approveRediscoverEvery, func(time.Time) tea.Msg { return watchRediscMsg{} }))
		return m, tea.Batch(cmds...)

	case watchRediscMsg:
		return m, m.discoverCmd()

	case watchPolledMsg:
		ep, ok := m.eps[msg.key]
		if !ok || ep.gen != msg.gen {
			return m, nil // endpoint vanished or was replaced
		}
		ep.err = msg.err
		if msg.err != nil {
			ep.pending = nil
			return m, m.pollCmd(msg.key, ep, 0, approveRetryDelay)
		}
		ep.pending = msg.reqs
		if m.markSeen(msg.key, msg.reqs) && m.bell != nil {
			m.bell() // a single byte through the locked writer; never blocks for long
		}
		return m, m.pollCmd(msg.key, ep, approvePollWait, 0)

	case watchTickMsg:
		m.now = time.Time(msg)
		return m, watchTick()
	}
	return m, nil
}

// markSeen records the requests of endpoint key and reports whether any is new.
func (m watchModel) markSeen(key string, reqs []hitl.Request) bool {
	old := m.seen[key]
	cur := make(map[string]bool, len(reqs))
	fresh := false
	for _, r := range reqs {
		cur[r.ID] = true
		if !old[r.ID] {
			fresh = true
		}
	}
	m.seen[key] = cur
	return fresh
}

func slicesDeleteID(reqs []hitl.Request, id string) []hitl.Request {
	out := reqs[:0:0]
	for _, r := range reqs {
		if r.ID != id {
			out = append(out, r)
		}
	}
	return out
}

func (m watchModel) View() string {
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	var b strings.Builder
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("nexus-cli approve"))
	b.WriteString(dim.Render(fmt.Sprintf(" — watching %d endpoint(s)", len(m.eps))))
	b.WriteString("\n\n")
	if _, ep, req, more, ok := m.current(); ok {
		src := fmt.Sprintf("%s · pid %d", ep.info.Kind, ep.info.PID)
		if ep.info.CWD != "" {
			src += " · " + ep.info.CWD
		}
		pv := hitl.PromptView{Source: src, Pending: more}
		if !req.Created.IsZero() {
			pv.Age = m.now.Sub(req.Created)
		}
		b.WriteString(hitl.RenderPrompt(req, pv))
		b.WriteString(dim.Render(fmt.Sprintf("request %s · q to quit", req.ID)))
		b.WriteString("\n")
	} else {
		b.WriteString("waiting for approval requests… (q to quit)\n")
	}
	if m.discErr != nil {
		b.WriteString(dim.Render("discovery error: "+m.discErr.Error()) + "\n")
	}
	if m.status != "" {
		b.WriteString("\n" + m.status + "\n")
	}
	return b.String()
}
