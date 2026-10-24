package hitl

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"
)

// TTYOptions configures a TTYApprover. Zero values select sensible defaults.
type TTYOptions struct {
	Timeout    time.Duration // per-prompt timeout before auto-deny (default DefaultTimeout)
	In         io.Reader     // key input (default os.Stdin)
	Out        io.Writer     // prompt output (default os.Stdout)
	IsTerminal func() bool   // reports whether In is interactive (default: isatty on In/os.Stdin)
}

// TTYApprover prompts on the local terminal with a Bubble Tea box. Prompts are serialized (one on
// screen at a time, showing how many more are queued), count down, and deny on timeout or when the
// request context ends (e.g. another approver answered or the client went away).
type TTYApprover struct {
	timeout time.Duration
	in      io.Reader
	out     io.Writer
	pump    *inputPump // non-nil when In is not an *os.File

	sem     chan struct{} // capacity 1: the terminal
	waiting atomic.Int64  // prompts queued behind the active one

	// abortGrace bounds how long a withdrawn prompt may take to quit before it is killed.
	abortGrace time.Duration
}

// NewTTYApprover returns a terminal approver, or (nil, false) when the input is not a terminal.
func NewTTYApprover(opts TTYOptions) (*TTYApprover, bool) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.In == nil {
		opts.In = os.Stdin
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.IsTerminal == nil {
		in := opts.In
		opts.IsTerminal = func() bool {
			f, ok := in.(*os.File)
			if !ok {
				return false
			}
			return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
		}
	}
	if !opts.IsTerminal() {
		return nil, false
	}
	t := &TTYApprover{
		timeout:    opts.Timeout,
		in:         opts.In,
		out:        opts.Out,
		sem:        make(chan struct{}, 1),
		abortGrace: time.Second,
	}
	if _, isFile := opts.In.(*os.File); !isFile {
		// Bubble Tea cannot cancel reads on arbitrary readers, so a finished prompt would leave a
		// reader goroutine that steals the next prompt's keys. Route input through one pump instead.
		t.pump = newInputPump(opts.In)
	}
	return t, true
}

// Queued reports how many prompts are waiting behind the one currently shown.
func (t *TTYApprover) Queued() int { return int(t.waiting.Load()) }

// Approve shows the prompt and blocks until a key is pressed, the timeout elapses, or ctx ends.
func (t *TTYApprover) Approve(ctx context.Context, req Request) Decision {
	if ctx.Err() != nil {
		return Deny
	}
	t.waiting.Add(1)
	select {
	case t.sem <- struct{}{}:
		t.waiting.Add(-1)
	case <-ctx.Done():
		t.waiting.Add(-1)
		return Deny
	}
	defer func() { <-t.sem }()

	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	if ctx.Err() != nil {
		return Deny
	}
	deadline, _ := ctx.Deadline()

	in := t.in
	if t.pump != nil {
		pr := t.pump.reader()
		defer pr.Close()
		in = pr
	}

	model := NewModel(ApprovalRequest{
		AgentID:   req.AgentID,
		ActAsUser: req.ActAsUser,
		ToolName:  req.Tool,
		TargetURI: req.Target,
		Params:    req.Params,
		Reason:    req.Reason,
	})
	model.deadline = deadline
	model.pending = t.Queued

	killCtx, kill := context.WithCancel(context.Background())
	defer kill()
	prog := tea.NewProgram(model,
		tea.WithContext(killCtx),
		tea.WithInput(in),
		tea.WithOutput(t.out),
		tea.WithoutSignalHandler(),
	)

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-done:
			return
		case <-ctx.Done():
		}
		sent := make(chan struct{})
		go func() {
			defer close(sent)
			// Returns once delivered or once the program has stopped (its context is cancelled).
			prog.Send(abortMsg{timedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)})
		}()
		select {
		case <-done:
		case <-time.After(t.abortGrace):
			kill()
		}
		<-sent
	}()

	final, err := prog.Run()
	close(done)
	wg.Wait()

	if err != nil {
		return Deny
	}
	m, ok := final.(Model)
	if !ok {
		return Deny
	}
	if d, answered := m.Decision(); answered {
		return d
	}
	return Deny
}

// inputPump owns the only goroutine reading a non-file input and hands bytes to the active prompt.
type inputPump struct {
	ch   chan []byte
	done chan struct{}
	err  error
}

func newInputPump(r io.Reader) *inputPump {
	p := &inputPump{ch: make(chan []byte), done: make(chan struct{})}
	go func() {
		for {
			buf := make([]byte, 256)
			n, err := r.Read(buf)
			if n > 0 {
				select {
				case p.ch <- buf[:n]:
				case <-p.done:
				}
			}
			if err != nil {
				p.err = err
				close(p.done)
				return
			}
		}
	}()
	return p
}

// reader returns a per-prompt reader. Input typed before the prompt appeared is discarded so a
// stray keypress cannot approve a request the human has not seen.
func (p *inputPump) reader() *pumpReader {
	for {
		select {
		case <-p.ch:
			continue
		default:
		}
		break
	}
	return &pumpReader{p: p, closed: make(chan struct{})}
}

type pumpReader struct {
	p      *inputPump
	closed chan struct{}
	once   sync.Once
	rest   []byte
}

func (r *pumpReader) Read(b []byte) (int, error) {
	if len(r.rest) > 0 {
		n := copy(b, r.rest)
		r.rest = r.rest[n:]
		return n, nil
	}
	select {
	case <-r.closed:
		return 0, io.EOF
	default:
	}
	select {
	case chunk := <-r.p.ch:
		n := copy(b, chunk)
		r.rest = chunk[n:]
		return n, nil
	case <-r.p.done:
		return 0, io.EOF
	case <-r.closed:
		return 0, io.EOF
	}
}

func (r *pumpReader) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}
