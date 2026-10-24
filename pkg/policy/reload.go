package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
)

// SetPolicy atomically replaces the ruleset (hot reload). Per-session taints and one_time
// consumption are kept: consumption is keyed by rule fingerprint, so an unchanged one_time rule
// stays consumed while a rule whose match or scope changed starts fresh. Session grants
// ("approve for this session") are cleared, because the human gave them under the old rules.
func (e *Engine) SetPolicy(p Policy) {
	if p.DefaultAction == "" {
		p.DefaultAction = ActionDeny
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policy = p
	for _, s := range e.sessions {
		s.granted = make(map[string]bool)
	}
}

// Sum returns the hex SHA-256 of policy file content.
func Sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ShortSum is the 12-hex-digit prefix of a Sum used in logs and audit targets.
func ShortSum(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

// AuditLogger is the subset of *audit.Logger the watcher uses.
type AuditLogger interface {
	Log(audit.Entry) error
}

// WatcherConfig configures a policy Watcher.
type WatcherConfig struct {
	Path   string
	Engine *Engine
	// Load turns file content into a policy, strictly: it must reject unknown keys, validation
	// errors and (when pinned) unapproved content. A rejected reload keeps the current policy.
	Load func(data []byte) (Policy, error)
	// InitialSum is the Sum of the content Engine was built from ("" when it wasn't a file).
	InitialSum string
	// Deps are extra files (e.g. the pin file) whose change re-attempts a load.
	Deps []string
	// Interval between polls (default 1s).
	Interval time.Duration
	// Audit, when set, records every reload attempt as tool "policy/reload".
	Audit AuditLogger
	// Stderr receives "[nexus] policy reload…" lines (default os.Stderr).
	Stderr io.Writer
	// OnReload runs after a successful swap.
	OnReload func(Policy)
	// NoSignal disables SIGHUP-triggered reloads (e.g. when SIGHUP is relayed to a child).
	NoSignal bool
}

type fileStamp struct {
	mod  time.Time
	size int64
	ok   bool
}

func stampOf(path string) fileStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{mod: fi.ModTime(), size: fi.Size(), ok: true}
}

// Watcher hot-reloads a policy file: it polls mtime, size and SHA-256 every Interval, and on
// unix also reloads on SIGHUP. A file that fails to load is reported once (stderr + audit) and
// the engine keeps its current policy.
type Watcher struct {
	cfg WatcherConfig

	mu      sync.Mutex
	lastSum string // content last attempted (loaded or rejected)
	stamp   fileStamp
	deps    []fileStamp
	missing bool

	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
	started bool
}

// NewWatcher builds a watcher; call Start to begin polling.
func NewWatcher(cfg WatcherConfig) *Watcher {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	w := &Watcher{cfg: cfg, lastSum: cfg.InitialSum, stop: make(chan struct{}), done: make(chan struct{})}
	w.stamp = stampOf(cfg.Path)
	for _, d := range cfg.Deps {
		w.deps = append(w.deps, stampOf(d))
	}
	return w
}

// Start begins polling (and SIGHUP handling on unix) in the background.
func (w *Watcher) Start() {
	w.mu.Lock()
	w.started = true
	w.mu.Unlock()
	hup := make(chan os.Signal, 1)
	if !w.cfg.NoSignal {
		notifyReload(hup)
	}
	go func() {
		defer close(w.done)
		defer stopReloadNotify(hup)
		t := time.NewTicker(w.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-w.stop:
				return
			case <-hup:
				_ = w.Reload()
			case <-t.C:
				w.Poll()
			}
		}
	}()
}

// Close stops the watcher and waits for it to exit. Safe to call more than once, and on a
// watcher that was never started.
func (w *Watcher) Close() {
	w.once.Do(func() {
		close(w.stop)
	})
	w.mu.Lock()
	started := w.started
	w.mu.Unlock()
	if !started {
		return
	}
	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
	}
}

// Reload forces a load of the file, even if it looks unchanged.
func (w *Watcher) Reload() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.check(true)
}

// Poll loads the file if it changed since the last attempt (or a dependency changed).
func (w *Watcher) Poll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	force := false
	for i, d := range w.cfg.Deps {
		if st := stampOf(d); st != w.deps[i] {
			w.deps[i] = st
			force = true
		}
	}
	_ = w.check(force)
}

func (w *Watcher) check(force bool) error {
	st := stampOf(w.cfg.Path)
	if !st.ok {
		if !w.missing || force {
			w.missing = true
			err := fmt.Errorf("%s is missing or unreadable; keeping the current policy", w.cfg.Path)
			w.report(false, "", err)
			return err
		}
		return nil
	}
	// mtime+size short-circuit; content written within the filesystem's timestamp granularity
	// is re-hashed so same-size edits in the same tick aren't missed.
	if !force && !w.missing && st == w.stamp && time.Since(st.mod) > 3*time.Second {
		return nil
	}
	w.missing = false
	w.stamp = st
	data, err := os.ReadFile(w.cfg.Path)
	if err != nil {
		w.report(false, "", err)
		return err
	}
	sum := Sum(data)
	if !force && sum == w.lastSum {
		return nil
	}
	w.lastSum = sum
	p, err := w.cfg.Load(data)
	if err == nil && w.cfg.Engine == nil {
		err = errors.New("no engine to reload")
	}
	if err != nil {
		w.report(false, sum, err)
		return err
	}
	w.cfg.Engine.SetPolicy(p)
	w.report(true, sum, nil)
	if w.cfg.OnReload != nil {
		w.cfg.OnReload(p)
	}
	return nil
}

func (w *Watcher) report(ok bool, sum string, err error) {
	target := w.cfg.Path
	if sum != "" {
		target += "#sha256:" + ShortSum(sum)
	}
	decision, reason := "allow", "policy reloaded"
	if ok {
		fmt.Fprintf(w.cfg.Stderr, "[nexus] policy reloaded from %s (sha256:%s)\n", w.cfg.Path, ShortSum(sum))
	} else {
		decision, reason = "deny", err.Error()
		fmt.Fprintf(w.cfg.Stderr, "[nexus] policy reload failed: %v (keeping the current policy)\n", err)
	}
	if w.cfg.Audit != nil {
		_ = w.cfg.Audit.Log(audit.Entry{
			Agent:    "nexus-cli",
			ActAs:    "nexus-cli",
			Tool:     "policy/reload",
			Target:   target,
			Decision: decision,
			Reason:   reason,
		})
	}
}
