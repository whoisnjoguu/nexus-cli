package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
)

// StatusInterval is how often a running gateway refreshes its status file.
const StatusInterval = 10 * time.Second

// UpstreamStatus is the observable state of one upstream.
type UpstreamStatus struct {
	Name      string    `json:"name"`
	Transport string    `json:"transport"`
	State     string    `json:"state"` // starting | up | restarting | down | disabled | stopped
	Tools     int       `json:"tools"`
	Restarts  int       `json:"restarts"`
	LastError string    `json:"last_error,omitempty"`
	Since     time.Time `json:"since"`
	Protocol  string    `json:"protocol,omitempty"`
}

// StatusFile is the content of <nexus home>/mcp/<pid>.json written by a running gateway.
type StatusFile struct {
	PID       int              `json:"pid"`
	Version   string           `json:"version"`
	Started   time.Time        `json:"started"`
	Updated   time.Time        `json:"updated"`
	CWD       string           `json:"cwd,omitempty"`
	Policy    string           `json:"policy,omitempty"`
	HTTP      string           `json:"http,omitempty"`
	Sessions  int              `json:"sessions"`
	Upstreams []UpstreamStatus `json:"upstreams"`

	Path string `json:"-"` // file it was read from
}

// Stale reports whether the writer stopped refreshing the file (it probably exited uncleanly).
func (f StatusFile) Stale(now time.Time) bool {
	return now.Sub(f.Updated) > 3*StatusInterval
}

// Alive reports whether the gateway that wrote the file is still running. A file whose process
// is gone is left over from an unclean exit.
func (f StatusFile) Alive() bool { return processAlive(f.PID) }

// CleanStatusFiles drops status files whose process no longer exists, deleting them from disk,
// and returns the remaining files plus how many were removed.
func CleanStatusFiles(files []StatusFile) ([]StatusFile, int) {
	var keep []StatusFile
	removed := 0
	for _, f := range files {
		if f.PID != os.Getpid() && !f.Alive() {
			if f.Path != "" && os.Remove(f.Path) == nil {
				removed++
			}
			continue
		}
		keep = append(keep, f)
	}
	return keep, removed
}

// HomeDir returns the nexus state directory ($NEXUS_HOME, or ~/.nexus).
func HomeDir() (string, error) { return audit.Home() }

// StatusDir returns the directory gateways write status files to (<nexus home>/mcp).
func StatusDir() (string, error) {
	h, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "mcp"), nil
}

// ReadStatusFiles loads every gateway status file in dir, newest first. A missing dir is empty.
func ReadStatusFiles(dir string) ([]StatusFile, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []StatusFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimSuffix(name, ".json")); err != nil {
			continue
		}
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var f StatusFile
		if json.Unmarshal(data, &f) != nil {
			continue
		}
		f.Path = p
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out, nil
}

// statusWriter periodically writes the gateway's status file.
type statusWriter struct {
	srv     *Server
	dir     string
	path    string
	policy  string
	httpMu  sync.Mutex
	http    string
	cwd     string
	started time.Time

	kickCh chan struct{}
	stopCh chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
}

func (w *statusWriter) configure(s *Server, dir, policyPath, httpAddr string) {
	w.srv = s
	w.dir = dir
	w.policy = policyPath
	w.http = httpAddr
	w.cwd, _ = os.Getwd()
	w.started = time.Now()
	w.kickCh = make(chan struct{}, 1)
	w.stopCh = make(chan struct{})
	if dir != "" {
		w.path = filepath.Join(dir, strconv.Itoa(os.Getpid())+".json")
	}
}

// SetHTTPAddr records the Streamable HTTP listen address in the status file.
func (s *Server) SetHTTPAddr(addr string) {
	s.status.httpMu.Lock()
	s.status.http = addr
	s.status.httpMu.Unlock()
	s.status.kick()
}

func (w *statusWriter) start() {
	if w.path == "" {
		return
	}
	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		w.srv.logf("status dir: %v", err)
		w.path = ""
		return
	}
	w.write()
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		tick := time.NewTicker(StatusInterval)
		defer tick.Stop()
		for {
			select {
			case <-w.stopCh:
				return
			case <-tick.C:
			case <-w.kickCh:
			}
			w.write()
		}
	}()
}

func (w *statusWriter) kick() {
	if w.kickCh == nil {
		return
	}
	select {
	case w.kickCh <- struct{}{}:
	default:
	}
}

func (w *statusWriter) snapshot() StatusFile {
	s := w.srv
	s.sessMu.Lock()
	n := len(s.sessions)
	s.sessMu.Unlock()
	w.httpMu.Lock()
	httpAddr := w.http
	w.httpMu.Unlock()
	return StatusFile{
		PID:       os.Getpid(),
		Version:   s.version,
		Started:   w.started,
		Updated:   time.Now(),
		CWD:       w.cwd,
		Policy:    w.policy,
		HTTP:      httpAddr,
		Sessions:  n,
		Upstreams: s.Status(),
	}
}

func (w *statusWriter) write() {
	if w.path == "" {
		return
	}
	data, err := json.MarshalIndent(w.snapshot(), "", "  ")
	if err != nil {
		return
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		w.srv.logf("write status: %v", err)
		return
	}
	if err := os.Rename(tmp, w.path); err != nil {
		_ = os.Remove(tmp)
		w.srv.logf("write status: %v", err)
	}
}

func (w *statusWriter) stop() {
	if w.stopCh == nil {
		return
	}
	w.once.Do(func() {
		close(w.stopCh)
		w.wg.Wait()
		if w.path != "" {
			_ = os.Remove(w.path)
		}
	})
}
