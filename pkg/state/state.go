// Package state persists small pieces of security state (consumed token IDs, one_time rule
// consumption, session taints) across nexus-cli restarts and between concurrent nexus-cli
// processes sharing a NEXUS_HOME.
//
// A store is one JSON file of expiring key/value entries under $NEXUS_HOME/state (0700 dir,
// 0600 files). Every Update runs under an in-process mutex plus an advisory cross-process lock
// on "<file>.lock", reads the current content, prunes expired entries, applies the change and
// atomically replaces the file, so check-then-insert operations are atomic across processes.
//
// A corrupt file is logged, moved aside to "<file>.corrupt" and treated as empty. This fails
// open for availability (a damaged state file must not brick the proxy): the worst case is that
// unexpired single-use tokens or one_time rules become usable once more. The state directory is
// inside NEXUS_HOME, which the policy guard keeps out of reach of gated agents.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/whoisnjoguu/nexus-cli/internal/atomicfile"
	"github.com/whoisnjoguu/nexus-cli/internal/fslock"
)

// Entry is one stored value and the time after which it is discarded.
type Entry struct {
	Value   json.RawMessage `json:"v,omitempty"`
	Expires time.Time       `json:"exp"`
}

type fileFormat struct {
	Version int              `json:"version"`
	Entries map[string]Entry `json:"entries"`
}

// File is a persistent, expiring key/value store backed by one JSON file.
type File struct {
	path string
	mu   sync.Mutex

	// Now is the clock used for expiry (tests may replace it before use).
	Now func() time.Time
	// Logf receives warnings such as a corrupt file being reset. Defaults to stderr.
	Logf func(format string, args ...any)
}

// Dir returns the state directory: $NEXUS_HOME/state (or ~/.nexus/state).
func Dir() (string, error) {
	if h := os.Getenv("NEXUS_HOME"); h != "" {
		return filepath.Join(h, "state"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".nexus", "state"), nil
}

// DefaultPath returns <state dir>/<name>.
func DefaultPath(name string) (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, name), nil
}

// Open prepares a store at path, creating its directory with mode 0700.
func Open(path string) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	return &File{
		path: path,
		Now:  time.Now,
		Logf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) },
	}, nil
}

// Path returns the backing file.
func (f *File) Path() string { return f.path }

// read loads the file; corrupt reports undecodable content (treated as empty).
func (f *File) read() (entries map[string]Entry, corrupt bool, err error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]Entry{}, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read state %s: %w", f.path, err)
	}
	var ff fileFormat
	if len(data) == 0 {
		return map[string]Entry{}, false, nil
	}
	if uerr := json.Unmarshal(data, &ff); uerr != nil {
		f.Logf("[nexus] state file %s is corrupt (%v); treating it as empty", f.path, uerr)
		return map[string]Entry{}, true, nil
	}
	if ff.Entries == nil {
		ff.Entries = map[string]Entry{}
	}
	return ff.Entries, false, nil
}

func (f *File) prune(m map[string]Entry) bool {
	now := f.Now()
	pruned := false
	for k, e := range m {
		if !e.Expires.IsZero() && !now.Before(e.Expires) {
			delete(m, k)
			pruned = true
		}
	}
	return pruned
}

// Snapshot returns the current unexpired entries without taking the cross-process lock (writes
// are atomic renames, so the content is always a complete version).
func (f *File) Snapshot() (map[string]Entry, error) {
	m, _, err := f.read()
	if err != nil {
		return nil, err
	}
	f.prune(m)
	return m, nil
}

// Get returns one unexpired entry.
func (f *File) Get(key string) (Entry, bool, error) {
	m, err := f.Snapshot()
	if err != nil {
		return Entry{}, false, err
	}
	e, ok := m[key]
	return e, ok, nil
}

// Update atomically applies fn to the unexpired entries across processes. fn reports whether it
// changed the map; the file is rewritten when it did or when expired entries were pruned. An
// error from fn aborts without writing.
func (f *File) Update(fn func(m map[string]Entry) (changed bool, err error)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	release, err := fslock.Acquire(f.path + ".lock")
	if err != nil {
		return err
	}
	defer release()

	m, corrupt, err := f.read()
	if err != nil {
		return err
	}
	pruned := f.prune(m)
	changed, err := fn(m)
	if err != nil {
		return err
	}
	if !changed && !pruned && !corrupt {
		return nil
	}
	if corrupt {
		_ = os.Rename(f.path, f.path+".corrupt")
	}
	data, err := json.Marshal(fileFormat{Version: 1, Entries: m})
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return atomicfile.Write(f.path, data, 0o600)
}
