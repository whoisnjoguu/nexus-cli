package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/state"
)

// SessionSnapshot is the durable part of a session: taint labels and consumed one_time rules
// (by rule fingerprint). Session grants are deliberately not persisted.
type SessionSnapshot struct {
	Taints   []string `json:"taints,omitempty"`
	Consumed []string `json:"consumed,omitempty"`
}

// StateStore persists session state so taints and one_time consumption survive restarts.
type StateStore interface {
	// Load returns the stored state of a session (empty when unknown or expired).
	Load(session string) (SessionSnapshot, error)
	// Save merges snap into the stored state of a session (state only ever grows).
	Save(session string, snap SessionSnapshot) error
}

// SetStateStore attaches a store: a session not yet in memory is hydrated from it, and every
// change to a session's taints or one_time consumption is written back. Call it before the
// engine evaluates requests; nil detaches.
func (e *Engine) SetStateStore(st StateStore) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.store = st
}

// StateErrorf reports state store failures (default: stderr). The engine keeps working from
// memory when the store fails.
var StateErrorf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[nexus] session state: "+format+"\n", args...)
}

func (e *Engine) hydrateLocked(id string, s *sessionState) {
	if e.store == nil {
		return
	}
	snap, err := e.store.Load(id)
	if err != nil {
		StateErrorf("load %q: %v", id, err)
		return
	}
	for _, t := range snap.Taints {
		s.tainted[t] = true
	}
	for _, c := range snap.Consumed {
		s.consumed[c] = true
	}
	s.persisted = len(s.tainted) + len(s.consumed)
	// savedAt stays zero so the first evaluation refreshes the stored entry's expiry.
}

func (e *Engine) persistLocked(id string, s *sessionState) {
	if e.store == nil {
		return
	}
	n := len(s.tainted) + len(s.consumed)
	now := e.now()
	if n == 0 || (n == s.persisted && now.Sub(s.savedAt) < SessionIdleTTL/2) {
		return
	}
	snap := SessionSnapshot{Taints: sortedKeys(s.tainted), Consumed: sortedKeys(s.consumed)}
	if err := e.store.Save(id, snap); err != nil {
		StateErrorf("save %q: %v", id, err)
		return
	}
	s.persisted, s.savedAt = n, now
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FileStateStore is a StateStore in a pkg/state JSON file shared safely between processes.
// Entries expire SessionIdleTTL after their last save, matching the engine's in-memory idle TTL.
type FileStateStore struct {
	f   *state.File
	TTL time.Duration
}

// NewFileStateStore opens (creating on first write) the session state file at path.
func NewFileStateStore(path string) (*FileStateStore, error) {
	f, err := state.Open(path)
	if err != nil {
		return nil, err
	}
	return &FileStateStore{f: f, TTL: SessionIdleTTL}, nil
}

// DefaultSessionStatePath returns $NEXUS_HOME/state/sessions.json.
func DefaultSessionStatePath() (string, error) { return state.DefaultPath("sessions.json") }

// Path is the backing file.
func (fs *FileStateStore) Path() string { return fs.f.Path() }

// Load implements StateStore.
func (fs *FileStateStore) Load(session string) (SessionSnapshot, error) {
	var snap SessionSnapshot
	ent, ok, err := fs.f.Get("session:" + session)
	if err != nil || !ok || len(ent.Value) == 0 {
		return snap, err
	}
	if err := json.Unmarshal(ent.Value, &snap); err != nil {
		return SessionSnapshot{}, fmt.Errorf("decode session %q: %w", session, err)
	}
	return snap, nil
}

// Save implements StateStore: the stored sets become the union of what is stored and snap, so
// processes sharing the file never drop each other's taints or consumption.
func (fs *FileStateStore) Save(session string, snap SessionSnapshot) error {
	key := "session:" + session
	return fs.f.Update(func(m map[string]state.Entry) (bool, error) {
		var cur SessionSnapshot
		if ent, ok := m[key]; ok && len(ent.Value) > 0 {
			_ = json.Unmarshal(ent.Value, &cur)
		}
		merged := SessionSnapshot{Taints: union(cur.Taints, snap.Taints), Consumed: union(cur.Consumed, snap.Consumed)}
		raw, err := json.Marshal(merged)
		if err != nil {
			return false, err
		}
		now := time.Now
		if fs.f.Now != nil {
			now = fs.f.Now
		}
		m[key] = state.Entry{Value: raw, Expires: now().Add(fs.TTL)}
		return true, nil
	})
}

func union(a, b []string) []string {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		set[s] = true
	}
	return sortedKeys(set)
}
