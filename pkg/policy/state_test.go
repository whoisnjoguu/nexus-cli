package policy

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func statePolicy() Policy {
	return Policy{
		DefaultAction:       ActionDeny,
		EscalateWhenTainted: true,
		Tools: []Rule{
			{Match: Match{Tool: "pay"}, Action: ActionAllow, OneTime: true},
			{Match: Match{Tool: "read_secret"}, Action: ActionAllow, Taints: []string{"secret"}},
			{Match: Match{Tool: "write_file"}, Action: ActionHITL},
			{Match: Match{Method: "GET"}, Action: ActionAllow},
		},
	}
}

func storeAt(t *testing.T, path string) *FileStateStore {
	t.Helper()
	st, err := NewFileStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func engineWithStore(t *testing.T, path string) *Engine {
	t.Helper()
	e := NewEngine(statePolicy())
	e.SetStateStore(storeAt(t, path))
	return e
}

func TestOneTimeSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "sessions.json")
	pay := Request{SessionID: "agent|alice", Tool: "pay"}
	e1 := engineWithStore(t, path)
	if d := e1.Evaluate(pay); d.Action != ActionAllow {
		t.Fatalf("first pay = %+v", d)
	}
	e2 := engineWithStore(t, path) // "restart"
	if d := e2.Evaluate(pay); d.Action != ActionDeny || !strings.Contains(d.Reason, "one-time") {
		t.Fatalf("pay after restart = %+v", d)
	}
	// Other sessions are unaffected.
	if d := e2.Evaluate(Request{SessionID: "agent|bob", Tool: "pay"}); d.Action != ActionAllow {
		t.Fatalf("other session = %+v", d)
	}
	if fi, err := os.Stat(path); err != nil || (os.PathSeparator == '/' && fi.Mode().Perm() != 0o600) {
		t.Fatalf("state file: %v %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || (os.PathSeparator == '/' && fi.Mode().Perm() != 0o700) {
		t.Fatalf("state dir: %v %v", fi, err)
	}
	// Without a store the restart forgets (the old behaviour, e.g. --ephemeral-state).
	if d := NewEngine(statePolicy()).Evaluate(pay); d.Action != ActionAllow {
		t.Fatalf("ephemeral = %+v", d)
	}
}

func TestTaintSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	sess := "agent|alice"
	e1 := engineWithStore(t, path)
	if d := e1.Evaluate(Request{SessionID: sess, Tool: "read_secret"}); d.Action != ActionAllow {
		t.Fatal(d)
	}
	e2 := engineWithStore(t, path)
	d := e2.Evaluate(Request{SessionID: sess, Method: "GET", Host: "evil.example", Path: "/"})
	if d.Action != ActionHITL || !d.TaintEscalated {
		t.Fatalf("egress after restart = %+v", d)
	}
}

func TestGrantsAreNotPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	req := Request{SessionID: "s", Tool: "write_file"}
	e1 := engineWithStore(t, path)
	e1.GrantSession(req, e1.Evaluate(req))
	if d := e1.Evaluate(req); d.Action != ActionAllow {
		t.Fatalf("grant = %+v", d)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a grant alone wrote session state")
	}
	if d := engineWithStore(t, path).Evaluate(req); d.Action != ActionHITL {
		t.Fatalf("grant persisted: %+v", d)
	}
}

func TestStateStoreMergesAcrossWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	a, b := storeAt(t, path), storeAt(t, path)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			if err := a.Save("s", SessionSnapshot{Taints: []string{"a" + string(rune('a'+i))}}); err != nil {
				t.Error(err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if err := b.Save("s", SessionSnapshot{Consumed: []string{"b" + string(rune('a'+i))}}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	snap, err := storeAt(t, path).Load("s")
	if err != nil || len(snap.Taints) != 20 || len(snap.Consumed) != 20 {
		t.Fatalf("merged = %+v %v", snap, err)
	}
}

func TestStateExpiresWithIdleTTL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	st := storeAt(t, path)
	st.TTL = 20 * time.Millisecond
	e1 := NewEngine(statePolicy())
	e1.SetStateStore(st)
	pay := Request{SessionID: "s", Tool: "pay"}
	e1.Evaluate(pay)
	time.Sleep(60 * time.Millisecond)
	if d := engineWithStore(t, path).Evaluate(pay); d.Action != ActionAllow {
		t.Fatalf("expired state still applied: %+v", d)
	}
}

func TestCorruptStateIsTreatedAsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := storeAt(t, path)
	var logged []string
	var mu sync.Mutex
	st.f.Logf = func(f string, a ...any) { mu.Lock(); logged = append(logged, f); mu.Unlock() }
	e := NewEngine(statePolicy())
	e.SetStateStore(st)
	if d := e.Evaluate(Request{SessionID: "s", Tool: "pay"}); d.Action != ActionAllow {
		t.Fatalf("corrupt state: %+v", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logged) == 0 {
		t.Fatal("corrupt state not logged")
	}
	if d := engineWithStore(t, path).Evaluate(Request{SessionID: "s", Tool: "pay"}); d.Action != ActionDeny {
		t.Fatalf("state not rewritten after corruption: %+v", d)
	}
}

type failingStore struct{}

func (failingStore) Load(string) (SessionSnapshot, error) { return SessionSnapshot{}, os.ErrPermission }
func (failingStore) Save(string, SessionSnapshot) error   { return os.ErrPermission }

func TestStateStoreFailureKeepsWorkingInMemory(t *testing.T) {
	var msgs []string
	old := StateErrorf
	StateErrorf = func(f string, a ...any) { msgs = append(msgs, f) }
	t.Cleanup(func() { StateErrorf = old })
	e := NewEngine(statePolicy())
	e.SetStateStore(failingStore{})
	pay := Request{SessionID: "s", Tool: "pay"}
	if e.Evaluate(pay).Action != ActionAllow || e.Evaluate(pay).Action != ActionDeny {
		t.Fatal("in-memory one_time broken by store failure")
	}
	if len(msgs) < 2 {
		t.Fatalf("errors not reported: %v", msgs)
	}
}

func TestSetPolicyKeepsPersistedConsumption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	pay := Request{SessionID: "s", Tool: "pay"}
	engineWithStore(t, path).Evaluate(pay)
	e := engineWithStore(t, path)
	e.SetPolicy(statePolicy())
	if d := e.Evaluate(pay); d.Action != ActionDeny {
		t.Fatalf("after restart+reload = %+v", d)
	}
}
