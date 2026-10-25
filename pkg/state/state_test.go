package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateGetExpiry(t *testing.T) {
	f, err := Open(filepath.Join(t.TempDir(), "s", "x.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	f.Now = func() time.Time { return now }
	err = f.Update(func(m map[string]Entry) (bool, error) {
		m["a"] = Entry{Value: json.RawMessage(`1`), Expires: now.Add(time.Minute)}
		m["b"] = Entry{Value: json.RawMessage(`2`), Expires: now.Add(time.Hour)}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if e, ok, _ := f.Get("a"); !ok || string(e.Value) != "1" {
		t.Fatalf("get a = %v %v", e, ok)
	}
	now = now.Add(2 * time.Minute)
	if _, ok, _ := f.Get("a"); ok {
		t.Fatal("expired entry returned")
	}
	// A no-op update still prunes the expired entry from disk.
	if err := f.Update(func(map[string]Entry) (bool, error) { return false, nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(f.Path())
	var ff fileFormat
	if err := json.Unmarshal(raw, &ff); err != nil || len(ff.Entries) != 1 {
		t.Fatalf("on-disk entries = %v (%v)", ff.Entries, err)
	}
}

func TestUpdateErrorAborts(t *testing.T) {
	f, err := Open(filepath.Join(t.TempDir(), "x.json"))
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err = f.Update(func(m map[string]Entry) (bool, error) {
		m["a"] = Entry{}
		return true, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(f.Path()); !os.IsNotExist(err) {
		t.Fatal("file written despite error")
	}
}

func TestDirHonoursNexusHome(t *testing.T) {
	t.Setenv("NEXUS_HOME", filepath.Join("x", "home"))
	d, err := Dir()
	if err != nil || d != filepath.Join("x", "home", "state") {
		t.Fatalf("Dir = %q, %v", d, err)
	}
}

func TestDefaultPathAndHomeFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	d, err := Dir()
	if err != nil || d != filepath.Join(home, ".nexus", "state") {
		t.Fatalf("Dir = %q, %v", d, err)
	}
	p, err := DefaultPath("replay.json")
	if err != nil || p != filepath.Join(home, ".nexus", "state", "replay.json") {
		t.Fatalf("DefaultPath = %q, %v", p, err)
	}
}

func TestCorruptFileIsMovedAsideAndReset(t *testing.T) {
	f, err := Open(filepath.Join(t.TempDir(), "x.json"))
	if err != nil {
		t.Fatal(err)
	}
	var logged string
	f.Logf = func(format string, _ ...any) { logged = format }
	if err := os.WriteFile(f.Path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if m, err := f.Snapshot(); err != nil || len(m) != 0 || logged == "" {
		t.Fatalf("snapshot of corrupt file = %v, %v (logged %q)", m, err, logged)
	}
	// Even a no-op update rewrites a corrupt file and keeps the damaged copy for inspection.
	if err := f.Update(func(map[string]Entry) (bool, error) { return false, nil }); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(f.Path() + ".corrupt"); err != nil || string(b) != "{not json" {
		t.Fatalf("corrupt copy = %q, %v", b, err)
	}
	raw, _ := os.ReadFile(f.Path())
	var ff fileFormat
	if err := json.Unmarshal(raw, &ff); err != nil || ff.Version != 1 {
		t.Fatalf("rewritten file = %q, %v", raw, err)
	}

	// An empty file and a file with no entries both read as empty.
	for _, content := range []string{"", `{"version":1}`} {
		if err := os.WriteFile(f.Path(), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := f.Get("a"); ok || err != nil {
			t.Fatalf("%q: get = %v, %v", content, ok, err)
		}
	}
}

func TestOpenAndReadErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(blocker, "sub", "x.json")); err == nil {
		t.Fatal("Open under a regular file succeeded")
	}
	// The store path is a directory: reads must fail rather than report "empty".
	f, err := Open(filepath.Join(dir, "isdir"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Snapshot(); err == nil {
		t.Fatal("Snapshot of a directory succeeded")
	}
	if _, _, err := f.Get("a"); err == nil {
		t.Fatal("Get of a directory succeeded")
	}
	if err := f.Update(func(map[string]Entry) (bool, error) { return true, nil }); err == nil {
		t.Fatal("Update of a directory succeeded")
	}
}
