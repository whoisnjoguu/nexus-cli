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
