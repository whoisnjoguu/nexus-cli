package jwt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPersistentReplayAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "jti.json")
	g1, err := NewPersistentReplayGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := g1.Use("abc", exp); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := g1.Use("abc", exp); err == nil {
		t.Fatal("reuse in same instance accepted")
	}
	g2, err := NewPersistentReplayGuard(path) // simulates a restart
	if err != nil {
		t.Fatal(err)
	}
	if err := g2.Use("abc", exp); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("reuse after restart: %v", err)
	}
	if err := g2.Use("other", exp); err != nil {
		t.Fatalf("fresh jti rejected: %v", err)
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Fatalf("state file mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm() != 0o700 && os.PathSeparator == '/' {
		t.Fatalf("state dir mode %v", fi.Mode().Perm())
	}
}

func TestPersistentReplayConcurrentGoroutines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jti.json")
	exp := time.Now().Add(time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		g, err := NewPersistentReplayGuard(path)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.Use("same", exp) == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d winners, want exactly 1", wins)
	}
}

func TestPersistentReplayCorruptFileTreatedAsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jti.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := NewPersistentReplayGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	var logged string
	g.store.Logf = func(f string, a ...any) { logged = fmt.Sprintf(f, a...) }
	if err := g.Use("x", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("use after corruption: %v", err)
	}
	if !strings.Contains(logged, "corrupt") {
		t.Fatalf("corruption not logged: %q", logged)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt file not kept aside: %v", err)
	}
	if err := g.Use("x", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("replay accepted after reset")
	}
}

// TestHelperReplayProcess is the child side of TestPersistentReplayAcrossProcesses.
func TestHelperReplayProcess(t *testing.T) {
	path := os.Getenv("NEXUS_REPLAY_HELPER")
	if path == "" {
		t.Skip("helper process only")
	}
	g, err := NewPersistentReplayGuard(path)
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(3)
	}
	// Start together: wait for the parent's go file.
	for i := 0; i < 500; i++ {
		if _, err := os.Stat(path + ".go"); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := g.Use("raced-jti", time.Now().Add(time.Hour)); err != nil {
		fmt.Println("LOST", err)
		os.Exit(2)
	}
	fmt.Println("WON")
	os.Exit(0)
}

func TestPersistentReplayAcrossProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	path := filepath.Join(t.TempDir(), "jti.json")
	const n = 4
	cmds := make([]*exec.Cmd, n)
	outs := make([]*strings.Builder, n)
	for i := range cmds {
		c := exec.Command(os.Args[0], "-test.run=^TestHelperReplayProcess$", "-test.count=1")
		c.Env = append(os.Environ(), "NEXUS_REPLAY_HELPER="+path)
		outs[i] = &strings.Builder{}
		c.Stdout, c.Stderr = outs[i], outs[i]
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = c
	}
	time.Sleep(200 * time.Millisecond)
	if err := os.WriteFile(path+".go", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	won, lost := 0, 0
	for i, c := range cmds {
		err := c.Wait()
		out := outs[i].String()
		switch {
		case err == nil && strings.Contains(out, "WON"):
			won++
		case strings.Contains(out, "LOST"):
			lost++
		default:
			t.Fatalf("helper %d: %v\n%s", i, err, out)
		}
	}
	if won != 1 || lost != n-1 {
		t.Fatalf("won=%d lost=%d, want exactly one winner", won, lost)
	}
}
