package audit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestAuditHelperProcess is the child side of the cross-process tests; it is a no-op unless
// spawned with NEXUS_AUDIT_HELPER set.
func TestAuditHelperProcess(t *testing.T) {
	path := os.Getenv("NEXUS_AUDIT_HELPER")
	if path == "" {
		t.Skip("helper process")
	}
	n, _ := strconv.Atoi(os.Getenv("NEXUS_AUDIT_N"))
	maxBytes, _ := strconv.ParseInt(os.Getenv("NEXUS_AUDIT_MAX"), 10, 64)
	l, err := OpenWithOptions(path, Options{Fsync: true, MaxBytes: maxBytes})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for i := 0; i < n; i++ {
		if err := l.Log(Entry{Agent: os.Getenv("NEXUS_AUDIT_ID"), Target: strconv.Itoa(i), Decision: "allow"}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		}
	}
	if err := l.Close(); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

func runWriters(t *testing.T, path string, procs, n int, maxBytes int64) {
	t.Helper()
	cmds := make([]*exec.Cmd, procs)
	for i := range cmds {
		c := exec.Command(os.Args[0], "-test.run=^TestAuditHelperProcess$", "-test.count=1")
		c.Env = append(os.Environ(),
			"NEXUS_AUDIT_HELPER="+path,
			"NEXUS_AUDIT_N="+strconv.Itoa(n),
			"NEXUS_AUDIT_MAX="+strconv.FormatInt(maxBytes, 10),
			fmt.Sprintf("NEXUS_AUDIT_ID=p%d", i))
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[i] = c
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
}

func checkWriters(t *testing.T, path string, procs, n int) VerifyResult {
	t.Helper()
	res, err := VerifyWithOptions(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("chain forked or corrupted: %v", err)
	}
	if res.Entries != procs*n || res.HeadSeq != uint64(procs*n) {
		t.Fatalf("got %+v, want %d entries", res, procs*n)
	}
	all, _ := ReadAll(path)
	per := map[string]int{}
	for _, e := range all {
		if strconv.Itoa(per[e.Agent]) != e.Target {
			t.Fatalf("%s wrote out of order: %s", e.Agent, e.Target)
		}
		per[e.Agent]++
	}
	return res
}

func TestCrossProcessWriters(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	runWriters(t, path, 2, 200, -1)
	checkWriters(t, path, 2, 200)
}

func TestCrossProcessWritersWithRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	runWriters(t, path, 3, 150, 4096)
	if res := checkWriters(t, path, 3, 150); res.Files < 3 {
		t.Fatalf("expected rotation, %+v", res)
	}
}
