package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/mcp"
)

func writeMCPStatus(t *testing.T, home string, pid int, ups []mcp.UpstreamStatus) {
	t.Helper()
	dir := filepath.Join(home, "mcp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := mcp.StatusFile{PID: pid, Started: time.Now(), Updated: time.Now(), Upstreams: ups}
	data, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(pid)+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDoctorMCPChecks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)

	if got := doctorMCPChecks(); len(got) != 0 {
		t.Fatalf("no gateways: want no results, got %+v", got)
	}

	pid := os.Getpid()
	writeMCPStatus(t, home, pid, []mcp.UpstreamStatus{{Name: "fs", State: "up", Tools: 3}})
	got := doctorMCPChecks()
	if len(got) != 1 || !got[0].pass || !strings.Contains(got[0].msg, "1 upstream(s) healthy") {
		t.Fatalf("healthy gateway: got %+v", got)
	}

	writeMCPStatus(t, home, pid, []mcp.UpstreamStatus{
		{Name: "fs", State: "up"},
		{Name: "gh", State: "down", LastError: "exec: \"docker\": not found\nmore"},
	})
	got = doctorMCPChecks()
	if len(got) != 1 || got[0].pass {
		t.Fatalf("down upstream should fail: %+v", got)
	}
	if !strings.Contains(got[0].msg, "gh down") || !strings.Contains(got[0].msg, "docker") || strings.Contains(got[0].msg, "\n") {
		t.Fatalf("unexpected message: %q", got[0].msg)
	}
}

func TestDoctorMCPChecksDropsDeadGateways(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)
	// PID far above pid_max on Linux/macOS; treated as not running.
	writeMCPStatus(t, home, 99999999, []mcp.UpstreamStatus{{Name: "fs", State: "down"}})
	if got := doctorMCPChecks(); len(got) != 0 {
		t.Fatalf("dead gateway should be ignored: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(home, "mcp", "99999999.json")); !os.IsNotExist(err) {
		t.Fatalf("stale status file should be removed, stat err=%v", err)
	}
}
