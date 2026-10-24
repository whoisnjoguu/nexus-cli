package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/mcp"
)

func runMCPStatus(t *testing.T, args ...string) string {
	t.Helper()
	c := newMCPStatusCmd()
	var out bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&out)
	c.SetArgs(args)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func writeStatusFile(t *testing.T, f mcp.StatusFile) {
	t.Helper()
	dir, err := mcp.StatusDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(f)
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(f.PID)+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMCPStatusEmpty(t *testing.T) {
	t.Setenv("NEXUS_HOME", t.TempDir())
	if out := runMCPStatus(t); !strings.Contains(out, "no running nexus-cli MCP gateways") {
		t.Fatalf("%q", out)
	}
	if out := strings.TrimSpace(runMCPStatus(t, "--json")); out != "[]" {
		t.Fatalf("%q", out)
	}
}

func TestMCPStatusOutput(t *testing.T) {
	t.Setenv("NEXUS_HOME", t.TempDir())
	now := time.Now()
	writeStatusFile(t, mcp.StatusFile{
		PID: os.Getpid(), Version: "v9.9.9", Started: now.Add(-time.Hour), Updated: now,
		CWD: "/work/repo", Policy: "/work/repo/nexus.yaml", HTTP: "127.0.0.1:8765", Sessions: 2,
		Upstreams: []mcp.UpstreamStatus{
			{Name: "fs", Transport: "stdio", State: "up", Tools: 11, Since: now},
			{Name: "remote", Transport: "http", State: "down", Restarts: 5, LastError: "connection refused\nretry", Since: now},
		},
	})
	writeStatusFile(t, mcp.StatusFile{PID: os.Getppid(), Version: "v1", Started: now.Add(-2 * time.Hour), Updated: now.Add(-time.Hour)})
	// A file left behind by a gateway that no longer exists is cleaned up.
	writeStatusFile(t, mcp.StatusFile{PID: 999999999, Version: "dead", Started: now, Updated: now})

	out := runMCPStatus(t)
	for _, want := range []string{
		fmt.Sprintf("gateway pid %d (v9.9.9) running", os.Getpid()), "policy:   /work/repo/nexus.yaml", "http://127.0.0.1:8765/mcp",
		"sessions: 2", "UPSTREAM", "fs", "stdio", "up", "11", "remote", "down", "connection refused retry",
		fmt.Sprintf("gateway pid %d (v1) stale", os.Getppid()), "(no upstream servers configured)",
		"removed 1 status file(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	var files []mcp.StatusFile
	if err := json.Unmarshal([]byte(runMCPStatus(t, "--json")), &files); err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files", len(files))
	}
	if strings.Contains(out, "(dead)") {
		t.Error("dead gateway listed")
	}
	dir, _ := mcp.StatusDir()
	if _, err := os.Stat(filepath.Join(dir, "999999999.json")); !os.IsNotExist(err) {
		t.Error("dead gateway status file not removed")
	}
}

func TestWriteHTTPToken(t *testing.T) {
	t.Setenv("NEXUS_HOME", t.TempDir())
	path, err := writeHTTPToken("secret-token")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != "secret-token" {
		t.Fatalf("%q %v", data, err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
}

func TestMCPLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8765": true, "[::1]:1": true, "localhost:80": true, "0.0.0.0:8765": false, "192.168.1.2:1": false,
	} {
		if got := mcpIsLoopbackAddr(addr); got != want {
			t.Errorf("%s: got %v", addr, got)
		}
	}
}
