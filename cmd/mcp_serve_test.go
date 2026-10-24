package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mcpHelperEnv = "NEXUS_TEST_MCP_HELPER"

// TestMCPHelperProcess runs either `nexus-cli mcp serve` (mode "serve") or a minimal stdio MCP
// upstream exposing one tool, read_file (mode "upstream"). It is a no-op in normal test runs.
func TestMCPHelperProcess(t *testing.T) {
	switch os.Getenv(mcpHelperEnv) {
	case "serve":
		args := os.Args
		for i, a := range args {
			if a == "--" {
				args = args[i+1:]
				break
			}
		}
		rootCmd.SetArgs(args)
		if err := rootCmd.Execute(); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "upstream":
		in := bufio.NewScanner(os.Stdin)
		in.Buffer(make([]byte, 1<<20), 1<<20)
		for in.Scan() {
			var m struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params struct {
					ProtocolVersion string         `json:"protocolVersion"`
					Arguments       map[string]any `json:"arguments"`
				} `json:"params"`
			}
			if json.Unmarshal(in.Bytes(), &m) != nil || m.ID == nil {
				continue
			}
			var result any
			switch m.Method {
			case "initialize":
				result = map[string]any{"protocolVersion": m.Params.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}},
					"serverInfo": map[string]any{"name": "fake", "version": "1"}}
			case "tools/list":
				result = map[string]any{"tools": []any{map[string]any{"name": "read_file", "inputSchema": map[string]any{"type": "object"}}}}
			case "tools/call":
				result = map[string]any{"content": []any{map[string]any{"type": "text", "text": fmt.Sprint("ran ", m.Params.Arguments["path"])}}}
			default:
				result = map[string]any{}
			}
			out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
			fmt.Println(string(out))
		}
		os.Exit(0)
	}
}

type mcpClient struct {
	t      *testing.T
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr *lockedBuf
	id     int
}

type lockedBuf struct {
	mu  chan struct{}
	buf strings.Builder
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu <- struct{}{}
	defer func() { <-b.mu }()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu <- struct{}{}
	defer func() { <-b.mu }()
	return b.buf.String()
}

func startMCPServe(t *testing.T, dir, nexusHome string, args ...string) (*mcpClient, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestMCPHelperProcess$", "--", "mcp", "serve", "--agent-id", "t"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), mcpHelperEnv+"=serve", "NEXUS_HOME="+nexusHome, "HOME="+t.TempDir(),
		"USERPROFILE="+t.TempDir(), "NEXUS_KEY_BACKEND=file", "NEXUS_POLICY=")
	c := &mcpClient{t: t, cmd: cmd, stderr: &lockedBuf{mu: make(chan struct{}, 1)}}
	cmd.Stderr = c.stderr
	var err error
	if c.in, err = cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c.out = bufio.NewReader(stdout)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = c.in.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	if _, err := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "test", "version": "1"}}); err != nil {
		return c, err
	}
	fmt.Fprintln(c.in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return c, nil
}

func (c *mcpClient) call(method string, params any) (map[string]any, error) {
	c.id++
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if _, err := fmt.Fprintln(c.in, string(msg)); err != nil {
		return nil, err
	}
	type line struct {
		b   []byte
		err error
	}
	for {
		ch := make(chan line, 1)
		go func() { b, err := c.out.ReadBytes('\n'); ch <- line{b, err} }()
		var l line
		select {
		case l = <-ch:
		case <-time.After(30 * time.Second):
			return nil, fmt.Errorf("timeout waiting for %s; stderr:\n%s", method, c.stderr.String())
		}
		if l.err != nil {
			return nil, fmt.Errorf("%s: %v; stderr:\n%s", method, l.err, c.stderr.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(l.b, &resp); err != nil {
			continue
		}
		if id, ok := resp["id"].(float64); ok && int(id) == c.id {
			return resp, nil
		}
	}
}

// tool calls name and reports whether it was allowed, plus the first text content.
func (c *mcpClient) tool(name string, args map[string]any) (bool, string) {
	c.t.Helper()
	resp, err := c.call("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		c.t.Fatal(err)
	}
	res, _ := resp["result"].(map[string]any)
	if res == nil {
		c.t.Fatalf("tools/call %s: %v", name, resp)
	}
	text := ""
	if content, _ := res["content"].([]any); len(content) > 0 {
		text, _ = content[0].(map[string]any)["text"].(string)
	}
	isErr, _ := res["isError"].(bool)
	return !isErr, text
}

func writeMCPPolicy(t *testing.T, path, action string) {
	t.Helper()
	exe, _ := json.Marshal(os.Args[0])
	pol := fmt.Sprintf(`default_action: deny
tools:
  - match: {tool: "fake__read_file"}
    action: %s
mcp:
  upstreams:
    - name: fake
      command: %s
      args: ["-test.run=^TestMCPHelperProcess$"]
      env: {%s: upstream}
`, action, exe, mcpHelperEnv)
	if err := os.WriteFile(path, []byte(pol), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMCPServeGuardAndReload(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	ws, nh := t.TempDir(), t.TempDir()
	pol := filepath.Join(ws, "nexus.yaml")
	writeMCPPolicy(t, pol, "allow")
	c, err := startMCPServe(t, ws, nh)
	if err != nil {
		t.Fatal(err)
	}

	if ok, text := c.tool("fake__read_file", map[string]any{"path": "/tmp/x"}); !ok || text != "ran /tmp/x" {
		t.Fatalf("allowed call = %v %q", ok, text)
	}
	for _, args := range []map[string]any{
		{"path": "nexus.yaml"},
		{"path": filepath.Join("sub", "..", "nexus.yaml")},
		{"nested": map[string]any{"list": []any{filepath.Join(nh, "ed25519.key")}}},
	} {
		if ok, text := c.tool("fake__read_file", args); ok || !strings.Contains(text, "protected nexus file") {
			t.Fatalf("guard: args %v = %v %q", args, ok, text)
		}
	}
	if !strings.Contains(c.stderr.String(), "inside the agent's workspace") {
		t.Errorf("missing workspace warning:\n%s", c.stderr.String())
	}

	writeMCPPolicy(t, pol, "deny")
	deadline := time.Now().Add(10 * time.Second)
	for {
		ok, _ := c.tool("fake__read_file", map[string]any{"path": "/tmp/x"})
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("policy not reloaded:\n%s", c.stderr.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestMCPServeRefusesUnpinnedChange(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	ws, nh := t.TempDir(), t.TempDir()
	pol := filepath.Join(ws, "nexus.yaml")
	writeMCPPolicy(t, pol, "allow")
	// Pin the current file via the real command, then change it.
	pin := exec.Command(os.Args[0], "-test.run=^TestMCPHelperProcess$", "--", "policy", "pin", "--policy", pol)
	pin.Env = append(os.Environ(), mcpHelperEnv+"=serve", "NEXUS_HOME="+nh)
	if out, err := pin.CombinedOutput(); err != nil {
		t.Fatalf("policy pin: %v\n%s", err, out)
	}
	writeMCPPolicy(t, pol, "deny")

	c, err := startMCPServe(t, ws, nh, "--policy", pol)
	if err == nil {
		t.Fatalf("mcp serve started with an unpinned policy change")
	}
	_ = c.cmd.Wait()
	if !strings.Contains(c.stderr.String(), "does not match its pin") {
		t.Fatalf("unexpected stderr:\n%s", c.stderr.String())
	}

	c2, err := startMCPServe(t, ws, nh, "--policy", pol, "--accept-policy-change")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := c2.tool("fake__read_file", map[string]any{"path": "/tmp/x"}); ok {
		t.Fatal("accepted policy (deny) not in force")
	}
}
