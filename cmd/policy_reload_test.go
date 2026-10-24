package cmd

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// startDevWith runs `nexus-cli dev` with exactly args (after "dev") and isolated HOME/NEXUS_HOME,
// returning the address, stdout, stderr and a stop function.
func startDevWith(t *testing.T, args ...string) (addr string, out, errb *syncBuffer, stop func() error) {
	t.Helper()
	resetFlags(t, devCmd.Flags())
	t.Cleanup(func() { resetFlags(t, devCmd.Flags()) })
	out, errb = &syncBuffer{}, &syncBuffer{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(errb)
	rootCmd.SetArgs(append([]string{"dev", "--port", "0"}, args...))
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	ctx, cancel := context.WithCancel(context.Background())
	devCmd.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- rootCmd.ExecuteContext(ctx) }()
	var once sync.Once
	var stopErr error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopErr = <-done:
			case <-time.After(10 * time.Second):
				stopErr = context.DeadlineExceeded
			}
		})
		return stopErr
	}
	t.Cleanup(func() { _ = stop() })
	re := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("dev exited early: %v; out=%q err=%q", err, out.String(), errb.String())
		default:
		}
		if m := re.FindStringSubmatch(out.String()); m != nil && strings.Contains(out.String(), "approvals:") {
			return m[1], out, errb, stop
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("dev did not start; out=%q err=%q", out.String(), errb.String())
	return "", nil, nil, nil
}

func directStatus(t *testing.T, addr string) int {
	t.Helper()
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Get("http://" + addr + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	nh := filepath.Join(home, ".nexus")
	t.Setenv("NEXUS_HOME", nh)
	t.Setenv("NEXUS_POLICY", "")
	t.Setenv("NEXUS_KEY_BACKEND", "file")
	return nh
}

func TestDevHotReload(t *testing.T) {
	nh := isolateHome(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "nexus.yaml")
	deny := "default_action: deny\ntools:\n  - match: {method: GET}\n    action: deny\n"
	allow := "default_action: deny\ntools:\n  - match: {method: GET}\n    action: allow\n"
	if err := os.WriteFile(pol, []byte(deny), 0o600); err != nil {
		t.Fatal(err)
	}
	addr, out, errb, stop := startDevWith(t, "--require-auth=false", "--policy", pol, "--key", filepath.Join(dir, "k"))
	if !strings.Contains(out.String(), "hot reload on") {
		t.Fatalf("out = %q", out.String())
	}
	if c := directStatus(t, addr); c != http.StatusForbidden {
		t.Fatalf("before reload = %d", c)
	}
	if err := os.WriteFile(pol, []byte(allow), 0o600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "reload", func() bool { return strings.Contains(errb.String(), "[nexus] policy reloaded from "+pol) })
	if c := directStatus(t, addr); c != http.StatusOK {
		t.Fatalf("after reload = %d", c)
	}

	if err := os.WriteFile(pol, []byte("default_action: deny\ntools:\n  - match: {method: GET}\n    action: alow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "failed reload", func() bool { return strings.Contains(errb.String(), "[nexus] policy reload failed:") })
	if c := directStatus(t, addr); c != http.StatusOK {
		t.Fatalf("old policy not kept: %d", c)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	ents, err := audit.ReadAll(filepath.Join(nh, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var decisions []string
	for _, e := range ents {
		if e.Tool == "policy/reload" {
			decisions = append(decisions, e.Decision)
			if !strings.HasPrefix(e.Target, pol+"#sha256:") {
				t.Errorf("target = %q", e.Target)
			}
		}
	}
	if strings.Join(decisions, ",") != "allow,deny" {
		t.Fatalf("reload audit decisions = %v", decisions)
	}
}

func TestDevNoReloadFlag(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "nexus.yaml")
	if err := os.WriteFile(pol, []byte("tools:\n  - match: {method: GET}\n    action: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	addr, out, errb, _ := startDevWith(t, "--require-auth=false", "--no-audit", "--no-reload", "--policy", pol, "--key", filepath.Join(dir, "k"))
	if strings.Contains(out.String(), "hot reload on") {
		t.Fatal("reload announced despite --no-reload")
	}
	if err := os.WriteFile(pol, []byte("tools:\n  - match: {method: GET}\n    action: allow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if c := directStatus(t, addr); c != http.StatusForbidden || strings.Contains(errb.String(), "reloaded") {
		t.Fatalf("policy reloaded with --no-reload (status %d, err %q)", c, errb.String())
	}
}

func TestAppendPolicyRuleAtomicPreservesSections(t *testing.T) {
	isolateHome(t)
	pol := filepath.Join(t.TempDir(), "nexus.yaml")
	src := `agent: a
tools:
  - match: {tool: write_file}
    action: hitl
mcp:
  upstreams:
    - name: fs
      command: npx
      args: ["-y", "server-fs"]
      env: {A: "1"}
audit:
  max_bytes: 1234
  sinks:
    - {type: syslog, network: udp, addr: "logs.example:514"}
`
	if err := os.WriteFile(pol, []byte(src), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := appendPolicyRule(pol, policy.PersistedAllow(policy.Match{Tool: "write_file"}, nil)); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := loadConfig(pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tools) != 2 || cfg.Tools[0].Match.Tool != "write_file" || cfg.Tools[0].Action != policy.ActionAllow {
		t.Fatalf("tools = %+v", cfg.Tools)
	}
	if len(cfg.MCP.Upstreams) != 1 || cfg.MCP.Upstreams[0].Env["A"] != "1" || cfg.Audit.MaxBytes != 1234 || len(cfg.Audit.Sinks) != 1 {
		t.Fatalf("sections lost: mcp=%+v audit=%+v", cfg.MCP, cfg.Audit)
	}
	if fi, _ := os.Stat(pol); os.PathSeparator == '/' && fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
	newFile := filepath.Join(t.TempDir(), "fresh.yaml")
	if err := appendPolicyRule(newFile, policy.PersistedAllow(policy.Match{Tool: "x"}, nil)); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(newFile); os.PathSeparator == '/' && fi.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode = %v", fi.Mode().Perm())
	}
}

func TestWriteConfigNeverPartiallyRead(t *testing.T) {
	pol := filepath.Join(t.TempDir(), "nexus.yaml")
	var small, big configFile
	small.Policy = policy.Policy{Agent: "small"}
	big.Policy = policy.DefaultPolicy()
	for i := 0; i < 300; i++ {
		big.Tools = append(big.Tools, policy.Rule{Match: policy.Match{Tool: "tool_" + strings.Repeat("x", i%50)}, Action: policy.ActionHITL})
	}
	if err := writeConfig(pol, small); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 40; i++ {
			c := small
			if i%2 == 0 {
				c = big
			}
			if err := writeConfig(pol, c); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		data, err := os.ReadFile(pol)
		if err != nil {
			continue
		}
		cfg, err := decodeConfig(pol, data)
		if err != nil || (cfg.Agent != "small" && len(cfg.Tools) != len(big.Tools)) {
			t.Fatalf("partial read (%d bytes): %v", len(data), err)
		}
	}
}
