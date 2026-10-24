package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/whoisnjoguu/nexus-cli/pkg/audit"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

const validPolicy = "default_action: deny\ntools:\n  - match: {tool: read_file}\n    action: allow\n"

func runRoot(t *testing.T, sub *cobra.Command, args ...string) (string, error) {
	t.Helper()
	resetFlags(t, sub.Flags())
	t.Cleanup(func() { resetFlags(t, sub.Flags()) })
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return out.String(), err
}

func TestResolvePolicyPathPrecedence(t *testing.T) {
	nh := isolateHome(t)
	t.Chdir(t.TempDir())
	c := &cobra.Command{}
	c.Flags().String("policy", "nexus.yaml", "")

	if got := resolvePolicyPath(c); got != "nexus.yaml" {
		t.Fatalf("default = %q", got)
	}
	homePol := filepath.Join(nh, "policy.yaml")
	if err := os.MkdirAll(nh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homePol, []byte(validPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := resolvePolicyPath(c); got != homePol {
		t.Fatalf("home policy = %q", got)
	}
	t.Setenv("NEXUS_POLICY", "env.yaml")
	if got := resolvePolicyPath(c); got != "env.yaml" {
		t.Fatalf("env = %q", got)
	}
	if err := c.Flags().Set("policy", "flag.yaml"); err != nil {
		t.Fatal(err)
	}
	if got := resolvePolicyPath(c); got != "flag.yaml" {
		t.Fatalf("flag = %q", got)
	}
	if got := resolvePolicyPath(nil); got != "env.yaml" {
		t.Fatalf("nil cmd = %q", got)
	}
}

func TestPolicyLintHonoursNexusPolicyEnv(t *testing.T) {
	isolateHome(t)
	t.Setenv("NEXUS_POLICY", writePolicy(t, "tools:\n  - match: {tool: x}\n    action: alow\n"))
	out, err := runLint(t)
	if code, ok := ExitCode(err); !ok || code != 1 || !strings.Contains(out, `unknown action "alow"`) {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestPolicyProtectMovesFileAndPin(t *testing.T) {
	nh := isolateHome(t)
	ws := t.TempDir()
	t.Chdir(ws)
	if err := os.WriteFile("nexus.yaml", []byte(validPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runRoot(t, policyPinCmd, "policy", "pin"); err != nil || !strings.Contains(out, "pinned nexus.yaml sha256:"+policy.Sum([]byte(validPolicy))) {
		t.Fatalf("pin: %q %v", out, err)
	}
	out, err := runRoot(t, policyProtectCmd, "policy", "protect")
	dst := filepath.Join(nh, "policy.yaml")
	if err != nil || strings.TrimSpace(out) != dst {
		t.Fatalf("protect: %q %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(ws, "nexus.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original not removed: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != validPolicy {
		t.Fatalf("moved content: %q %v", data, err)
	}
	if fi, _ := os.Stat(dst); os.PathSeparator == '/' && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
	pinFile, _ := policy.PinPath()
	if pinned, err := policy.CheckPin(pinFile, dst, data); !pinned || err != nil {
		t.Fatalf("pin did not move: %v %v", pinned, err)
	}
	if _, ok, _ := policy.ReadPin(pinFile, filepath.Join(ws, "nexus.yaml")); ok {
		t.Fatal("old pin entry kept")
	}
	if got := resolvePolicyPath(nil); got != dst {
		t.Fatalf("precedence after protect = %q", got)
	}
	if out, err := runRoot(t, policyProtectCmd, "policy", "protect"); err != nil || !strings.Contains(out, "already protected") {
		t.Fatalf("second protect: %q %v", out, err)
	}
}

func TestPolicyProtectKeepAndRefusals(t *testing.T) {
	isolateHome(t)
	t.Chdir(t.TempDir())
	if _, err := runRoot(t, policyProtectCmd, "policy", "protect"); err == nil || !strings.Contains(err.Error(), "no policy file") {
		t.Fatalf("missing source: %v", err)
	}
	if err := os.WriteFile("nexus.yaml", []byte("tools:\n  - match: {tool: x}\n    action: alow\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRoot(t, policyProtectCmd, "policy", "protect"); err == nil || !strings.Contains(err.Error(), "invalid policy") {
		t.Fatalf("invalid source: %v", err)
	}
	if err := os.WriteFile("nexus.yaml", []byte(validPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRoot(t, policyProtectCmd, "policy", "protect", "--keep"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("nexus.yaml"); err != nil {
		t.Fatalf("--keep removed the original: %v", err)
	}
	if _, err := runRoot(t, policyProtectCmd, "policy", "protect", "--policy", "nexus.yaml"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing destination: %v", err)
	}
}

func pinEntries(t *testing.T, nh string) []audit.Entry {
	t.Helper()
	ents, err := audit.ReadAll(filepath.Join(nh, "audit.jsonl"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var out []audit.Entry
	for _, e := range ents {
		if e.Tool == "policy/pin" {
			out = append(out, e)
		}
	}
	return out
}

func TestPinMismatchRefusedAndAccepted(t *testing.T) {
	nh := isolateHome(t)
	pol := writePolicy(t, validPolicy)
	pinFile, _ := policy.PinPath()
	if err := policy.WritePin(pinFile, pol, policy.Sum([]byte(validPolicy))); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicyRuntime(pol, runtimeOptions{}); err != nil {
		t.Fatalf("matching pin refused: %v", err)
	}
	edited := strings.Replace(validPolicy, "deny", "allow", 1)
	if err := os.WriteFile(pol, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadPolicyRuntime(pol, runtimeOptions{})
	var mm *policy.PinMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("mismatch not refused: %v", err)
	}
	if ents := pinEntries(t, nh); len(ents) != 1 || ents[0].Decision != "deny" || !strings.HasPrefix(ents[0].Target, pol+"#sha256:") {
		t.Fatalf("mismatch audit = %+v", ents)
	}
	rt, err := loadPolicyRuntime(pol, runtimeOptions{AcceptPolicyChange: true})
	if err != nil || rt.Policy.DefaultAction != policy.ActionAllow {
		t.Fatalf("accept: %v", err)
	}
	if pinned, err := policy.CheckPin(pinFile, pol, []byte(edited)); !pinned || err != nil {
		t.Fatalf("not re-pinned: %v %v", pinned, err)
	}
	if ents := pinEntries(t, nh); len(ents) != 2 || ents[1].Decision != "allow" {
		t.Fatalf("accept audit = %+v", ents)
	}
	// The runtime guards the policy file and nexus home.
	for _, p := range []string{pol, filepath.Join(nh, "keys", "agent.key"), pinFile} {
		if d := rt.Engine.Evaluate(policy.Request{Tool: "write_file", Args: map[string]any{"path": p}}); d.Source != policy.SourceGuard {
			t.Fatalf("%s not guarded: %+v", p, d)
		}
	}
}

func TestWatcherRefusesUnpinnedEdit(t *testing.T) {
	isolateHome(t)
	pol := writePolicy(t, validPolicy)
	pinFile, _ := policy.PinPath()
	if err := policy.WritePin(pinFile, pol, policy.Sum([]byte(validPolicy))); err != nil {
		t.Fatal(err)
	}
	rt, err := loadPolicyRuntime(pol, runtimeOptions{NoAudit: true})
	if err != nil {
		t.Fatal(err)
	}
	errb := &syncBuffer{}
	rt.watch(nil, errb, true)
	defer rt.Close()
	req := policy.Request{SessionID: "s", Tool: "other"}
	if rt.Engine.Evaluate(req).Action != policy.ActionDeny {
		t.Fatal("precondition")
	}
	edited := strings.Replace(validPolicy, "deny", "allow", 1)
	if err := os.WriteFile(pol, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "pin refusal", func() bool { return strings.Contains(errb.String(), "does not match its pin") })
	if rt.Engine.Evaluate(req).Action != policy.ActionDeny {
		t.Fatal("unpinned edit was loaded")
	}
	// Approving the edit (policy pin) makes the watcher retry and load it.
	if out, err := runRoot(t, policyPinCmd, "policy", "pin", "--policy", pol); err != nil {
		t.Fatalf("pin: %q %v", out, err)
	}
	waitUntil(t, "reload after pin", func() bool { return rt.Engine.Evaluate(req).Action == policy.ActionAllow })
	if !strings.Contains(errb.String(), "policy reloaded from") {
		t.Fatalf("stderr = %q", errb.String())
	}
}

func TestAppendPolicyRuleRepins(t *testing.T) {
	isolateHome(t)
	pinFile, _ := policy.PinPath()
	pinned := writePolicy(t, validPolicy)
	if err := policy.WritePin(pinFile, pinned, policy.Sum([]byte(validPolicy))); err != nil {
		t.Fatal(err)
	}
	unpinned := writePolicy(t, validPolicy)
	for _, p := range []string{pinned, unpinned} {
		if err := appendPolicyRule(p, policy.PersistedAllow(policy.Match{Tool: "write_file"}, nil)); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(pinned)
	if ok, err := policy.CheckPin(pinFile, pinned, data); !ok || err != nil {
		t.Fatalf("pinned file not re-pinned: %v %v", ok, err)
	}
	if _, ok, _ := policy.ReadPin(pinFile, unpinned); ok {
		t.Fatal("unpinned file got pinned")
	}
	if _, err := loadPolicyRuntime(pinned, runtimeOptions{}); err != nil {
		t.Fatalf("re-pinned policy refused: %v", err)
	}
}

func TestDevWorkspaceWarningAndPinRefusal(t *testing.T) {
	isolateHome(t)
	ws := t.TempDir()
	t.Chdir(ws)
	if err := os.WriteFile("nexus.yaml", []byte(validPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, errb, stop := startDevWith(t, "--require-auth=false", "--no-audit", "--key", filepath.Join(t.TempDir(), "k"))
	_ = stop()
	want := "[nexus] warning: policy ." + string(filepath.Separator) + "nexus.yaml is inside the agent's workspace — the agent could edit it; move it with 'nexus-cli policy protect' or rely on the built-in guard"
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("stderr = %q", errb.String())
	}

	if out, err := runRoot(t, policyPinCmd, "policy", "pin"); err != nil {
		t.Fatalf("pin: %q %v", out, err)
	}
	if err := os.WriteFile("nexus.yaml", []byte(validPolicy+"# edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetFlags(t, devCmd.Flags())
	_, err := runRoot(t, devCmd, "dev", "--port", "0", "--no-audit", "--require-auth=false", "--key", filepath.Join(t.TempDir(), "k"))
	var mm *policy.PinMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("dev started with an unpinned edit: %v", err)
	}
}
