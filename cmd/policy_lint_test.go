package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whoisnjoguu/nexus-cli/external"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nexus.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runLint(t *testing.T, args ...string) (string, error) {
	t.Helper()
	resetFlags(t, policyLintCmd.Flags())
	t.Cleanup(func() { resetFlags(t, policyLintCmd.Flags()) })
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	rootCmd.SetArgs(append([]string{"policy", "lint"}, args...))
	err := rootCmd.Execute()
	return out.String(), err
}

func TestLoadConfigUnknownFieldsWithLineNumbers(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"top":   {"agent: a\nfoo: 1\n", `line 2: unknown field "foo" in the top level`},
		"match": {"tools:\n  - match: {tool: x, tol: y}\n    action: allow\n", `line 2: unknown field "tol" in a rule match`},
		"rule":  {"tools:\n  - match: {tool: x}\n    acton: allow\n", `line 3: unknown field "acton" in a tools rule`},
		"mcp":   {"mcp:\n  upstream: []\n", `line 2: unknown field "upstream" in mcp`},
		"mcp upstream": {"mcp:\n  upstreams:\n    - name: fs\n      comand: npx\n",
			`line 4: unknown field "comand" in an mcp.upstreams entry`},
		"audit":      {"audit:\n  max_byte: 10\n", `line 2: unknown field "max_byte" in audit`},
		"audit sink": {"audit:\n  sinks:\n    - type: webhook\n      ur: x\n", `line 4: unknown field "ur" in an audit.sinks entry`},
		"egress":     {"egress:\n  alow: [x]\n", `line 2: unknown field "alow" in egress`},
		"syntax":     {"tools: [\n", "line"},
	}
	for name, c := range cases {
		_, _, err := loadConfig(writePolicy(t, c.yaml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	if _, _, err := loadConfig(writePolicy(t, "")); err != nil {
		t.Errorf("empty file: %v", err)
	}
}

func TestLoadConfigRejectsValidationErrorsNotWarnings(t *testing.T) {
	_, _, err := loadConfig(writePolicy(t, "tools:\n  - match: {tool: x}\n    action: alow\n"))
	if err == nil || !strings.Contains(err.Error(), `tools[0].action: unknown action "alow"`) {
		t.Fatalf("err = %v", err)
	}
	if _, _, _, err := loadPolicyOrDefault(writePolicy(t, "default_action: nope\n")); err == nil {
		t.Fatal("loadPolicyOrDefault accepted an invalid default_action")
	}
	if _, _, err := loadConfig(writePolicy(t, "tools:\n  - match: {tool: \"*get*\"}\n    action: allow\n")); err != nil {
		t.Fatalf("warnings must not fail loading: %v", err)
	}
}

func TestScaffoldPolicyLintsClean(t *testing.T) {
	cfg, err := parseConfig("nexus.yaml", []byte(external.Policy))
	if err != nil {
		t.Fatal(err)
	}
	if issues := policy.Validate(cfg.Policy); len(issues) != 0 {
		t.Fatalf("scaffold has issues: %v", issues)
	}
	e := policy.NewEngine(cfg.Policy)
	for tool, want := range map[string]policy.Action{
		"fs__read_file": policy.ActionAllow, "list_repos": policy.ActionAllow,
		"forget_password": policy.ActionHITL, "budget_delete": policy.ActionHITL, "execute_shell": policy.ActionDeny,
	} {
		if d := e.Evaluate(policy.Request{SessionID: "s", Tool: tool}); d.Action != want {
			t.Errorf("scaffold %s = %s, want %s", tool, d.Action, want)
		}
	}
	d := e.Evaluate(policy.Request{SessionID: "s", Method: "GET", Host: "api.github.com", Path: "/user"})
	if d.Rule == nil || !d.Rule.Inject {
		t.Errorf("scaffold inject rule shadowed: %+v", d)
	}
}

func TestPolicyLintOutputAndExitCodes(t *testing.T) {
	bad := writePolicy(t, "tools:\n  - match: {tool: x}\n    action: allow\n  - match: {tool: y}\n    action: deny\n  - match: {tool: z}\n    action: alow\n")
	out, err := runLint(t, "--policy", bad)
	if code, ok := ExitCode(err); !ok || code != 1 {
		t.Fatalf("exit = %v", err)
	}
	if !strings.Contains(out, `error tools[2].action: unknown action "alow" (want allow|deny|hitl)`) {
		t.Fatalf("output = %q", out)
	}

	warn := writePolicy(t, "tools:\n  - match: {tool: \"*get*\"}\n    action: allow\n")
	out, err = runLint(t, "--policy", warn)
	if err != nil || !strings.Contains(out, "warning tools[0].match.tool") {
		t.Fatalf("warnings only: err=%v out=%q", err, out)
	}
	if _, err = runLint(t, "--policy", warn, "--strict-warnings"); err == nil {
		t.Fatal("--strict-warnings did not fail on warnings")
	}

	out, err = runLint(t, "--policy", warn, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Errors, Warnings int
		Issues           []policy.Issue
	}
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil || res.Warnings != 1 || res.Errors != 0 || res.Issues[0].Path != "tools[0].match.tool" {
		t.Fatalf("json = %q (%v)", out, jerr)
	}

	unknown := writePolicy(t, "agent: a\nbogus: true\n")
	out, err = runLint(t, "--policy", unknown)
	if _, ok := ExitCode(err); !ok || !strings.Contains(out, `error line 2: unknown field "bogus"`) {
		t.Fatalf("unknown key: err=%v out=%q", err, out)
	}

	clean := writePolicy(t, "tools:\n  - match: {tool: read_file}\n    action: allow\n")
	if out, err = runLint(t, "--policy", clean); err != nil || !strings.Contains(out, "no issues") {
		t.Fatalf("clean: err=%v out=%q", err, out)
	}
	if _, err = runLint(t, "--policy", filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file accepted")
	}
}
