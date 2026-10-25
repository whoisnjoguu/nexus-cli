package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgsMatch(t *testing.T) {
	home, _ := os.UserHomeDir()
	args := func(js string) map[string]any {
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(js))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatalf("bad json %s: %v", js, err)
		}
		return m
	}
	cases := []struct {
		name string
		want map[string]string
		args string
		ok   bool
	}{
		{"path inside", map[string]string{"path": "/workspace/**"}, `{"path":"/workspace/src/a.go"}`, true},
		{"dir itself", map[string]string{"path": "/workspace/**"}, `{"path":"/workspace"}`, true},
		{"path outside", map[string]string{"path": "/workspace/**"}, `{"path":"/etc/passwd"}`, false},
		{"traversal blocked", map[string]string{"path": "/workspace/**"}, `{"path":"/workspace/../etc/passwd"}`, false},
		{"traversal deep", map[string]string{"path": "/workspace/**"}, `{"path":"/workspace/a/../../etc"}`, false},
		{"dotdot staying inside", map[string]string{"path": "/workspace/**"}, `{"path":"/workspace/a/../b"}`, true},
		{"prefix sibling", map[string]string{"path": "/workspace/**"}, `{"path":"/workspace-evil/x"}`, false},
		{"single star segment", map[string]string{"path": "/workspace/*.go"}, `{"path":"/workspace/a.go"}`, true},
		{"single star no deep", map[string]string{"path": "/workspace/*.go"}, `{"path":"/workspace/x/a.go"}`, false},
		{"doublestar middle", map[string]string{"path": "/workspace/**/*.env"}, `{"path":"/workspace/a/b/.env"}`, true},
		{"path case sensitive", map[string]string{"path": "/Workspace/**"}, `{"path":"/workspace/a"}`, false},
		{"home expansion", map[string]string{"path": "~/.ssh/**"}, `{"path":"` + filepath.ToSlash(filepath.Join(home, ".ssh", "id_rsa")) + `"}`, true},
		{"home in value", map[string]string{"path": "~/.ssh/**"}, `{"path":"~/.ssh/id_rsa"}`, true},
		{"relative pattern", map[string]string{"path": "./src/**"}, `{"path":"src/x/../y.go"}`, true},
		{"relative escape", map[string]string{"path": "./src/**"}, `{"path":"src/../../y.go"}`, false},
		{"negation outside", map[string]string{"path": "!/workspace/**"}, `{"path":"/etc/passwd"}`, true},
		{"negation inside", map[string]string{"path": "!/workspace/**"}, `{"path":"/workspace/a"}`, false},
		{"negation traversal", map[string]string{"path": "!/workspace/**"}, `{"path":"/workspace/../etc"}`, true},
		{"nested key", map[string]string{"options.mode": "fast"}, `{"options":{"mode":"fast"}}`, true},
		{"nested key mismatch", map[string]string{"options.mode": "fast"}, `{"options":{"mode":"slow"}}`, false},
		{"literal dotted key", map[string]string{"a.b": "x"}, `{"a.b":"x"}`, true},
		{"array any", map[string]string{"paths": "/workspace/**"}, `{"paths":["/etc/x","/workspace/y"]}`, true},
		{"array none", map[string]string{"paths": "/workspace/**"}, `{"paths":["/etc/x","/tmp/y"]}`, false},
		{"array negation none", map[string]string{"paths": "!/workspace/**"}, `{"paths":["/etc/x","/tmp/y"]}`, true},
		{"array negation some", map[string]string{"paths": "!/workspace/**"}, `{"paths":["/etc/x","/workspace/y"]}`, false},
		{"array of objects", map[string]string{"edits.path": "/workspace/**"}, `{"edits":[{"path":"/a"},{"path":"/workspace/b"}]}`, true},
		{"number", map[string]string{"limit": "10"}, `{"limit":10}`, true},
		{"number glob", map[string]string{"limit": "1*"}, `{"limit":100}`, true},
		{"number mismatch", map[string]string{"limit": "10"}, `{"limit":11}`, false},
		{"float", map[string]string{"ratio": "0.5"}, `{"ratio":0.5}`, true},
		{"bool", map[string]string{"recursive": "true"}, `{"recursive":true}`, true},
		{"missing key", map[string]string{"path": "/workspace/**"}, `{"other":"/workspace/a"}`, false},
		{"missing key negated", map[string]string{"path": "!/workspace/**"}, `{"other":"x"}`, false},
		{"missing nested", map[string]string{"options.mode": "*"}, `{"options":{}}`, false},
		{"text glob ci", map[string]string{"sql": "select *"}, `{"sql":"SELECT * FROM users"}`, true},
		{"text negation sql", map[string]string{"sql": "!select *"}, `{"sql":"DROP TABLE users"}`, true},
		{"url glob crosses slash", map[string]string{"url": "https://api.github.com/*"}, `{"url":"https://api.github.com/repos/x/y"}`, true},
		{"url glob other host", map[string]string{"url": "https://api.github.com/*"}, `{"url":"https://evil.com/api.github.com/"}`, false},
		{"question mark", map[string]string{"mode": "r?"}, `{"mode":"rw"}`, true},
		{"all keys required", map[string]string{"path": "/workspace/**", "mode": "ro"}, `{"path":"/workspace/a","mode":"rw"}`, false},
		{"path pattern number value", map[string]string{"path": "/workspace/**"}, `{"path":5}`, false},
		{"nil args", map[string]string{"path": "*"}, `null`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var a map[string]any
			if tc.args != "null" {
				a = args(tc.args)
			}
			if got := argsMatch(tc.want, a); got != tc.ok {
				t.Fatalf("argsMatch(%v, %s) = %v, want %v", tc.want, tc.args, got, tc.ok)
			}
		})
	}
}

func TestArgRulesInEngine(t *testing.T) {
	e := NewEngine(Policy{
		DefaultAction: ActionDeny,
		Tools: []Rule{
			{Match: Match{Tool: "fs__write_file", Args: map[string]string{"path": "/workspace/**"}}, Action: ActionAllow},
			{Match: Match{Tool: "fs__write_file"}, Action: ActionHITL},
			{Match: Match{Args: map[string]string{"path": "*"}}, Action: ActionAllow}, // args-only: never matches
		},
	})
	cases := []struct {
		args map[string]any
		want Action
	}{
		{map[string]any{"path": "/workspace/a.txt"}, ActionAllow},
		{map[string]any{"path": "/workspace/../etc/passwd"}, ActionHITL},
		{map[string]any{}, ActionHITL},
	}
	for _, tc := range cases {
		if d := e.Evaluate(Request{SessionID: "s", Tool: "fs__write_file", Args: tc.args}); d.Action != tc.want {
			t.Fatalf("args %v: got %s want %s", tc.args, d.Action, tc.want)
		}
	}
	if d := e.Evaluate(Request{SessionID: "s", Tool: "other", Args: map[string]any{"path": "x"}}); d.Action != ActionDeny {
		t.Fatalf("args-only rule must not match: %+v", d)
	}
}

func TestOneTimeArgsRulesAreDistinct(t *testing.T) {
	e := NewEngine(Policy{
		DefaultAction: ActionDeny,
		Tools: []Rule{
			{Match: Match{Tool: "t", Args: map[string]string{"x": "a"}}, Action: ActionAllow, OneTime: true},
			{Match: Match{Tool: "t", Args: map[string]string{"x": "b"}}, Action: ActionAllow, OneTime: true},
		},
	})
	for _, v := range []string{"a", "b"} {
		if d := e.Evaluate(Request{SessionID: "s", Tool: "t", Args: map[string]any{"x": v}}); !d.Allowed() {
			t.Fatalf("x=%s first use should be allowed: %+v", v, d)
		}
	}
	if d := e.Evaluate(Request{SessionID: "s", Tool: "t", Args: map[string]any{"x": "a"}}); d.Allowed() {
		t.Fatal("second use of one-time rule should be denied")
	}
}

func TestDefaultPolicySamplingHITL(t *testing.T) {
	e := NewEngine(DefaultPolicy())
	if d := e.Evaluate(Request{SessionID: "s", Tool: "sampling/createMessage", Provider: "fs"}); d.Action != ActionHITL {
		t.Fatalf("sampling should require HITL by default: %+v", d)
	}
	for _, tool := range []string{"resources/read", "prompts/get"} {
		if d := e.Evaluate(Request{SessionID: "s", Tool: tool, Provider: "fs"}); !d.Allowed() {
			t.Fatalf("%s should be allowed by default: %+v", tool, d)
		}
	}
}

func TestToolEgressTaintEscalation(t *testing.T) {
	e := NewEngine(Policy{
		DefaultAction:       ActionDeny,
		EscalateWhenTainted: true,
		Egress:              Egress{Allow: []string{"api.github.com"}},
		Tools: []Rule{
			{Match: Match{Tool: "fs__read_secret"}, Action: ActionAllow, Taints: []string{"secrets"}},
			{Match: Match{Tool: "fetch__fetch"}, Action: ActionAllow},
		},
	})
	if d := e.Evaluate(Request{SessionID: "s", Tool: "fetch__fetch", Host: "evil.example"}); !d.Allowed() {
		t.Fatalf("untainted fetch should be allowed: %+v", d)
	}
	e.Evaluate(Request{SessionID: "s", Tool: "fs__read_secret"})
	if d := e.Evaluate(Request{SessionID: "s", Tool: "fetch__fetch", Host: "evil.example"}); d.Action != ActionHITL || !d.TaintEscalated {
		t.Fatalf("tainted fetch to non-allowlisted host should escalate: %+v", d)
	}
	if d := e.Evaluate(Request{SessionID: "s", Tool: "fetch__fetch", Host: "api.github.com"}); !d.Allowed() {
		t.Fatalf("tainted fetch to allowlisted host should be allowed: %+v", d)
	}
}
