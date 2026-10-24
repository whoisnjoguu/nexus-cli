package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func guardEngine(t *testing.T) (e *Engine, ws, home, pol string) {
	t.Helper()
	root := t.TempDir()
	ws = filepath.Join(root, "ws")
	home = filepath.Join(root, "nexus-home")
	for _, d := range []string{ws, home, filepath.Join(ws, "src")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pol = filepath.Join(ws, "nexus.yaml")
	if err := os.WriteFile(pol, []byte("tools: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e = NewEngine(Policy{DefaultAction: ActionAllow, Tools: []Rule{{Match: Match{Tool: "*"}, Action: ActionAllow}}})
	e.SetProtectedPaths(ws, []string{pol, home})
	return e, ws, home, pol
}

func TestGuardDeniesProtectedPaths(t *testing.T) {
	e, ws, home, pol := guardEngine(t)
	if runtime.GOOS != "windows" {
		if err := os.Symlink(home, filepath.Join(ws, "link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(pol, filepath.Join(ws, "pol-link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(home, "not-yet"), filepath.Join(ws, "dangling")); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]map[string]any{
		"absolute policy":      {"path": pol},
		"absolute home child":  {"path": filepath.Join(home, "audit.jsonl")},
		"home itself":          {"path": home},
		"relative":             {"path": "nexus.yaml"},
		"dot relative":         {"path": "./nexus.yaml"},
		"dotdot":               {"path": "src/../nexus.yaml"},
		"dotdot escape":        {"path": "src/../../nexus-home/keys/agent.key"},
		"file url":             {"uri": "file://" + filepath.ToSlash(pol)},
		"nested map":           {"opts": map[string]any{"deep": map[string]any{"target": pol}}},
		"nested slice":         {"paths": []any{"a.txt", []any{"b", pol}}},
		"string slice":         {"paths": []string{"ok.txt", pol}},
		"string map":           {"env": map[string]string{"X": pol}},
		"shell command":        {"command": "sed -i s/deny/allow/ nexus.yaml"},
		"shell redirect":       {"command": "echo allow >> " + pol},
		"shell redirect glued": {"command": "echo x >" + filepath.Join(home, "policy.pin")},
		"bare name in command": {"command": "rm nexus.yaml"},
	}
	if runtime.GOOS != "windows" {
		cases["symlink to protected dir"] = map[string]any{"path": "link/audit.jsonl"}
		cases["symlink new child"] = map[string]any{"path": "link/new/file.txt"}
		cases["symlink to protected file"] = map[string]any{"path": "pol-link"}
		cases["dangling symlink into home"] = map[string]any{"path": "dangling"}
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			d := e.Evaluate(Request{SessionID: "s", Tool: "write_file", Args: args})
			if d.Action != ActionDeny || d.Reason != ReasonProtected || d.Source != SourceGuard {
				t.Fatalf("decision = %+v, want guard deny", d)
			}
		})
	}
}

func TestGuardAllowsOtherPaths(t *testing.T) {
	e, ws, home, _ := guardEngine(t)
	cases := map[string]map[string]any{
		"workspace file":    {"path": "src/main.go"},
		"workspace dir":     {"path": ws},
		"parent of home":    {"path": filepath.Dir(home)},
		"sibling prefix":    {"path": home + "-other/x"},
		"similar name":      {"path": "nexus.yaml.bak"},
		"prose":             {"content": "edit nexus.yaml\nand ~/.nexus/policy.yaml in docs"},
		"number and bool":   {"n": 3.0, "b": true, "nil": nil},
		"no args":           nil,
		"command elsewhere": {"command": "go test ./..."},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			d := e.Evaluate(Request{SessionID: "s", Tool: "write_file", Args: args})
			if d.Action != ActionAllow || d.Source != "" {
				t.Fatalf("decision = %+v, want allow", d)
			}
		})
	}
}

func TestGuardBeatsRulesGrantsAndHTTP(t *testing.T) {
	e, _, _, pol := guardEngine(t)
	req := Request{SessionID: "s", Tool: "write_file", Args: map[string]any{"path": pol}}
	e.GrantSession(req, Decision{Action: ActionHITL, TaintEscalated: true})
	if d := e.Evaluate(req); d.Source != SourceGuard {
		t.Fatalf("grant bypassed guard: %+v", d)
	}
	e.SetPolicy(Policy{DefaultAction: ActionAllow})
	if d := e.Evaluate(req); d.Source != SourceGuard {
		t.Fatalf("reload dropped guard: %+v", d)
	}
	// HTTP proxy requests carry no Args and are never guarded.
	if d := e.Evaluate(Request{SessionID: "s", Method: "GET", Host: "example.com", Path: pol}); d.Action != ActionAllow {
		t.Fatalf("http request guarded: %+v", d)
	}
	e.SetProtectedPaths("", nil)
	if d := e.Evaluate(req); d.Action != ActionAllow {
		t.Fatalf("guard not disabled: %+v", d)
	}
	if e.ProtectedPaths() != nil {
		t.Fatal("ProtectedPaths after disable")
	}
}

func TestGuardTildeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	nh := filepath.Join(home, ".nexus")
	e := NewEngine(Policy{DefaultAction: ActionAllow})
	e.SetProtectedPaths(t.TempDir(), []string{nh})
	for _, s := range []string{"~/.nexus/policy.yaml", "cat ~/.nexus/keys/agent.key"} {
		if d := e.Evaluate(Request{Tool: "t", Args: map[string]any{"a": s}}); d.Source != SourceGuard {
			t.Fatalf("%q not guarded: %+v", s, d)
		}
	}
}
