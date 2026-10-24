package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// Regression tests for bugs found by the fuzz targets in fuzz_test.go.

func TestHostRulesMatchEquivalentHostForms(t *testing.T) {
	e := NewEngine(Policy{DefaultAction: ActionAllow, Tools: []Rule{
		{Match: Match{Host: "evil.com"}, Action: ActionDeny},
		{Match: Match{Host: "127.0.0.1"}, Action: ActionDeny},
		{Match: Match{Host: "::1"}, Action: ActionDeny},
	}})
	for _, host := range []string{
		"evil.com.", "evil.com.:443", "EVIL.com.", // FQDN root dot
		"[::ffff:127.0.0.1]:443", "::ffff:127.0.0.1", "[::ffff:7f00:1]", // IPv4-mapped IPv6
		"[::1]:443", "[::1]", "::1", "[0:0:0:0:0:0:0:1]:8080", // IPv6 spellings
	} {
		if d := e.Evaluate(Request{SessionID: "s", Method: "GET", Host: host}); d.Action != ActionDeny {
			t.Errorf("host %q = %s, want deny", host, d.Action)
		}
	}
	for _, host := range []string{"", ".", ":443", "[]:443"} {
		if hostMatch("", host) || hostMatch(".", host) {
			t.Errorf("empty pattern matched %q", host)
		}
	}
	if hostMatch("*.example.com", ".example.com") || hostMatch("*.example.com", "example.com.") {
		t.Error("wildcard matched its apex")
	}
	if !HostMatches([]string{"api.good.com"}, "API.good.com.:443") {
		t.Error("allowlist missed an FQDN spelling")
	}
}

func TestGuardDeniesDeeplyNestedArgs(t *testing.T) {
	e, _, _, pol := guardEngine(t)
	for _, depth := range []int{11, 20, 33, 64, 200} {
		raw := strings.Repeat(`{"a":[`, depth) + `"` + jsonEscape(pol) + `"` + strings.Repeat(`]}`, depth)
		var args map[string]any
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			t.Fatal(err)
		}
		if d := e.Evaluate(Request{SessionID: "s", Tool: "write_file", Args: args}); d.Action != ActionDeny || d.Source != "guard" {
			t.Errorf("depth %d: %+v, want guard deny", depth, d)
		}
	}
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

func TestNoShadowWarningForCaseDistinctPaths(t *testing.T) {
	p := Policy{Tools: []Rule{
		{Match: Match{Method: "GET", Path: "/API"}, Action: ActionDeny},
		{Match: Match{Method: "GET", Path: "/api"}, Action: ActionAllow},
	}}
	for _, is := range Validate(p) {
		if strings.Contains(is.Msg, "shadowed") {
			t.Fatalf("false shadow warning: %v", is)
		}
	}
	e := NewEngine(p)
	if d := e.Evaluate(Request{SessionID: "s", Method: "GET", Host: "h", Path: "/api"}); d.Action != ActionAllow {
		t.Fatalf("/api = %s, want allow (paths are case-sensitive)", d.Action)
	}
}

// Globs behave the same on every OS (filepath.Match let "*" cross "/" on Windows).
func TestGlobsAreSlashSemanticsOnEveryOS(t *testing.T) {
	for _, c := range []struct {
		pattern, value string
		want           bool
	}{
		{"/repos/*", "/repos/a", true},
		{"/repos/*", "/repos/a/b", false},
		{"/repos/*/issues", `/repos/a\b/issues`, true},
		{`/a\*b`, "/a*b", true},
		{`/a\*b`, "/axb", false},
	} {
		if got := pathMatch(c.pattern, c.value); got != c.want {
			t.Errorf("pathMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
	if toolMatch("fs__*", "fs__dir/../write") || !toolMatch("fs__*", `fs__x\y`) {
		t.Error("toolMatch: * must stop at / and only at /")
	}
}
