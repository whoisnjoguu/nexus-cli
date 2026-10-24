package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/whoisnjoguu/nexus-cli/external"
)

func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// normHost is the reference normalization for host matching: lowercase, no port, no trailing dot.
func normHost(h string) string { return normalizeHost(h) }

func FuzzHostMatch(f *testing.F) {
	for _, s := range [][2]string{
		{"*.example.com", "api.example.com"},
		{"*.example.com", "example.com"},
		{"*.example.com", "example.com.evil.com"},
		{"*.example.com", "evilexample.com"},
		{"*.example.com", "a.b.example.com:443"},
		{"*.Example.COM", "API.example.com"},
		{"example.com", "EXAMPLE.com:8443"},
		{"evil.com", "evil.com."},
		{"evil.com", "evil.com.:443"},
		{"*.example.com", "x.example.com.:443"},
		{"[::1]", "[::1]:443"},
		{"127.0.0.1:8080", "127.0.0.1"},
		{"*.", "a."},
		{"*", "anything"},
		{"", ""},
		{".", "."},
		{"*.com", "x.com"},
		{"::1", "[::1]:443"},
		{"::1", "::1"},
		{"127.0.0.1", "[::ffff:127.0.0.1]:443"},
		{"10.0.0.1", "[::ffff:a00:1]"},
		{"[::1]", "::1"},
		{"[localhost]", "localhost:80"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, host string) {
		got := hostMatch(pattern, host)
		if HostMatches([]string{pattern}, host) != got {
			t.Fatalf("HostMatches disagrees with hostMatch for %q / %q", pattern, host)
		}
		if up := hostMatch(asciiUpper(pattern), asciiUpper(host)); up != got {
			t.Fatalf("case sensitivity: hostMatch(%q,%q)=%v but upper-cased=%v", pattern, host, got, up)
		}
		h := stripPort(host)
		if h != "" && !strings.HasSuffix(h, ".") && !strings.ContainsAny(host, "[]") && strings.Count(host, ":") <= 1 {
			// A fully-qualified name ("evil.com.") resolves to the same host and must match the same rules.
			fq := h + "." + host[len(h):]
			if fqGot := hostMatch(pattern, fq); fqGot != got {
				t.Fatalf("trailing dot: hostMatch(%q,%q)=%v but hostMatch(%q,%q)=%v", pattern, host, got, pattern, fq, fqGot)
			}
		}
		np, nh := normHost(pattern), normHost(host)
		if got {
			if nh == "" {
				t.Fatalf("empty host %q matched %q", host, pattern)
			}
			wild := strings.HasPrefix(np, "*.")
			if !(np == nh || wild && strings.HasSuffix(nh, np[1:]) && len(nh) > len(np)-1) {
				t.Fatalf("unsound match: %q matched %q", pattern, host)
			}
		}
		if strings.HasPrefix(np, "*.") && len(np) > 2 {
			suffix := np[2:]
			if hostMatch(pattern, suffix) {
				t.Fatalf("%q matched its own apex %q", pattern, suffix)
			}
			evil := suffix + ".evil-nexus-fuzz.test"
			if !strings.HasSuffix(evil, "."+suffix) && hostMatch(pattern, evil) {
				t.Fatalf("%q matched %q", pattern, evil)
			}
		}
	})
}

func FuzzToolMatch(f *testing.F) {
	for _, s := range [][2]string{
		{"read_*", "read_file"},
		{"*__read_*", "fs__read_file"},
		{"*delete*", "fs__DELETE_all"},
		{"*", "resources/read"},
		{"google-*", "Google-Drive"},
		{"[a-", "a"},
		{"fs__\\*", "fs__*"},
		{"execute_shell", "EXECUTE_SHELL"},
		{"get_*", "forget_password"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, tool string) {
		got := toolMatch(pattern, tool)
		if up := toolMatch(asciiUpper(pattern), asciiUpper(tool)); up != got {
			t.Fatalf("case sensitivity: toolMatch(%q,%q)=%v, upper-cased=%v", pattern, tool, got, up)
		}
		if !strings.Contains(pattern, "*") && got != (strings.ToLower(pattern) == strings.ToLower(tool)) {
			t.Fatalf("literal pattern %q vs %q = %v", pattern, tool, got)
		}
		// "*" and "?" never cross "/" (MCP method names like "resources/read"), on every OS.
		if got && !strings.ContainsAny(pattern, "/[\\") && strings.Contains(tool, "/") {
			t.Fatalf("%q matched %q across a slash", pattern, tool)
		}
	})
}

// buildArgs places v at the dot path key in one of several nested shapes.
func buildArgs(key string, v any, shape uint8) map[string]any {
	parts := strings.Split(key, ".")
	switch shape % 4 {
	case 0:
		return map[string]any{key: v}
	case 1: // nested maps
		cur := v
		for i := len(parts) - 1; i >= 0; i-- {
			cur = map[string]any{parts[i]: cur}
		}
		return cur.(map[string]any)
	case 2: // nested maps with every intermediate wrapped in an array
		cur := v
		for i := len(parts) - 1; i >= 1; i-- {
			cur = []any{map[string]any{parts[i]: cur}}
		}
		return map[string]any{parts[0]: cur}
	default: // leaf in an array next to an unrelated element
		return buildArgs(key, []any{v, map[string]any{"unrelated": true}}, 1)
	}
}

func FuzzArgsMatch(f *testing.F) {
	f.Add("path", "/workspace/**", "/workspace/a/b.txt", uint8(0))
	f.Add("path", "/etc/**", "/workspace/../etc/passwd", uint8(1))
	f.Add("options.mode", "w*", "write", uint8(2))
	f.Add("a.b.c", "!*.env", "secrets.ENV", uint8(3))
	f.Add("url", "https://*.example.com/*", "https://api.example.com/v1/x", uint8(1))
	f.Add("path", "./src/*", "src/main.go", uint8(0))
	f.Add("path", "~/.ssh/**", "~/.ssh/id_rsa", uint8(0))
	f.Add("n", "4?", "42", uint8(0))
	f.Add("x", "[", "[", uint8(0))
	f.Add("path", "/a/**/z", "//a///b/./c/../z", uint8(2))
	f.Fuzz(func(t *testing.T, key, pattern, value string, shape uint8) {
		if key == "" || strings.HasPrefix(key, ".") || strings.HasSuffix(key, ".") || strings.Contains(key, "..") {
			return
		}
		args := buildArgs(key, value, shape)
		got := argsMatch(map[string]string{key: pattern}, args)
		if !strings.HasPrefix(pattern, "!") {
			if neg := argsMatch(map[string]string{key: "!" + pattern}, args); neg == got {
				t.Fatalf("negation: %q and !%q both = %v on %v", pattern, pattern, got, args)
			}
		}
		// The leaf value addressed by a dot path matches the same whatever the nesting.
		if flat := argsMatch(map[string]string{key: pattern}, map[string]any{key: value}); flat != got && shape%4 != 3 {
			t.Fatalf("nesting changed the result: flat=%v nested(%d)=%v for %q=%q value %q", flat, shape%4, got, key, pattern, value)
		}
		if argsMatch(map[string]string{key + ".missing-nexus-fuzz": pattern}, args) ||
			argsMatch(map[string]string{key + ".missing-nexus-fuzz": "!" + pattern}, args) {
			t.Fatal("a missing key matched")
		}
		// Path patterns compare cleaned paths: "./", "//" and "x/.." never change the answer.
		if isPathPattern(pattern) && strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") {
			i := strings.Index(value[1:], "/") + 1
			if i <= 0 {
				i = len(value)
			}
			variant := value[:i] + "/./x-nexus-fuzz/..//" + strings.TrimPrefix(value[i:], "/")
			if strings.HasSuffix(value, "/") || filepath.Clean(variant) != filepath.Clean(value) {
				return
			}
			if v := argValueMatch(pattern, variant); v != argValueMatch(pattern, value) {
				t.Fatalf("path pattern %q: %q=%v but %q=%v", pattern, value, !v, variant, v)
			}
		}
	})
}

var (
	shadowRe = regexp.MustCompile(`unreachable: shadowed by tools\[(\d+)\]`)
	toolsRe  = regexp.MustCompile(`^tools\[(\d+)\]$`)
)

// checkPolicyInvariants is shared by the policy and config-loader fuzzers.
func checkPolicyInvariants(t *testing.T, p Policy) {
	t.Helper()
	issues := Validate(p)
	if again := Validate(p); !reflect.DeepEqual(issues, again) {
		t.Fatalf("Validate is not deterministic:\n%v\n%v", issues, again)
	}
	hasErr := false
	for _, is := range issues {
		if is.Severity == SeverityError {
			hasErr = true
		}
		_ = is.String()
	}
	if err := Check(p); (err != nil) != hasErr {
		t.Fatalf("Check=%v but error issues=%v", err, hasErr)
	}

	// Every "shadowed" warning must be sound: a concrete request hitting the later rule also hits
	// the earlier one.
	for _, is := range issues {
		m := shadowRe.FindStringSubmatch(is.Msg)
		pm := toolsRe.FindStringSubmatch(is.Path)
		if m == nil || pm == nil {
			continue
		}
		i, _ := strconv.Atoi(m[1])
		j, _ := strconv.Atoi(pm[1])
		a, b := p.Tools[i].Match, p.Tools[j].Match
		var req Request
		if isToolMatch(b) {
			if hasGlobMeta(b.Tool) || hasGlobMeta(b.Provider) || len(b.Args) > 0 {
				continue
			}
			req = Request{Tool: b.Tool, Provider: b.Provider}
		} else {
			if b.Method == "*" || hasGlobMeta(b.Host) || hasGlobMeta(b.Path) {
				continue
			}
			req = Request{Method: b.Method, Host: b.Host, Path: b.Path}
		}
		if ruleMatches(b, req) && !ruleMatches(a, req) {
			t.Fatalf("tools[%d] reported shadowed by tools[%d], but %+v matches only the later rule", j, i, req)
		}
	}

	if hasErr {
		return
	}
	// A valid policy only ever yields a valid action.
	e := NewEngine(p)
	reqs := []Request{
		{Tool: "read_file", Args: map[string]any{"path": "/etc/passwd"}},
		{Tool: "request_access", Provider: "github"},
		{Tool: "get_credential", Provider: "github"},
		{Method: "GET", Host: "api.github.com:443", Path: "/repos"},
		{Method: "POST", Host: "evil.example"},
		{Method: "CONNECT", Host: "evil.example:443"},
	}
	for _, r := range p.Tools {
		reqs = append(reqs,
			Request{Tool: r.Match.Tool, Provider: r.Match.Provider, Args: map[string]any{"path": "x"}},
			Request{Method: r.Match.Method, Host: r.Match.Host, Path: r.Match.Path})
	}
	for name := range p.Providers {
		reqs = append(reqs, Request{Tool: "request_access", Provider: name}, Request{Tool: "get_credential", Provider: name})
	}
	for _, r := range reqs {
		r.SessionID = "fuzz"
		if d := e.Evaluate(r); !validAction(d.Action) {
			t.Fatalf("valid policy produced action %q for %+v", d.Action, r)
		}
	}
}

func policySeeds(f *testing.F) {
	f.Add([]byte(external.Policy))
	f.Add([]byte("default_action: deny\ntools:\n  - match: {tool: read_*}\n    action: allow\n"))
	f.Add([]byte("tools:\n  - match: {path: /API}\n    action: deny\n  - match: {path: /api}\n    action: allow\n"))
	f.Add([]byte("tools:\n  - match: {host: Example.com}\n    action: deny\n  - match: {host: example.com, method: get}\n    action: allow\n"))
	f.Add([]byte("tools:\n  - match: {tool: \"*\"}\n    action: allow\n  - match: {tool: rm}\n    action: deny\n"))
	f.Add([]byte("tools:\n  - match: {tool: write_file, args: {path: \"!/workspace/**\"}}\n    action: deny\n    one_time: true\n"))
	f.Add([]byte("egress:\n  allow: [\"*.\", \"*\", \"\", \"a/b\", \"*.*.com\"]\n"))
	f.Add([]byte("providers:\n  GitHub: {access: allow}\n  github: {access: maybe, credential: allow, scopes: [\"\"]}\n"))
	f.Add([]byte("tools:\n  - match: {tool: \"[\"}\n  - match: {method: FETCH}\n  - match: {}\n    taints: [\"\"]\n    inject: true\n"))
	f.Add([]byte("default_action: sometimes\n"))
	f.Add([]byte("{"))
}

func FuzzValidateYAML(f *testing.F) {
	policySeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		var p Policy
		// The same decoding as Load (cmd's strict loader is fuzzed by cmd.FuzzParseConfig).
		if err := yaml.Unmarshal(data, &p); err != nil {
			return
		}
		checkPolicyInvariants(t, p)
	})
}

// guardFixture is shared by fuzz iterations: a workspace with a protected policy file and a
// protected nexus home directory.
type guardFixture struct {
	e        *Engine
	ws, home string
	pol      string
}

func newGuardFixture(f *testing.F) guardFixture {
	root := f.TempDir()
	g := guardFixture{ws: filepath.Join(root, "ws"), home: filepath.Join(root, "nexus-home")}
	for _, d := range []string{g.ws, g.home, filepath.Join(g.ws, "src")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			f.Fatal(err)
		}
	}
	g.pol = filepath.Join(g.ws, "nexus.yaml")
	if err := os.WriteFile(g.pol, []byte("tools: []\n"), 0o600); err != nil {
		f.Fatal(err)
	}
	g.e = NewEngine(Policy{DefaultAction: ActionAllow, Tools: []Rule{{Match: Match{Tool: "*"}, Action: ActionAllow}}})
	g.e.SetProtectedPaths(g.ws, []string{g.pol, g.home})
	return g
}

// plainSegment reduces s to a single harmless path segment.
func plainSegment(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 || r == ':' || r < ' ' || strings.ContainsRune(" \t;|&<>()'\"`=,~", r) {
			return -1
		}
		return r
	}, s)
	if s == "" || strings.Trim(s, ".") == "" {
		return "seg"
	}
	return s
}

// wrapArg buries v in JSON-like nesting of the given depth.
func wrapArg(v any, depth, kind uint8) any {
	for i := 0; i < int(depth); i++ {
		switch (int(kind) + i) % 3 {
		case 0:
			v = map[string]any{"k": v}
		case 1:
			v = []any{"x", v}
		default:
			v = map[string]any{"a": []any{map[string]any{"b": v}}}
		}
	}
	return v
}

func FuzzProtectedPathGuard(f *testing.F) {
	g := newGuardFixture(f)
	f.Add("src", uint8(0), uint8(0), uint8(0), uint8(0))
	f.Add("a/b/c", uint8(1), uint8(3), uint8(2), uint8(1))
	f.Add("..", uint8(2), uint8(1), uint8(40), uint8(2))
	f.Add("x y", uint8(3), uint8(2), uint8(5), uint8(1))
	f.Add("", uint8(4), uint8(7), uint8(80), uint8(0))
	f.Add("deep", uint8(5), uint8(5), uint8(200), uint8(2))
	f.Fuzz(func(t *testing.T, noise string, target, form, depth, kind uint8) {
		seg := plainSegment(noise)
		sep := string(filepath.Separator)
		var abs, rel string
		switch target % 3 {
		case 0:
			abs, rel = g.pol, "nexus.yaml"
		case 1:
			abs, rel = filepath.Join(g.home, "audit.jsonl"), filepath.Join("..", "nexus-home", "audit.jsonl")
		default:
			abs, rel = g.home, filepath.Join("..", "nexus-home")
		}
		var p string
		switch form % 8 {
		case 0:
			p = abs
		case 1:
			p = rel
		case 2:
			p = "." + sep + rel
		case 3:
			p = seg + sep + ".." + sep + rel
		case 4:
			p = filepath.Dir(abs) + sep + sep + "." + sep + seg + sep + ".." + sep + filepath.Base(abs)
		case 5:
			p = "src" + sep + seg + sep + ".." + sep + ".." + sep + rel
		case 6:
			p = "file://" + filepath.ToSlash(abs)
		default:
			p = abs + sep
		}
		if filepath.Clean(p) != filepath.Clean(abs) && !strings.HasPrefix(p, "file://") {
			if c := filepath.Join(g.ws, p); filepath.Clean(c) != filepath.Clean(abs) {
				t.Fatalf("fixture bug: %q does not clean to %q", p, abs)
			}
		}
		var arg any = p
		if kind%3 == 2 {
			arg = "cat " + p + " > /dev/null"
		}
		d := g.e.Evaluate(Request{Tool: "write_file", Args: map[string]any{"arg": wrapArg(arg, depth, kind)}})
		if d.Action != ActionDeny || d.Source != SourceGuard {
			t.Fatalf("protected path %q (depth %d) not denied by the guard: %+v", p, depth, d)
		}
		// The same structure around a harmless path must not trip the guard.
		ok := filepath.Join(g.ws, "src", seg)
		if d := g.e.Evaluate(Request{Tool: "write_file", Args: map[string]any{"arg": wrapArg(ok, depth%32, kind)}}); d.Source == SourceGuard {
			t.Fatalf("harmless path %q denied by the guard", ok)
		}
	})
}

func FuzzGuardArbitraryJSON(f *testing.F) {
	g := newGuardFixture(f)
	f.Add([]byte(`{"path":"nexus.yaml"}`))
	f.Add([]byte(`{"cmd":"rm -rf ../nexus-home"}`))
	f.Add([]byte(`{"a":[{"b":{"c":["x","./src/../nexus.yaml"]}}]}`))
	f.Add([]byte(`{"uri":"file:///etc/passwd"}`))
	f.Add([]byte(`{"n":1,"b":true,"z":null,"s":"   "}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var args map[string]any
		if json.Unmarshal(data, &args) != nil || args == nil {
			return
		}
		d := g.e.Evaluate(Request{Tool: "t", Args: args})
		if d.Source == SourceGuard && d.Action != ActionDeny {
			t.Fatalf("guard decision is not deny: %+v", d)
		}
		// Reference: any string leaf that cleans to a protected path must be denied.
		var walk func(v any) bool
		walk = func(v any) bool {
			switch x := v.(type) {
			case string:
				s := strings.TrimSpace(x)
				if s == "" || strings.ContainsRune(s, 0) || strings.HasPrefix(s, "~") || strings.HasPrefix(strings.ToLower(s), "file:") {
					return false
				}
				if !filepath.IsAbs(s) {
					s = filepath.Join(g.ws, s)
				}
				return within(filepath.Clean(s), g.pol) || within(filepath.Clean(s), g.home)
			case map[string]any:
				for _, e := range x {
					if walk(e) {
						return true
					}
				}
			case []any:
				for _, e := range x {
					if walk(e) {
						return true
					}
				}
			}
			return false
		}
		if walk(args) && d.Source != SourceGuard {
			t.Fatalf("args %s reach a protected path but were not denied: %+v", data, d)
		}
	})
}
