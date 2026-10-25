package policy

import (
	"strings"
	"testing"
)

func findIssue(issues []Issue, sev Severity, path, substr string) bool {
	for _, i := range issues {
		if i.Severity == sev && i.Path == path && strings.Contains(i.Msg, substr) {
			return true
		}
	}
	return false
}

func TestValidateIssueTypes(t *testing.T) {
	p := Policy{
		DefaultAction: "maybe",
		Egress: Egress{
			Allow:       []string{"api.github.com", "", "api.*.com", "*.com", "https://x.com/"},
			Passthrough: []string{"*.pinned.example", "bad*"},
		},
		Providers: map[string]ProviderRule{
			"github": {Access: "allow", Credential: "allow"},
			"GitHub": {Access: "sometimes", Scopes: []string{" "}},
		},
		Tools: []Rule{
			{Match: Match{Tool: "x"}, Action: "alow"},              // 0 unknown action
			{Match: Match{}, Action: ActionAllow},                  // 1 empty match
			{Match: Match{Tool: "fs__[read"}, Action: ActionAllow}, // 2 bad glob
			{Match: Match{Method: "GTE"}, Action: ActionAllow},     // 3 bad method
			{}, // 4 set below
			{Match: Match{Method: "POST"}, Action: ActionAllow, Inject: true},                 // 5 inject without host
			{Match: Match{Tool: "t"}, Action: ActionAllow, Taints: []string{"ok", " "}},       // 6 empty taint
			{Match: Match{Tool: "*"}, Action: ActionAllow},                                    // 7 broad tool
			{Match: Match{Tool: "*get*"}, Action: ActionAllow},                                // 8 substring
			{Match: Match{Host: "*.com"}, Action: ActionAllow},                                // 9 broad host
			{Match: Match{Tool: "zz"}, Action: ActionDeny},                                    // 10 shadowed by 7
			{Match: Match{Args: map[string]string{"path": "/x"}}, Action: ActionDeny},         // 11 args only
			{Match: Match{Tool: "w", Args: map[string]string{"path": "/a/[b"}}},               // 12 bad args glob
			{Match: Match{Tool: "w", Method: "GET"}, Action: ActionDeny},                      // 13 mixed
			{Match: Match{Path: "v1/x"}, Action: ActionDeny},                                  // 14 relative path
			{Match: Match{Path: "/v1/[x"}, Action: ActionDeny},                                // 15 bad path glob
			{Match: Match{Host: "a.*.com"}, Action: ActionDeny},                               // 16 bad host
			{Match: Match{Method: "*", Host: "h.example"}, Action: ActionDeny},                // 17 ok
			{Match: Match{Method: "GET", Host: "h.example", Path: "/x"}, Action: ActionAllow}, // 18 shadowed by 17
		},
	}
	p.Tools[4] = Rule{Match: Match{Tool: "a"}, Action: ActionHITL, OneTime: true}
	issues := Validate(p)
	want := []struct {
		sev        Severity
		path, text string
	}{
		{SeverityError, "default_action", `unknown action "maybe"`},
		{SeverityError, "egress.allow[1]", "empty host pattern"},
		{SeverityError, "egress.allow[2]", "unsupported host pattern"},
		{SeverityWarning, "egress.allow[3]", "top-level domain"},
		{SeverityError, "egress.allow[4]", "scheme or path"},
		{SeverityError, "egress.passthrough[1]", "unsupported host pattern"},
		{SeverityError, "providers.github", "differ only in case"},
		{SeverityError, "providers.GitHub.access", `unknown action "sometimes"`},
		{SeverityError, "providers.GitHub.scopes[0]", "empty scope"},
		{SeverityWarning, "providers.github.credential", "raw provider tokens"},
		{SeverityError, "tools[0].action", `unknown action "alow" (want allow|deny|hitl)`},
		{SeverityWarning, "tools[1].match", "rule never matches"},
		{SeverityError, "tools[2].match.tool", "invalid glob"},
		{SeverityError, "tools[3].match.method", `unknown HTTP method "GTE"`},
		{SeverityError, "tools[4].one_time", "requires action allow"},
		{SeverityError, "tools[5].inject", "requires match.host"},
		{SeverityError, "tools[6].taints[1]", "empty taint"},
		{SeverityWarning, "tools[7].match.tool", "allows every tool"},
		{SeverityWarning, "tools[8].match.tool", "mid-word"},
		{SeverityWarning, "tools[9].match.host", "top-level domain"},
		{SeverityWarning, "tools[10]", "unreachable: shadowed by tools[7]"},
		{SeverityWarning, "tools[11].match.args", "rule never matches"},
		{SeverityError, "tools[12].match.args.path", "invalid glob"},
		{SeverityWarning, "tools[13].match", "ignored on tool rules"},
		{SeverityWarning, "tools[14].match.path", "never matches"},
		{SeverityError, "tools[15].match.path", "invalid glob"},
		{SeverityError, "tools[16].match.host", "unsupported host pattern"},
		{SeverityWarning, "tools[18]", "unreachable: shadowed by tools[17]"},
		{SeverityWarning, "tools[12]", "unreachable: shadowed by tools[7]"},
		{SeverityWarning, "tools[13]", "unreachable: shadowed by tools[7]"},
	}
	for _, w := range want {
		if !findIssue(issues, w.sev, w.path, w.text) {
			t.Errorf("missing %s %s: %q", w.sev, w.path, w.text)
		}
	}
	if len(issues) != len(want) {
		for _, i := range issues {
			t.Log(i)
		}
		t.Errorf("got %d issues, want %d", len(issues), len(want))
	}
	if err := Check(p); err == nil || !strings.Contains(err.Error(), `tools[0].action: unknown action "alow"`) {
		t.Fatalf("Check = %v", err)
	}
}

func TestValidateCleanPolicies(t *testing.T) {
	for name, p := range map[string]Policy{
		"default": DefaultPolicy(),
		"empty":   {},
		"one_time default allow": {DefaultAction: ActionAllow, Tools: []Rule{
			{Match: Match{Tool: "pay"}, OneTime: true},
		}},
		"inject with host": {Tools: []Rule{
			{Match: Match{Method: "GET", Host: "api.github.com", Path: "/**"}, Action: ActionAllow, Inject: true},
			{Match: Match{Method: "GET"}, Action: ActionAllow},
		}},
	} {
		if issues := Validate(p); len(issues) != 0 {
			t.Errorf("%s: unexpected issues %v", name, issues)
		}
	}
}

func TestValidateWarningsDoNotFailCheckOrEngine(t *testing.T) {
	p := Policy{Tools: []Rule{{Match: Match{Tool: "*get*"}, Action: ActionAllow}}}
	if err := Check(p); err != nil {
		t.Fatalf("warnings must not fail Check: %v", err)
	}
	if NewEngine(p) == nil {
		t.Fatal("engine construction failed")
	}
}

func TestMethodWildcardMatches(t *testing.T) {
	e := NewEngine(Policy{Tools: []Rule{{Match: Match{Method: "*", Host: "h.example"}, Action: ActionAllow}}})
	if d := e.Evaluate(Request{SessionID: "s", Method: "DELETE", Host: "h.example", Path: "/"}); d.Action != ActionAllow {
		t.Fatalf("method * = %s", d.Action)
	}
}

func TestDefaultPolicyAnchoredGlobs(t *testing.T) {
	e := NewEngine(DefaultPolicy())
	allow := []string{"server__get_x", "get_x", "read_file", "fs__read_file", "github__get_issue",
		"list_repos", "fs__list_directory", "search_code", "github__search_issues", "resources/read", "prompts/get"}
	notAllow := []string{"forget_password", "budget_delete", "target_delete", "thread_reply", "unlisted_publish",
		"research_and_post", "widget_update", "spreadsheet_write", "fs__forget_all"}
	for _, tool := range allow {
		if d := e.Evaluate(Request{SessionID: "s", Tool: tool}); d.Action != ActionAllow {
			t.Errorf("%s: want allow, got %s", tool, d.Action)
		}
	}
	for _, tool := range notAllow {
		if d := e.Evaluate(Request{SessionID: "s", Tool: tool}); d.Action == ActionAllow {
			t.Errorf("%s: must not be auto-allowed (%s)", tool, d.Reason)
		}
	}
}
