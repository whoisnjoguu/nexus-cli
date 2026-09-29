package tui

import (
	"testing"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

func TestBuildRoundTrip(t *testing.T) {
	in := policy.Policy{
		Agent:               "demo",
		Egress:              policy.Egress{Allow: []string{"api.github.com"}},
		DefaultAction:       policy.ActionDeny,
		EscalateWhenTainted: true,
		Tools: []policy.Rule{
			{Match: policy.Match{Tool: "fs__read*"}, Action: policy.ActionAllow},
			{Match: policy.Match{Method: "GET", Host: "api.internal", Path: "/**"}, Action: policy.ActionAllow}, // host rule preserved
		},
		Providers: map[string]policy.ProviderRule{
			"github": {Access: policy.ActionAllow, Scopes: []string{"repo"}},
		},
	}
	m := newModel(Options{
		Policy:    in,
		Providers: []principal.ProviderInfo{{Name: "github", AuthType: "oauth2", Scopes: []string{"repo", "read:user"}}},
	})
	out := m.build()

	if out.DefaultAction != policy.ActionDeny || !out.EscalateWhenTainted {
		t.Fatalf("defaults not preserved: %+v", out)
	}
	if len(out.Egress.Allow) != 1 || out.Egress.Allow[0] != "api.github.com" {
		t.Fatalf("egress not preserved: %v", out.Egress.Allow)
	}
	// host rule preserved + tool rule re-emitted
	var hasHostRule, hasToolRule bool
	for _, r := range out.Tools {
		if r.Match.Host == "api.internal" {
			hasHostRule = true
		}
		if r.Match.Tool == "fs__read*" && r.Action == policy.ActionAllow {
			hasToolRule = true
		}
	}
	if !hasHostRule {
		t.Fatal("host/path rule was dropped on save")
	}
	if !hasToolRule {
		t.Fatal("tool rule not preserved")
	}
	pr, ok := out.Providers["github"]
	if !ok || pr.Access != policy.ActionAllow || len(pr.Scopes) != 1 || pr.Scopes[0] != "repo" {
		t.Fatalf("provider rule not preserved: %+v", pr)
	}
}
