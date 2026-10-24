package cmd

import (
	"testing"

	"github.com/whoisnjoguu/nexus-cli/external"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

// FuzzParseConfig runs arbitrary bytes through the real nexus.yaml loader. It must never
// panic, and a config it accepts must yield an engine that only ever answers allow, deny or hitl.
func FuzzParseConfig(f *testing.F) {
	for _, s := range []string{
		external.Policy,
		"",
		"default_action: deny\n",
		"default_action: maybe\n",
		"bogus: 1\n",
		"tools:\n  - match: {tool: x, bogus: 1}\n    action: allow\n",
		"mcp:\n  upstreams:\n    - name: a\n      command: [x]\n      extra: 1\n",
		"audit:\n  sinks:\n    - {type: webhook, nope: 1}\n",
		"providers:\n  github:\n    access: allow\n    credential: allow\n",
		"providers:\n  github:\n    credential: sometimes\n",
		"tools:\n  - match: {tool: 'fs__*', args: {path: '/tmp/**'}}\n    action: hitl\n    taints: [secrets]\n",
		"egress:\n  allow: ['*.example.com']\n  deny: [evil.com]\nescalate_when_tainted: true\n",
		"\t- [",
		"a: &a [*a]\n",
		"tools: !!str x\n",
		"---\n---\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := parseConfig("nexus.yaml", data)
		if err != nil {
			if err.Error() == "" {
				t.Fatal("empty error message")
			}
			return
		}
		e := policy.NewEngine(cfg.Policy)
		for _, req := range []policy.Request{
			{SessionID: "s", Tool: "fs__read_file", Args: map[string]any{"path": "/etc/passwd"}},
			{SessionID: "s", Method: "GET", Host: "api.example.com", Path: "/x"},
			{SessionID: "s", Method: "POST", Host: "evil.com", Path: "/"},
			{SessionID: "s", Tool: "get_credential", Provider: "github"},
			{SessionID: "s", Tool: "request_access", Provider: "github", Scopes: []string{"repo"}},
			{SessionID: "s", Tool: "x"},
		} {
			switch d := e.Evaluate(req); d.Action {
			case policy.ActionAllow, policy.ActionDeny, policy.ActionHITL:
			default:
				t.Fatalf("accepted config yields action %q for %+v", d.Action, req)
			}
		}
	})
}
