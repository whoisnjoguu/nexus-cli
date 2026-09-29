package sdk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
)

func gateFor(rules []policy.Rule, approve bool) *LocalGate {
	e := policy.NewEngine(policy.Policy{Tools: rules})
	return NewLocalGate(e, ApproverFunc(func(context.Context, ToolCall, string) bool { return approve }), nil)
}

func TestLocalGateAllow(t *testing.T) {
	g := gateFor([]policy.Rule{{Match: policy.Match{Method: "GET", Path: "/**"}, Action: policy.ActionAllow}}, false)
	dec, err := g.Authorize(context.Background(), ToolCall{SessionID: "s", Method: "GET", Path: "/x"})
	if err != nil || !dec.Allowed {
		t.Fatalf("want allowed, got %+v err=%v", dec, err)
	}
}

func TestLocalGateHITLApprove(t *testing.T) {
	g := gateFor([]policy.Rule{{Match: policy.Match{Method: "POST", Path: "/**"}, Action: policy.ActionHITL}}, true)
	dec, _ := g.Authorize(context.Background(), ToolCall{SessionID: "s", Method: "POST", Path: "/x"})
	if !dec.Allowed {
		t.Fatalf("approved HITL should allow, got %+v", dec)
	}
}

func TestLocalGateHITLDeny(t *testing.T) {
	g := gateFor([]policy.Rule{{Match: policy.Match{Method: "POST", Path: "/**"}, Action: policy.ActionHITL}}, false)
	dec, _ := g.Authorize(context.Background(), ToolCall{SessionID: "s", Method: "POST", Path: "/x"})
	if dec.Allowed {
		t.Fatalf("denied HITL should block, got %+v", dec)
	}
}

func TestGateTransportDenies(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	g := gateFor([]policy.Rule{{Match: policy.Match{Method: "POST", Path: "/**"}, Action: policy.ActionDeny}}, false)
	client := &http.Client{Transport: &GateTransport{Gate: g, Agent: "a", ActAs: "u"}}

	_, err := client.Post(upstream.URL+"/x", "text/plain", nil)
	if err == nil {
		t.Fatal("expected denial error from gate transport")
	}
}
