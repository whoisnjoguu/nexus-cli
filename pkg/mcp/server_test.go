package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
)

// harness spins up an MCP server over in-memory pipes and returns a writer for client
// requests plus a scanner over the server's output.
type harness struct {
	t    *testing.T
	w    *io.PipeWriter
	out  *bufio.Scanner
	done chan struct{}
}

func newHarness(t *testing.T, strict bool) *harness {
	t.Helper()
	signer, err := jwt.NewTokenSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv := newServer(signer, strict, inR, io.Discard, outW)

	done := make(chan struct{})
	go func() {
		_ = srv.Serve()
		close(done)
	}()

	sc := bufio.NewScanner(outR)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return &harness{t: t, w: inW, out: sc, done: done}
}

func (h *harness) send(v any) {
	h.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		h.t.Fatalf("marshal: %v", err)
	}
	if _, err := h.w.Write(append(b, '\n')); err != nil {
		h.t.Fatalf("write: %v", err)
	}
}

func (h *harness) recv() map[string]any {
	h.t.Helper()
	type result struct {
		m   map[string]any
		err error
	}
	ch := make(chan result, 1)
	go func() {
		if !h.out.Scan() {
			ch <- result{err: io.EOF}
			return
		}
		var m map[string]any
		ch <- result{m: m, err: json.Unmarshal(h.out.Bytes(), &m)}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			h.t.Fatalf("recv: %v", r.err)
		}
		return r.m
	case <-time.After(3 * time.Second):
		h.t.Fatal("recv: timed out waiting for server output")
		return nil
	}
}

func (h *harness) close() {
	_ = h.w.Close()
	<-h.done
}

func (h *harness) initialize(withElicitation bool) {
	h.t.Helper()
	caps := map[string]any{}
	if withElicitation {
		caps["elicitation"] = map[string]any{}
	}
	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{"protocolVersion": protocolVersion, "capabilities": caps},
	})
	resp := h.recv()
	if _, ok := resp["result"]; !ok {
		h.t.Fatalf("initialize: expected result, got %v", resp)
	}
}

func TestToolsListAndMint(t *testing.T) {
	h := newHarness(t, false)
	defer h.close()
	h.initialize(false)

	h.send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	list := h.recv()
	result := list["result"].(map[string]any)
	tools := result["tools"].([]any)
	names := map[string]bool{}
	for _, tv := range tools {
		if tm, ok := tv.(map[string]any); ok {
			if n, ok := tm["name"].(string); ok {
				names[n] = true
			}
		}
	}
	for _, want := range []string{"mint_token", "list_providers", "request_access", "get_credential"} {
		if !names[want] {
			t.Fatalf("tools/list missing %q; got %v", want, names)
		}
	}

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{
			"name":      "mint_token",
			"arguments": map[string]any{"agent_id": "a", "user_id": "u", "scopes": []string{"read"}, "ttl_seconds": 30},
		},
	})
	call := h.recv()
	res := call["result"].(map[string]any)
	if res["isError"].(bool) {
		t.Fatalf("mint returned error: %v", res)
	}
	content := res["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if len(text) < 20 {
		t.Fatalf("expected a JWT, got %q", text)
	}
}

func TestStrictElicitationApprove(t *testing.T) {
	h := newHarness(t, true)
	defer h.close()
	h.initialize(true)

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/call",
		"params": map[string]any{
			"name":      "mint_token",
			"arguments": map[string]any{"agent_id": "a", "user_id": "u"},
		},
	})

	// Server must first ask for approval via elicitation.
	elicit := h.recv()
	if elicit["method"] != "elicitation/create" {
		t.Fatalf("expected elicitation/create, got %v", elicit["method"])
	}
	elicitID := elicit["id"]

	// Approve.
	h.send(map[string]any{
		"jsonrpc": "2.0", "id": elicitID,
		"result": map[string]any{"action": "accept", "content": map[string]any{"decision": "once"}},
	})

	call := h.recv()
	res := call["result"].(map[string]any)
	if res["isError"].(bool) {
		t.Fatalf("approved call returned error: %v", res)
	}
}

func TestStrictElicitationDecline(t *testing.T) {
	h := newHarness(t, true)
	defer h.close()
	h.initialize(true)

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call",
		"params": map[string]any{
			"name":      "mint_token",
			"arguments": map[string]any{"agent_id": "a", "user_id": "u"},
		},
	})

	elicit := h.recv()
	if elicit["method"] != "elicitation/create" {
		t.Fatalf("expected elicitation/create, got %v", elicit["method"])
	}

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": elicit["id"],
		"result": map[string]any{"action": "decline"},
	})

	call := h.recv()
	res := call["result"].(map[string]any)
	if !res["isError"].(bool) {
		t.Fatalf("declined call should be an error result, got %v", res)
	}
}

func TestStrictWithoutElicitationDenies(t *testing.T) {
	h := newHarness(t, true)
	defer h.close()
	h.initialize(false) // client advertises no elicitation capability

	h.send(map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{
			"name":      "mint_token",
			"arguments": map[string]any{"agent_id": "a", "user_id": "u"},
		},
	})

	call := h.recv()
	res := call["result"].(map[string]any)
	if !res["isError"].(bool) {
		t.Fatalf("expected fail-closed denial, got %v", res)
	}
}
