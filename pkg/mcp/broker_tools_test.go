package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
	"github.com/whoisnjoguu/nexus-cli/pkg/policy"
	"github.com/whoisnjoguu/nexus-cli/pkg/principal"
)

func fakeGateway(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/request-connection", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"authUrl": "https://consent.example/authorize", "connection_id": "conn-1"})
	})
	mux.HandleFunc("/v1/check-connection/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "active"})
	})
	mux.HandleFunc("/v1/token/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-123"})
	})
	mux.HandleFunc("/v1/providers", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]map[string]map[string]any{
			"oauth2": {"github": {"scopes": []string{"repo"}}},
		})
	})
	return httptest.NewServer(mux)
}

func TestBrokerTools(t *testing.T) {
	gw := fakeGateway(t)
	defer gw.Close()

	signer, _ := jwt.NewTokenSigner()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv := newServer(signer, false, inR, io.Discard, outW)
	srv.gateway = gw.URL
	srv.session = &principal.Principal{Subject: "alice@co"}
	srv.engine = policy.NewEngine(policy.Policy{
		DefaultAction: policy.ActionDeny,
		Providers: map[string]policy.ProviderRule{
			"github": {Access: policy.ActionAllow, Credential: policy.ActionAllow},
			"gitlab": {Access: policy.ActionAllow}, // no credential rule -> get_credential denied
		},
	})

	go func() { _ = srv.Serve() }()
	sc := bufio.NewScanner(outR)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	send := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = inW.Write(append(b, '\n'))
	}
	recv := func() map[string]any {
		type res struct {
			m   map[string]any
			err error
		}
		ch := make(chan res, 1)
		go func() {
			if sc.Scan() {
				var m map[string]any
				_ = json.Unmarshal(sc.Bytes(), &m)
				ch <- res{m: m}
				return
			}
			ch <- res{err: io.EOF}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("recv: %v", r.err)
			}
			return r.m
		case <-time.After(5 * time.Second):
			t.Fatal("recv timeout")
			return nil
		}
	}
	text := func(m map[string]any) (string, bool) {
		result, _ := m["result"].(map[string]any)
		isErr, _ := result["isError"].(bool)
		content, _ := result["content"].([]any)
		first, _ := content[0].(map[string]any)
		s, _ := first["text"].(string)
		return s, isErr
	}

	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}}})
	recv()
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	// request_access github -> allowed, returns consent URL
	send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "request_access", "arguments": map[string]any{"provider": "github"}}})
	if s, isErr := text(recv()); isErr || !strings.Contains(s, "consent.example") {
		t.Fatalf("request_access github: isErr=%v text=%q", isErr, s)
	}

	// connection_status github -> active
	send(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "connection_status", "arguments": map[string]any{"provider": "github"}}})
	if s, isErr := text(recv()); isErr || !strings.Contains(s, "active") {
		t.Fatalf("connection_status github: isErr=%v text=%q", isErr, s)
	}

	// get_credential github -> allowed by explicit rule -> returns token
	send(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "get_credential", "arguments": map[string]any{"provider": "github"}}})
	if s, isErr := text(recv()); isErr || s != "tok-123" {
		t.Fatalf("get_credential github: isErr=%v text=%q", isErr, s)
	}

	// get_credential gitlab -> denied (no credential rule; secretless default)
	send(map[string]any{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": map[string]any{"name": "get_credential", "arguments": map[string]any{"provider": "gitlab"}}})
	if s, isErr := text(recv()); !isErr || !strings.Contains(strings.ToLower(s), "denied") {
		t.Fatalf("get_credential gitlab should be denied: isErr=%v text=%q", isErr, s)
	}

	_ = inW.Close()
}
