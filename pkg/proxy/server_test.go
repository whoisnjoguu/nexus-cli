package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
)

func TestRequireAuthForwardsWithClaims(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Nexus-Act-As"); got != "alice" {
			t.Errorf("downstream X-Nexus-Act-As = %q, want alice", got)
		}
		if got := r.Header.Get("X-Nexus-Agent-ID"); got != "agent" {
			t.Errorf("downstream X-Nexus-Agent-ID = %q, want agent", got)
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()

	signer, err := jwt.NewTokenSigner()
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxyServer(0, false, true, signer.Verifier())
	tok, err := signer.MintDualActorToken("agent", "alice", []string{"read"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("expected forwarded 418, got %d", rec.Code)
	}
}

func TestRequireAuthRejectsMissingToken(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	p := NewProxyServer(0, false, true, signer.Verifier())

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireAuthRejectsBadToken(t *testing.T) {
	signer, _ := jwt.NewTokenSigner()
	p := NewProxyServer(0, false, true, signer.Verifier())

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer not.a.jwt")
	rec := httptest.NewRecorder()
	p.handleIntercept(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBearerTokenSources(t *testing.T) {
	cases := []struct {
		name   string
		set    func(*http.Request)
		expect string
	}{
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer abc") }, "abc"},
		{"proxy-authorization", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "bearer def") }, "def"},
		{"x-nexus-token", func(r *http.Request) { r.Header.Set("X-Nexus-Token", "ghi") }, "ghi"},
		{"none", func(r *http.Request) {}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
			c.set(req)
			if got := bearerToken(req); got != c.expect {
				t.Fatalf("bearerToken = %q, want %q", got, c.expect)
			}
		})
	}
}
