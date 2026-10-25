package credential

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func gateway(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestTokenFetchesFromGateway(t *testing.T) {
	var hits atomic.Int32
	url := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/token/conn-1" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at-1"}`))
	})
	r := NewResolver()
	for i := 0; i < 2; i++ {
		tok, err := r.Token(context.Background(), url, "conn-1")
		if err != nil || tok != "at-1" {
			t.Fatalf("Token = %q, %v", tok, err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("gateway hits = %d; tokens must not be cached", hits.Load())
	}
	if len(r.clients) != 1 || r.clientFor(url) != r.clientFor(url) {
		t.Fatal("gateway client not reused")
	}
}

func TestTokenErrors(t *testing.T) {
	r := NewResolver()
	ctx := context.Background()
	if _, err := r.Token(ctx, "", "c"); err == nil {
		t.Fatal("missing gateway accepted")
	}
	if _, err := r.Token(ctx, "http://gw", ""); err == nil {
		t.Fatal("missing connection id accepted")
	}

	empty := gateway(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"access_token":""}`)) })
	if _, err := r.Token(ctx, empty, "c"); err == nil || !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("empty token: err = %v", err)
	}

	denied := gateway(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"forbidden","message":"revoked"}`))
	})
	if _, err := r.Token(ctx, denied, "c"); err == nil || !strings.Contains(err.Error(), "fetch token") {
		t.Fatalf("gateway error: err = %v", err)
	}

	garbage := gateway(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`not json`)) })
	if _, err := r.Token(ctx, garbage, "c"); err == nil {
		t.Fatal("undecodable response accepted")
	}
}

func TestTokenHonoursTimeout(t *testing.T) {
	stall := make(chan struct{})
	url := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	})
	defer close(stall)
	r := NewResolver()
	r.timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := r.Token(context.Background(), url, "c"); err == nil {
		t.Fatal("stalled gateway returned a token")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("timeout not applied: took %v", d)
	}
}
