package principal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestConnectionsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	p := &Principal{Subject: "alice@co"}
	p.AddConnection(Connection{Provider: "github", ConnectionID: "c1", GatewayURL: "http://gw", Status: "active"})
	p.AddConnection(Connection{Provider: "google-drive", ConnectionID: "c2", GatewayURL: "http://gw"})
	if err := Save(path, p); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Connections) != 2 {
		t.Fatalf("want 2 connections, got %d", len(got.Connections))
	}
	c, ok := got.GetConnection("github")
	if !ok || c.ConnectionID != "c1" {
		t.Fatalf("github connection missing/wrong: %+v", c)
	}
	provs := got.Providers()
	if len(provs) != 2 || provs[0] != "github" || provs[1] != "google-drive" {
		t.Fatalf("providers sorted wrong: %v", provs)
	}
}

func TestListProviders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/providers" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"oauth2": {"github": {"category":"dev","description":"GitHub","scopes":["repo","read:user"]}},
			"api_key": {"stripe": {"category":"payments","description":"Stripe","scopes":[]}}
		}`))
	}))
	defer srv.Close()

	list, err := ListProviders(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 providers, got %d", len(list))
	}
	// sorted: github, stripe
	if list[0].Name != "github" || list[0].AuthType != "oauth2" || len(list[0].Scopes) != 2 {
		t.Fatalf("unexpected first provider: %+v", list[0])
	}
	if list[1].Name != "stripe" || list[1].AuthType != "api_key" {
		t.Fatalf("unexpected second provider: %+v", list[1])
	}
}
