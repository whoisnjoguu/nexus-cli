package principal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	oauthsdk "github.com/Prescott-Data/nexus-framework/nexus-sdk"
)

// fakeGateway is a minimal nexus-framework Gateway: one connection "c1" whose status walks
// through statuses on each check, and whose token carries idToken.
type fakeGateway struct {
	*httptest.Server
	mu        sync.Mutex
	statuses  []string
	checks    int
	idToken   string
	requested oauthsdk.RequestConnectionInput
	failOn    string // path prefix answered with 400
}

func newFakeGateway(t *testing.T, statuses ...string) *fakeGateway {
	t.Helper()
	// Connect opens the consent URL in a browser; an empty PATH makes that a no-op in tests.
	t.Setenv("PATH", t.TempDir())
	g := &fakeGateway{statuses: statuses}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGateway) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failOn != "" && strings.HasPrefix(r.URL.Path, g.failOn) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":"bad","message":"nope"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/providers":
		_, _ = w.Write([]byte(`{"oauth2":{"github":{"category":"dev","description":"GitHub","scopes":["repo","read:user"]},
			"google":{"scopes":["email"]}},"api_key":{"openai":{"category":"ai"}}}`))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/request-connection":
		_ = json.NewDecoder(r.Body).Decode(&g.requested)
		_, _ = w.Write([]byte(`{"authUrl":"https://consent.invalid/auth?c=c1","connection_id":"c1"}`))
	case r.Method == http.MethodGet && r.URL.Path == "/v1/check-connection/c1":
		st := "active"
		if g.checks < len(g.statuses) {
			st = g.statuses[g.checks]
		}
		if g.checks == 0 && g.requested.ReturnURL != "" {
			// The human's browser follows the post-consent redirect to the landing page.
			go func(u string) {
				if resp, err := http.Get(u); err == nil {
					resp.Body.Close()
				}
			}(g.requested.ReturnURL)
		}
		g.checks++
		_ = json.NewEncoder(w).Encode(map[string]string{"status": st})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/token/c1":
		out := map[string]any{"access_token": "at-123"}
		if g.idToken != "" {
			out["id_token"] = g.idToken
		}
		_ = json.NewEncoder(w).Encode(out)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"not_found","message":"` + r.URL.Path + `"}`))
	}
}

func idToken(claims map[string]string) string {
	b, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestNexusProviderLogin(t *testing.T) {
	g := newFakeGateway(t, "pending", "failed", "Active")
	g.idToken = idToken(map[string]string{"sub": "123", "email": "alice@example.com"})
	var prompted string
	p := NexusProvider{GatewayURL: g.URL, ProviderName: "github", UserID: "u1", Ceiling: []string{"repo:read"},
		TTL: time.Hour, PollInterval: 5 * time.Millisecond, Prompt: func(u string) { prompted = u }}
	if p.Name() != "nexus:github" {
		t.Fatalf("Name = %q", p.Name())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	prin, err := p.Login(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if prompted != "https://consent.invalid/auth?c=c1" {
		t.Errorf("prompted %q", prompted)
	}
	// No scopes given: the provider's registered defaults are requested.
	if strings.Join(g.requested.Scopes, ",") != "repo,read:user" || g.requested.UserID != "u1" || g.requested.ProviderName != "github" {
		t.Errorf("request-connection body = %+v", g.requested)
	}
	if !strings.HasPrefix(g.requested.ReturnURL, "http://127.0.0.1:") {
		t.Errorf("return url = %q, want the loopback landing page", g.requested.ReturnURL)
	}
	if prin.Subject != "alice@example.com" || prin.Email != "alice@example.com" || prin.Issuer != "nexus:github" ||
		prin.ConnectionID != "c1" || prin.GatewayURL != g.URL || strings.Join(prin.Scopes, ",") != "repo:read" {
		t.Errorf("principal = %+v", prin)
	}
	if d := time.Until(prin.ExpiresAt); d < 50*time.Minute || d > time.Hour {
		t.Errorf("expiry in %v, want ~1h", d)
	}
	if c, ok := prin.GetConnection("github"); !ok || c.ConnectionID != "c1" {
		t.Errorf("connection not recorded: %+v", prin.Connections)
	}
}

func TestNexusProviderLoginSubjectFallbacks(t *testing.T) {
	for _, c := range []struct {
		name, id, userID, want string
	}{
		{"user id", "", "u1", "u1"},
		{"connection id", "", "", "nexus:c1"},
		{"preferred username", idToken(map[string]string{"preferred_username": "alice", "sub": "9"}), "u1", "alice"},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newFakeGateway(t)
			g.idToken = c.id
			p := NexusProvider{GatewayURL: g.URL, ProviderName: "github", UserID: c.userID, ProviderScopes: []string{"x"},
				ReturnURL: "https://example.invalid/done", PollInterval: 5 * time.Millisecond, Prompt: func(string) {}}
			prin, err := p.Login(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if prin.Subject != c.want {
				t.Fatalf("subject = %q, want %q", prin.Subject, c.want)
			}
			if d := time.Until(prin.ExpiresAt); d < 7*time.Hour {
				t.Fatalf("default TTL gave expiry in %v", d)
			}
			if strings.Join(g.requested.Scopes, ",") != "x" || g.requested.ReturnURL != "https://example.invalid/done" {
				t.Fatalf("request = %+v", g.requested)
			}
		})
	}
}

func TestConnectErrors(t *testing.T) {
	if _, err := Connect(context.Background(), ConnectOptions{}); err == nil {
		t.Fatal("no provider name accepted")
	}
	for _, c := range []struct{ failOn, want string }{
		{"/v1/request-connection", "request connection"},
		{"/v1/check-connection", "waiting for consent"},
		{"/v1/token", "fetch token"},
	} {
		g := newFakeGateway(t)
		g.failOn = c.failOn
		_, err := Connect(context.Background(), ConnectOptions{GatewayURL: g.URL, ProviderName: "github", ProviderScopes: []string{"x"},
			ReturnURL: "https://example.invalid/", PollInterval: 5 * time.Millisecond, Prompt: func(string) {}})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("fail on %s: err = %v, want %q", c.failOn, err, c.want)
		}
	}

	// Consent never completes: the context bounds the wait.
	g := newFakeGateway(t, "pending", "pending", "pending", "pending", "pending", "pending", "pending", "pending",
		"pending", "pending", "pending", "pending", "pending", "pending", "pending", "pending", "pending", "pending")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := Connect(ctx, ConnectOptions{GatewayURL: g.URL, ProviderName: "github", ProviderScopes: []string{"x"},
		ReturnURL: "https://example.invalid/", PollInterval: 5 * time.Millisecond, Prompt: func(string) {}})
	if err == nil {
		t.Fatal("connect succeeded without consent")
	}
}

func TestStartConnectionStatusAndToken(t *testing.T) {
	g := newFakeGateway(t, "pending")
	ctx := context.Background()
	if _, err := StartConnection(ctx, ConnectOptions{GatewayURL: g.URL}); err == nil {
		t.Fatal("no provider name accepted")
	}
	pc, err := StartConnection(ctx, ConnectOptions{GatewayURL: g.URL, ProviderName: "github", UserID: "u", ReturnURL: "https://r.invalid/"})
	if err != nil {
		t.Fatal(err)
	}
	if pc.ConnectionID != "c1" || pc.AuthURL == "" || pc.GatewayURL != g.URL || strings.Join(pc.Scopes, ",") != "repo,read:user" {
		t.Fatalf("pending = %+v", pc)
	}
	st, err := CheckStatus(ctx, g.URL, "c1")
	if err != nil || st != "pending" || IsActiveStatus(st) {
		t.Fatalf("status = %q %v", st, err)
	}
	if st, _ = CheckStatus(ctx, g.URL, "c1"); !IsActiveStatus(st) {
		t.Fatalf("second status = %q, want active", st)
	}
	tok, err := FetchToken(ctx, g.URL, "c1")
	if err != nil || tok != "at-123" {
		t.Fatalf("token = %q %v", tok, err)
	}
	if _, err := FetchToken(ctx, g.URL, "nope"); err == nil {
		t.Fatal("unknown connection gave a token")
	}

	g.failOn = "/v1/request-connection"
	if _, err := StartConnection(ctx, ConnectOptions{GatewayURL: g.URL, ProviderName: "github"}); err == nil {
		t.Fatal("gateway error not surfaced")
	}
}

func TestIsActiveStatus(t *testing.T) {
	for _, s := range []string{"active", " Success ", "CONNECTED", "authorized", "completed", "ready"} {
		if !IsActiveStatus(s) {
			t.Errorf("%q not active", s)
		}
	}
	for _, s := range []string{"", "pending", "failed", "revoked", "activ"} {
		if IsActiveStatus(s) {
			t.Errorf("%q active", s)
		}
	}
}

func TestIdentityFromToken(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, c := range []struct {
		name        string
		tok         *oauthsdk.TokenResponse
		subj, email string
	}{
		{"nil", nil, "", ""},
		{"no id token", &oauthsdk.TokenResponse{}, "", ""},
		{"empty id token", &oauthsdk.TokenResponse{IDToken: str("")}, "", ""},
		{"two parts", &oauthsdk.TokenResponse{IDToken: str("a.b")}, "", ""},
		{"bad base64", &oauthsdk.TokenResponse{IDToken: str("a.!!!.c")}, "", ""},
		{"bad json", &oauthsdk.TokenResponse{IDToken: str("a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c")}, "", ""},
		{"email", &oauthsdk.TokenResponse{IDToken: str(idToken(map[string]string{"email": "a@x", "sub": "1"}))}, "a@x", "a@x"},
		{"username", &oauthsdk.TokenResponse{IDToken: str(idToken(map[string]string{"preferred_username": "al", "sub": "1"}))}, "al", ""},
		{"sub", &oauthsdk.TokenResponse{IDToken: str(idToken(map[string]string{"sub": "1"}))}, "1", ""},
	} {
		s, e := identityFromToken(c.tok)
		if s != c.subj || e != c.email {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", c.name, s, e, c.subj, c.email)
		}
	}
}

func TestListProvidersFromGateway(t *testing.T) {
	g := newFakeGateway(t)
	ps, err := ListProviders(context.Background(), g.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range ps {
		names = append(names, p.AuthType+":"+p.Name)
	}
	if strings.Join(names, ",") != "oauth2:github,oauth2:google,api_key:openai" {
		t.Fatalf("providers = %v", names)
	}
	if _, err := fetchProviderScopes(context.Background(), g.URL, "missing"); err == nil {
		t.Fatal("unknown provider gave scopes")
	}
	g.failOn = "/v1/providers"
	if _, err := ListProviders(context.Background(), g.URL); err == nil {
		t.Fatal("gateway error not surfaced")
	}
}

func TestReturnURLServer(t *testing.T) {
	u, shutdown, err := ReturnURLServer()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	shutdown()
	if _, err := http.Get(u); err == nil {
		t.Fatal("landing server still up after shutdown")
	}
}

func TestLocalProviderAndSessionPath(t *testing.T) {
	p := LocalProvider{Email: "a@x", Scopes: []string{"s"}}
	if p.Name() != "local" {
		t.Fatalf("Name = %q", p.Name())
	}
	prin, _ := p.Login(context.Background())
	if prin.Subject != "a@x" || prin.Issuer != "local" || !prin.ExpiresAt.IsZero() {
		t.Fatalf("principal = %+v", prin)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sp, err := DefaultSessionPath()
	if err != nil || sp != filepath.Join(home, ".nexus", "session.json") {
		t.Fatalf("session path = %q %v", sp, err)
	}
	if err := Save(sp, prin); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(sp); err != nil || (os.PathSeparator == '/' && fi.Mode().Perm() != 0o600) {
		t.Fatalf("session file: %v %v", fi, err)
	}
	if err := Clear(sp); err != nil {
		t.Fatal(err)
	}
	if err := Clear(sp); err != nil {
		t.Fatalf("clearing a missing session: %v", err)
	}
	// A file where the session directory should be makes Save fail rather than write elsewhere.
	blocker := filepath.Join(home, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Save(filepath.Join(blocker, "session.json"), prin); err == nil {
		t.Fatal("Save under a file succeeded")
	}
	if err := os.WriteFile(sp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(sp); err == nil {
		t.Fatal("corrupt session loaded")
	}
}
