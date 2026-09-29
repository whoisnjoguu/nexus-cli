package principal

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCapScopes(t *testing.T) {
	p := &Principal{Scopes: []string{"db:read", "payout:write"}}
	got := p.CapScopes([]string{"db:read", "admin:all"})
	if len(got) != 1 || got[0] != "db:read" {
		t.Fatalf("CapScopes = %v, want [db:read]", got)
	}
}

func TestCapScopesUnrestricted(t *testing.T) {
	p := &Principal{}
	got := p.CapScopes([]string{"anything"})
	if len(got) != 1 || got[0] != "anything" {
		t.Fatalf("unrestricted principal should pass scopes through, got %v", got)
	}
}

func TestValidExpiry(t *testing.T) {
	if (&Principal{Subject: "a", ExpiresAt: time.Now().Add(-time.Minute)}).Valid() {
		t.Fatal("expired principal should be invalid")
	}
	if !(&Principal{Subject: "a"}).Valid() {
		t.Fatal("principal with no expiry should be valid")
	}
	if (&Principal{}).Valid() {
		t.Fatal("empty principal should be invalid")
	}
}

func TestSaveLoadClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	in := &Principal{Subject: "alice@company.com", Issuer: "local", Scopes: []string{"db:read"}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != in.Subject || out.Issuer != in.Issuer {
		t.Fatalf("round trip mismatch: %+v", out)
	}
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	if p, _ := Load(path); p != nil {
		t.Fatal("expected nil after clear")
	}
}

func TestLocalProviderLogin(t *testing.T) {
	p, err := LocalProvider{Email: "alice@company.com", Scopes: []string{"db:read"}, TTL: time.Hour}.Login(nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "alice@company.com" || p.Issuer != "local" {
		t.Fatalf("unexpected principal: %+v", p)
	}
}
