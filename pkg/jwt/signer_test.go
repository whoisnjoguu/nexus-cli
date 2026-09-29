package jwt

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	s, err := NewTokenSigner()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.MintDualActorToken("agent", "user", []string{"read"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.Verifier().Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.AgentID != "agent" || claims.ActAs != "user" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	s, _ := NewTokenSigner()
	tok, _ := s.MintDualActorToken("a", "u", nil, -time.Minute)
	if _, err := s.Verifier().Verify(tok); err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	s1, _ := NewTokenSigner()
	s2, _ := NewTokenSigner()
	tok, _ := s1.MintDualActorToken("a", "u", nil, time.Minute)
	if _, err := s2.Verifier().Verify(tok); err == nil {
		t.Fatal("expected signature verification error")
	}
}

func TestLoadOrCreateSignerPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ed25519.key")
	s1, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrCreateSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s1.MintDualActorToken("a", "u", nil, time.Minute)
	if _, err := s2.Verifier().Verify(tok); err != nil {
		t.Fatalf("second load should verify the first signer's token: %v", err)
	}
}
