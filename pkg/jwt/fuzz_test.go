package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// FuzzVerify checks that Verify never panics and never accepts a token that is not an Ed25519
// signature, by one of the verifier's keys, over the token's exact header.payload bytes.
func FuzzVerify(f *testing.F) {
	s := signerFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	other := signerFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	v := s.Verifier()
	keys := []ed25519.PublicKey{s.PublicKey()}

	const ttl = 100 * 365 * 24 * time.Hour
	good, _ := s.Mint(MintOptions{AgentID: "agent", UserID: "alice", Scopes: []string{"read"}, TTL: ttl, SingleUse: true})
	f.Add(good)
	expired, _ := s.Mint(MintOptions{AgentID: "agent", UserID: "alice", TTL: -time.Hour})
	f.Add(expired)
	forged, _ := other.Mint(MintOptions{AgentID: "agent", UserID: "alice", TTL: ttl})
	f.Add(forged)
	// The other key's token relabelled with our kid.
	parts := strings.Split(forged, ".")
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"` + s.Kid() + `","typ":"JWT"}`))
	f.Add(hdr + "." + parts[1] + "." + parts[2])
	// No kid: falls back to the current key.
	nokid := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, DualActorClaims{AgentID: "a", RegisteredClaims: gojwt.RegisteredClaims{
		Issuer: "nexus-cli-local", Audience: gojwt.ClaimStrings{"nexus-gateway"}, ExpiresAt: gojwt.NewNumericDate(time.Now().Add(ttl)),
	}})
	if tok, err := nokid.SignedString(s.privKey); err == nil {
		f.Add(tok)
	}
	// alg confusion: HS256 keyed with the public key, and alg none.
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	f.Add(none + "." + strings.Split(good, ".")[1] + ".")
	hs := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + strings.Split(good, ".")[1]
	mac := hmac.New(sha256.New, s.PublicKey())
	mac.Write([]byte(hs))
	f.Add(hs + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	f.Add(strings.TrimSuffix(good, "A") + "B")
	f.Add(good + "=")
	f.Add("")
	f.Add("..")
	f.Add("a.b.c.d")

	f.Fuzz(func(t *testing.T, tok string) {
		claims, err := v.Verify(tok)
		if err != nil {
			if claims != nil {
				t.Fatal("claims returned with an error")
			}
			return
		}
		p := strings.Split(tok, ".")
		if len(p) != 3 {
			t.Fatalf("accepted a token with %d segments", len(p))
		}
		sig, derr := base64.RawURLEncoding.DecodeString(p[2])
		if derr != nil {
			sig, derr = base64.URLEncoding.DecodeString(p[2])
		}
		if derr != nil {
			t.Fatalf("accepted an undecodable signature: %q", tok)
		}
		ok := false
		for _, k := range keys {
			ok = ok || ed25519.Verify(k, []byte(p[0]+"."+p[1]), sig)
		}
		if !ok {
			t.Fatalf("accepted a token not signed by the verifier's key: %q", tok)
		}
		if claims.Issuer != "nexus-cli-local" || claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			t.Fatalf("accepted claims %+v", claims)
		}
	})
}
