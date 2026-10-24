package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"sort"
)

// JWK is a single JSON Web Key for an Ed25519 public key (OKP / Ed25519).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

// JWKS is a JSON Web Key Set that downstream services fetch to verify nexus-issued tokens
// themselves, instead of trusting proxy-injected headers.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns every key the verifier accepts, the default (current) key first.
func (v *Verifier) JWKS() JWKS {
	set := JWKS{Keys: []JWK{}}
	var cur string
	if v.pubKey != nil {
		cur = Thumbprint(v.pubKey)
		set.Keys = append(set.Keys, jwkFromPublic(v.pubKey))
	}
	kids := make([]string, 0, len(v.keys))
	for kid := range v.keys {
		if kid != cur {
			kids = append(kids, kid)
		}
	}
	sort.Strings(kids)
	for _, kid := range kids {
		k := jwkFromPublic(v.keys[kid])
		k.Kid = kid
		set.Keys = append(set.Keys, k)
	}
	return set
}

// JWKS returns the signer's current key followed by any retired keys still accepted.
func (s *TokenSigner) JWKS() JWKS {
	set := JWKS{Keys: []JWK{jwkFromPublic(s.pubKey)}}
	for _, r := range s.retired {
		if pub, err := r.PublicKey(); err == nil {
			set.Keys = append(set.Keys, jwkFromPublic(pub))
		}
	}
	return set
}

func jwkFromPublic(pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Use: "sig",
		Alg: "EdDSA",
		Kid: Thumbprint(pub),
	}
}
