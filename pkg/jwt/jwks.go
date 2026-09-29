package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
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

// JWKS returns the verifier's public key as a single-key JWKS.
func (v *Verifier) JWKS() JWKS {
	return JWKS{Keys: []JWK{jwkFromPublic(v.pubKey)}}
}

// JWKS returns the signer's public key as a single-key JWKS.
func (s *TokenSigner) JWKS() JWKS {
	return JWKS{Keys: []JWK{jwkFromPublic(s.pubKey)}}
}

func jwkFromPublic(pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Use: "sig",
		Alg: "EdDSA",
	}
}
