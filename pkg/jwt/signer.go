// Package jwt mints Ed25519-signed dual-actor tokens binding an agent to a human principal.
package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DualActorClaims explicitly binds Agent and Human identity
type DualActorClaims struct {
	AgentID string   `json:"sub"`    // The Agent ID
	ActAs   string   `json:"act_as"` // The Human Developer/Principal
	Scopes  []string `json:"scopes"` // Restricted Scope Ceiling
	// ConnID and Gateway link the token to a nexus-framework broker connection so the proxy can
	// fetch short-lived upstream credentials on the human's behalf
	ConnID  string `json:"conn_id,omitempty"`
	Gateway string `json:"gw,omitempty"`
	// SingleUse asks verifiers to reject any reuse of this token's jti. When false the token is
	// reusable until it expires.
	SingleUse bool `json:"single_use,omitempty"`
	jwt.RegisteredClaims
}

type TokenSigner struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
	kid     string

	// Set for signers loaded from persistent storage.
	keyPath string
	store   KeyStore
	retired []RetiredKey
}

func NewTokenSigner() (*TokenSigner, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return &TokenSigner{pubKey: pubKey, privKey: privKey, kid: Thumbprint(pubKey)}, nil
}

// PublicKey exposes the verification key so downstream gateways can validate tokens.
func (s *TokenSigner) PublicKey() ed25519.PublicKey {
	return s.pubKey
}

// Kid returns the RFC 7638 JWK thumbprint of the signing key, used as the JWT "kid" header.
func (s *TokenSigner) Kid() string { return s.kid }

// Backend returns the name of the backend the key was loaded from ("" for ephemeral signers).
func (s *TokenSigner) Backend() string {
	if s.store == nil {
		return ""
	}
	return s.store.Name()
}

// Location describes where the seed lives: the file path or the keychain service/account.
func (s *TokenSigner) Location() string {
	switch st := s.store.(type) {
	case *FileKeyStore:
		return st.Path
	case *KeychainKeyStore:
		return fmt.Sprintf("keychain service %q account %q", st.Service, st.Account)
	default:
		return ""
	}
}

// RetiredKeys returns the retired public keys still accepted for verification.
func (s *TokenSigner) RetiredKeys() []RetiredKey {
	return append([]RetiredKey(nil), s.retired...)
}

// Verifier returns a Verifier that accepts tokens signed by this signer's current key and by any
// retired key still listed, so rotation does not invalidate in-flight tokens.
func (s *TokenSigner) Verifier() *Verifier {
	keys := map[string]ed25519.PublicKey{s.kid: s.pubKey}
	for _, r := range s.retired {
		if pub, err := r.PublicKey(); err == nil {
			keys[r.Kid] = pub
		}
	}
	return &Verifier{pubKey: s.pubKey, keys: keys}
}

// Verifier validates dual-actor tokens against a set of Ed25519 public keys indexed by kid.
type Verifier struct {
	// pubKey is the current key, used for tokens without a kid header (may be nil).
	pubKey ed25519.PublicKey
	keys   map[string]ed25519.PublicKey
}

// NewVerifier builds a Verifier from a raw Ed25519 public key.
func NewVerifier(pub ed25519.PublicKey) *Verifier {
	return &Verifier{pubKey: pub, keys: map[string]ed25519.PublicKey{Thumbprint(pub): pub}}
}

// NewKeySetVerifier builds a Verifier from public keys indexed by kid. Tokens carrying a kid are
// verified with the matching key only; tokens without a kid are accepted only when the set
// holds exactly one key.
func NewKeySetVerifier(keys map[string]ed25519.PublicKey) *Verifier {
	v := &Verifier{keys: make(map[string]ed25519.PublicKey, len(keys))}
	for kid, pub := range keys {
		v.keys[kid] = pub
		if len(keys) == 1 {
			v.pubKey = pub
		}
	}
	return v
}

// Verify parses and validates a dual-actor token, returning its claims on success.
func (v *Verifier) Verify(tokenStr string) (*DualActorClaims, error) {
	claims := &DualActorClaims{}
	_, err := jwt.ParseWithClaims(
		tokenStr, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return v.keyFor(t.Header["kid"])
		},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer("nexus-cli-local"),
		jwt.WithAudience("nexus-gateway"),
	)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *Verifier) keyFor(kidHeader any) (ed25519.PublicKey, error) {
	if kidHeader == nil {
		if v.pubKey == nil {
			return nil, fmt.Errorf("token has no kid and verifier has no default key")
		}
		return v.pubKey, nil
	}
	kid, ok := kidHeader.(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("invalid kid header")
	}
	pub, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown signing key id %q", kid)
	}
	return pub, nil
}

func (s *TokenSigner) MintDualActorToken(agentID, userID string, scopes []string, ttl time.Duration) (string, error) {
	return s.Mint(MintOptions{AgentID: agentID, UserID: userID, Scopes: scopes, TTL: ttl})
}

// MintOptions carries all fields for minting a dual-actor token.
type MintOptions struct {
	AgentID string
	UserID  string
	Scopes  []string
	ConnID  string
	Gateway string
	TTL     time.Duration
	// SingleUse sets the single_use claim so the proxy enforces one request per token.
	SingleUse bool
}

// Mint issues a dual-actor token, optionally binding a broker connection for credential injection.
func (s *TokenSigner) Mint(o MintOptions) (string, error) {
	now := time.Now()
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := DualActorClaims{
		AgentID:   o.AgentID,
		ActAs:     o.UserID,
		Scopes:    o.Scopes,
		ConnID:    o.ConnID,
		Gateway:   o.Gateway,
		SingleUse: o.SingleUse,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    "nexus-cli-local",
			Audience:  jwt.ClaimStrings{"nexus-gateway"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(o.TTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if s.kid != "" {
		token.Header["kid"] = s.kid
	}
	return token.SignedString(s.privKey)
}

func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return hex.EncodeToString(b), nil
}
