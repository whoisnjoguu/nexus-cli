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
	jwt.RegisteredClaims
}

type TokenSigner struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

func NewTokenSigner() (*TokenSigner, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return &TokenSigner{pubKey: pubKey, privKey: privKey}, nil
}

// PublicKey exposes the verification key so downstream gateways can validate tokens.
func (s *TokenSigner) PublicKey() ed25519.PublicKey {
	return s.pubKey
}

// Verifier returns a Verifier bound to this signer's public key.
func (s *TokenSigner) Verifier() *Verifier {
	return &Verifier{pubKey: s.pubKey}
}

// Verifier validates dual-actor tokens against a known Ed25519 public key.
type Verifier struct {
	pubKey ed25519.PublicKey
}

// NewVerifier builds a Verifier from a raw Ed25519 public key.
func NewVerifier(pub ed25519.PublicKey) *Verifier {
	return &Verifier{pubKey: pub}
}

// Verify parses and validates a dual-actor token, returning its claims on success.
func (v *Verifier) Verify(tokenStr string) (*DualActorClaims, error) {
	claims := &DualActorClaims{}
	_, err := jwt.ParseWithClaims(
		tokenStr, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return v.pubKey, nil
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
}

// Mint issues a dual-actor token, optionally binding a broker connection for credential injection.
func (s *TokenSigner) Mint(o MintOptions) (string, error) {
	now := time.Now()
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := DualActorClaims{
		AgentID: o.AgentID,
		ActAs:   o.UserID,
		Scopes:  o.Scopes,
		ConnID:  o.ConnID,
		Gateway: o.Gateway,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    "nexus-cli-local",
			Audience:  jwt.ClaimStrings{"nexus-gateway"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(o.TTL)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(s.privKey)
}

func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return hex.EncodeToString(b), nil
}
