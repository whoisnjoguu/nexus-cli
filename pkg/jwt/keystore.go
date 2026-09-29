package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultKeyPath returns the default persistent key location (~/.nexus/ed25519.key).
func DefaultKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".nexus", "ed25519.key"), nil
}

// LoadOrCreateSigner loads a persisted Ed25519 seed from path, generating and saving one if absent.
func LoadOrCreateSigner(path string) (*TokenSigner, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil {
			return nil, fmt.Errorf("decode key %s: %w", path, derr)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid key length in %s: got %d want %d", path, len(seed), ed25519.SeedSize)
		}
		return signerFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	_, priv, gerr := ed25519.GenerateKey(rand.Reader)
	if gerr != nil {
		return nil, fmt.Errorf("generate keypair: %w", gerr)
	}
	seed := priv.Seed()
	encoded := base64.StdEncoding.EncodeToString(seed)
	if werr := os.WriteFile(path, []byte(encoded+"\n"), 0o600); werr != nil {
		return nil, fmt.Errorf("write key %s: %w", path, werr)
	}
	return signerFromSeed(seed), nil
}

func signerFromSeed(seed []byte) *TokenSigner {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &TokenSigner{pubKey: pub, privKey: priv}
}
