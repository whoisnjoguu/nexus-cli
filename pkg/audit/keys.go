package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyID is the first 16 hex chars of sha256(public key).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// DefaultKeyPath returns the audit signing key location: ($NEXUS_HOME or ~/.nexus)/audit.key.
// It is deliberately separate from the token-signing key.
func DefaultKeyPath() (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "audit.key"), nil
}

// DefaultPubKeyPath returns the public key written next to the default signing key.
func DefaultPubKeyPath() (string, error) {
	k, err := DefaultKeyPath()
	if err != nil {
		return "", err
	}
	return PublicKeyPath(k), nil
}

// PublicKeyPath maps a key path to its public key file ("audit.key" -> "audit.pub").
func PublicKeyPath(keyPath string) string {
	return strings.TrimSuffix(keyPath, filepath.Ext(keyPath)) + ".pub"
}

// LoadOrCreateKey loads a base64 Ed25519 seed from path (0600), generating one if absent. The
// public key is (re)written to PublicKeyPath(path) so verification never needs the private key.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	var priv ed25519.PrivateKey
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		seed, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil {
			return nil, fmt.Errorf("decode audit key %s: %w", path, derr)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid audit key length in %s: got %d want %d", path, len(seed), ed25519.SeedSize)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create key dir: %w", err)
		}
		_, p, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, fmt.Errorf("generate audit keypair: %w", gerr)
		}
		enc := base64.StdEncoding.EncodeToString(p.Seed())
		f, oerr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if oerr != nil {
			if errors.Is(oerr, os.ErrExist) {
				return LoadOrCreateKey(path) // lost a creation race; use the winner's key
			}
			return nil, fmt.Errorf("write audit key %s: %w", path, oerr)
		}
		_, werr := f.WriteString(enc + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, fmt.Errorf("write audit key %s: %w", path, werr)
		}
		priv = p
	default:
		return nil, fmt.Errorf("read audit key %s: %w", path, err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := writePublicKey(PublicKeyPath(path), pub); err != nil {
		return nil, err
	}
	return priv, nil
}

func writePublicKey(path string, pub ed25519.PublicKey) error {
	enc := EncodePublicKey(pub)
	cur, err := os.ReadFile(path)
	if err == nil {
		for _, line := range strings.Split(string(cur), "\n") {
			if strings.TrimSpace(line) == enc {
				return nil
			}
		}
	}
	// Append rather than overwrite so earlier keys stay available for verifying old history.
	if len(cur) > 0 && !bytes.HasSuffix(cur, []byte("\n")) {
		enc = "\n" + enc
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("write audit public key %s: %w", path, err)
	}
	_, werr := f.WriteString(enc + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("write audit public key %s: %w", path, werr)
	}
	return nil
}

// EncodePublicKey returns the base64 form used in .pub files.
func EncodePublicKey(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

// LoadPublicKeys reads base64 Ed25519 public keys, one per line ('#' comments allowed), so old
// keys can be kept for verifying history after a key rotation.
func LoadPublicKeys(path string) ([]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read audit public key: %w", err)
	}
	var keys []ed25519.PublicKey
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid audit public key in %s", path)
		}
		keys = append(keys, ed25519.PublicKey(b))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no public keys in %s", path)
	}
	return keys, nil
}
