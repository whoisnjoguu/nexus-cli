package jwt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Thumbprint returns the RFC 7638 JWK thumbprint (base64url SHA-256 of the canonical OKP JWK)
// of an Ed25519 public key. It is used as the JWT "kid".
func Thumbprint(pub ed25519.PublicKey) string {
	// Canonical form: required members only, lexicographic order, no whitespace (RFC 7638 §3.2).
	canon := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RetiredKey is a previously active public key that is still accepted for verification so that
// tokens minted before a rotation remain valid until they expire.
type RetiredKey struct {
	Kid       string    `json:"kid"`
	X         string    `json:"x"`
	RetiredAt time.Time `json:"retired_at"`
}

// PublicKey decodes X and checks it matches Kid.
func (r RetiredKey) PublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(r.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("retired key %s: invalid public key", r.Kid)
	}
	pub := ed25519.PublicKey(raw)
	if Thumbprint(pub) != r.Kid {
		return nil, fmt.Errorf("retired key %s: kid does not match public key", r.Kid)
	}
	return pub, nil
}

// RetiredPath returns the retired public key list stored next to keyPath: for
// ".../ed25519.key" it is ".../ed25519.retired.json". The list is kept on disk for every backend
// because it holds public keys only; it is signed by the current key to prevent tampering.
func RetiredPath(keyPath string) string {
	base := filepath.Base(keyPath)
	if ext := filepath.Ext(base); ext != "" && ext != base {
		base = strings.TrimSuffix(base, ext)
	}
	return filepath.Join(filepath.Dir(keyPath), base+".retired.json")
}

const retiredSigContext = "nexus-cli retired-keys v1\n"

type retiredFile struct {
	Version  int             `json:"version"`
	SignedBy string          `json:"signed_by"`
	Keys     json.RawMessage `json:"keys"`
	Sig      string          `json:"sig"`
}

// loadRetired reads and authenticates the retired list. A missing file is an empty list.
func loadRetired(path string, current ed25519.PublicKey) ([]RetiredKey, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read retired keys %s: %w", path, err)
	}
	var f retiredFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse retired keys %s: %w", path, err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, f.Keys); err != nil {
		return nil, fmt.Errorf("parse retired keys %s: %w", path, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(f.Sig)
	if err != nil || f.SignedBy != Thumbprint(current) ||
		!ed25519.Verify(current, append([]byte(retiredSigContext), compact.Bytes()...), sig) {
		return nil, fmt.Errorf("retired key list %s is not signed by the current signing key (tampered, or the key was "+
			"replaced outside nexus-cli); inspect it and delete it to continue", path)
	}
	var keys []RetiredKey
	if err := json.Unmarshal(compact.Bytes(), &keys); err != nil {
		return nil, fmt.Errorf("parse retired keys %s: %w", path, err)
	}
	cur := Thumbprint(current)
	out := keys[:0]
	for _, k := range keys {
		if k.Kid == cur {
			continue
		}
		if _, err := k.PublicKey(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, k)
	}
	return out, nil
}

// writeRetiredTemp writes the signed list to a temp file next to path and returns its name.
func writeRetiredTemp(path string, keys []RetiredKey, priv ed25519.PrivateKey) (string, error) {
	if keys == nil {
		keys = []RetiredKey{}
	}
	raw, err := json.Marshal(keys)
	if err != nil {
		return "", err
	}
	pub := priv.Public().(ed25519.PublicKey)
	f := retiredFile{
		Version:  1,
		SignedBy: Thumbprint(pub),
		Keys:     raw,
		Sig:      base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(retiredSigContext), raw...))),
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create key dir: %w", err)
	}
	fh, err := os.CreateTemp(dir, ".retired-*.tmp")
	if err != nil {
		return "", fmt.Errorf("write retired keys: %w", err)
	}
	_, werr := fh.Write(append(out, '\n'))
	if werr == nil {
		werr = fh.Sync()
	}
	if cerr := fh.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(fh.Name())
		return "", fmt.Errorf("write retired keys: %w", werr)
	}
	return fh.Name(), nil
}

func saveRetired(path string, keys []RetiredKey, priv ed25519.PrivateKey) error {
	tmp, err := writeRetiredTemp(path, keys, priv)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write retired keys %s: %w", path, err)
	}
	return nil
}

func signerFromSeed(seed []byte) *TokenSigner {
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &TokenSigner{pubKey: pub, privKey: priv, kid: Thumbprint(pub)}
}

func newStoredSigner(seed []byte, path string, store KeyStore) (*TokenSigner, error) {
	s := signerFromSeed(seed)
	retired, err := loadRetired(RetiredPath(path), s.pubKey)
	if err != nil {
		return nil, err
	}
	s.keyPath, s.store, s.retired = path, store, retired
	return s, nil
}

// PruneRetired drops retired keys retired more than olderThan ago and persists the list. Tokens
// signed by pruned keys no longer verify. It returns the number of keys removed.
func (s *TokenSigner) PruneRetired(olderThan time.Duration) (int, error) {
	return s.pruneRetiredAt(olderThan, time.Now())
}

func (s *TokenSigner) pruneRetiredAt(olderThan time.Duration, now time.Time) (int, error) {
	if s.keyPath == "" {
		return 0, errors.New("signer has no persistent key path")
	}
	cutoff := now.Add(-olderThan)
	var keep []RetiredKey
	for _, r := range s.retired {
		if r.RetiredAt.After(cutoff) {
			keep = append(keep, r)
		}
	}
	removed := len(s.retired) - len(keep)
	if removed == 0 {
		return 0, nil
	}
	if err := saveRetired(RetiredPath(s.keyPath), keep, s.privKey); err != nil {
		return 0, err
	}
	s.retired = keep
	return removed, nil
}

// RotateResult describes a completed key rotation.
type RotateResult struct {
	OldKid  string
	NewKid  string
	Backend string
	Signer  *TokenSigner
}

// Rotate replaces the signing key for path with a fresh one in the same backend. The old public
// key is appended to the retired list so tokens it signed stay valid until they expire or it is
// pruned.
func Rotate(path string, backend Backend) (*RotateResult, error) {
	store, err := selectStore(path, backend)
	if err != nil {
		return nil, err
	}
	oldSeed, err := store.Load()
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, fmt.Errorf("no signing key to rotate (%v)", err)
		}
		return nil, err
	}
	old, err := newStoredSigner(oldSeed, path, store)
	if err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	retired := append(old.RetiredKeys(), RetiredKey{
		Kid:       old.kid,
		X:         base64.RawURLEncoding.EncodeToString(old.pubKey),
		RetiredAt: time.Now().UTC().Truncate(time.Second),
	})
	rpath := RetiredPath(path)
	// Prepare the new list first, swap the seed, then publish the list: a failure before the
	// seed swap leaves the old key fully intact.
	tmp, err := writeRetiredTemp(rpath, retired, priv)
	if err != nil {
		return nil, err
	}
	if err := store.Save(priv.Seed()); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("store new key: %w", err)
	}
	if err := os.Rename(tmp, rpath); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("new key %s stored but retired list update failed (old public key %s): %w",
			Thumbprint(priv.Public().(ed25519.PublicKey)), base64.RawURLEncoding.EncodeToString(old.pubKey), err)
	}
	s, err := newStoredSigner(priv.Seed(), path, store)
	if err != nil {
		return nil, err
	}
	return &RotateResult{OldKid: old.kid, NewKid: s.kid, Backend: store.Name(), Signer: s}, nil
}

// MigrateResult describes a completed backend migration.
type MigrateResult struct {
	From   string
	To     string
	Kid    string
	Signer *TokenSigner
}

// Migrate moves the seed for path into the `to` backend (file or keychain). The source copy is
// deleted only after the destination round-trips the identical seed; a source file is
// overwritten before removal.
func Migrate(path string, to Backend) (*MigrateResult, error) {
	fileStore := NewFileKeyStore(path)
	kc, err := NewKeychainKeyStore(path)
	if err != nil {
		return nil, err
	}
	var src, dst KeyStore
	switch to {
	case BackendKeychain:
		src, dst = fileStore, kc
	case BackendFile:
		src, dst = kc, fileStore
	default:
		return nil, fmt.Errorf("migrate target must be %q or %q, got %q", BackendKeychain, BackendFile, to)
	}
	seed, err := src.Load()
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			if _, derr := dst.Load(); derr == nil {
				return nil, fmt.Errorf("signing key for %s is already in the %s backend", path, dst.Name())
			}
			return nil, fmt.Errorf("nothing to migrate: %w", err)
		}
		return nil, err
	}
	existing, err := dst.Load()
	switch {
	case err == nil:
		if subtle.ConstantTimeCompare(existing, seed) != 1 {
			return nil, fmt.Errorf("the %s backend already holds a different signing key for %s; refusing to overwrite", dst.Name(), path)
		}
	case errors.Is(err, ErrKeyNotFound):
		if err := dst.Save(seed); err != nil {
			return nil, fmt.Errorf("store key in %s: %w", dst.Name(), err)
		}
	default:
		return nil, err
	}
	got, err := dst.Load()
	if err != nil {
		return nil, fmt.Errorf("verify key in %s: %w", dst.Name(), err)
	}
	if subtle.ConstantTimeCompare(got, seed) != 1 {
		return nil, fmt.Errorf("verify key in %s: stored seed does not match; source left intact", dst.Name())
	}
	if err := src.Delete(); err != nil {
		return nil, fmt.Errorf("key copied to %s but removing it from %s failed: %w", dst.Name(), src.Name(), err)
	}
	s, err := newStoredSigner(seed, path, dst)
	if err != nil {
		return nil, err
	}
	return &MigrateResult{From: src.Name(), To: dst.Name(), Kid: s.kid, Signer: s}, nil
}
