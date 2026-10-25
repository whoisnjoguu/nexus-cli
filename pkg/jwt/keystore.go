package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Backend selects where the Ed25519 signing seed is stored.
type Backend string

const (
	// BackendAuto uses an existing key file if present, otherwise the OS keychain, falling back to
	// a key file when the keychain is unavailable.
	BackendAuto Backend = "auto"
	// BackendKeychain stores the seed in the OS credential store (macOS Keychain, Linux Secret
	// Service, Windows Credential Manager).
	BackendKeychain Backend = "keychain"
	// BackendFile stores the seed base64-encoded in a 0600 file.
	BackendFile Backend = "file"
)

// KeyBackendEnv names the environment variable that selects the key backend.
const KeyBackendEnv = "NEXUS_KEY_BACKEND"

// ErrKeyNotFound is returned by KeyStore.Load when no key is stored.
var ErrKeyNotFound = errors.New("signing key not found")

// noticeOut receives one-line operational notes (e.g. keychain fallback). Overridable in tests.
var noticeOut io.Writer = os.Stderr

// ParseBackend validates a backend name; the empty string means BackendAuto.
func ParseBackend(s string) (Backend, error) {
	switch b := Backend(strings.ToLower(strings.TrimSpace(s))); b {
	case "":
		return BackendAuto, nil
	case BackendAuto, BackendKeychain, BackendFile:
		return b, nil
	default:
		return "", fmt.Errorf("unknown key backend %q (want auto, keychain or file)", s)
	}
}

// BackendFromEnv returns the backend selected by NEXUS_KEY_BACKEND (default auto).
func BackendFromEnv() (Backend, error) {
	b, err := ParseBackend(os.Getenv(KeyBackendEnv))
	if err != nil {
		return "", fmt.Errorf("%s: %w", KeyBackendEnv, err)
	}
	return b, nil
}

// KeyStore persists a raw Ed25519 seed.
type KeyStore interface {
	// Load returns the seed, or an error wrapping ErrKeyNotFound if none is stored.
	Load() ([]byte, error)
	// Save stores the seed, replacing any existing one.
	Save(seed []byte) error
	// Delete removes the stored seed.
	Delete() error
	// Name returns the backend name ("file" or "keychain").
	Name() string
}

// DefaultKeyPath returns the default persistent key location: $NEXUS_HOME/ed25519.key if
// NEXUS_HOME is set, else ~/.nexus/ed25519.key.
func DefaultKeyPath() (string, error) {
	if h := os.Getenv("NEXUS_HOME"); h != "" {
		return filepath.Join(h, "ed25519.key"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".nexus", "ed25519.key"), nil
}

// FileKeyStore stores the seed base64-encoded in a file with 0600 permissions.
type FileKeyStore struct {
	Path string
}

// NewFileKeyStore returns a file-backed KeyStore at path.
func NewFileKeyStore(path string) *FileKeyStore { return &FileKeyStore{Path: path} }

// Name implements KeyStore.
func (f *FileKeyStore) Name() string { return string(BackendFile) }

// Load implements KeyStore. On unix it refuses keys readable or writable by group/other.
func (f *FileKeyStore) Load() ([]byte, error) {
	fi, err := os.Stat(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s", ErrKeyNotFound, f.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("stat key %s: %w", f.Path, err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key file %s has insecure permissions %#o (accessible by group/other); fix with: chmod 600 %s",
			f.Path, fi.Mode().Perm(), f.Path)
	}
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", f.Path, err)
	}
	return decodeSeed(string(data), f.Path)
}

// Save implements KeyStore by atomically replacing the file with a 0600 one.
func (f *FileKeyStore) Save(seed []byte) error {
	tmp, err := f.writeTemp(seed)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, f.Path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write key %s: %w", f.Path, err)
	}
	return nil
}

// create writes the seed only if no key file exists yet, so concurrent first runs agree on one key.
// It reports os.ErrExist if another process created the file first.
func (f *FileKeyStore) create(seed []byte) error {
	tmp, err := f.writeTemp(seed)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }()
	if err := os.Link(tmp, f.Path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return err
		}
		// Filesystems without hard links: fall back to an exclusive create.
		fh, oerr := os.OpenFile(f.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if oerr != nil {
			return oerr
		}
		_, werr := fh.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n")
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		return werr
	}
	return nil
}

func (f *FileKeyStore) writeTemp(seed []byte) (string, error) {
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("invalid seed length %d", len(seed))
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create key dir: %w", err)
	}
	fh, err := os.CreateTemp(dir, ".ed25519-*.tmp")
	if err != nil {
		return "", fmt.Errorf("write key %s: %w", f.Path, err)
	}
	name := fh.Name()
	fail := func(err error) (string, error) {
		_ = fh.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf("write key %s: %w", f.Path, err)
	}
	if err := fh.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		return fail(err)
	}
	if _, err := fh.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n"); err != nil {
		return fail(err)
	}
	if err := fh.Sync(); err != nil {
		return fail(err)
	}
	if err := fh.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("write key %s: %w", f.Path, err)
	}
	return name, nil
}

// Delete implements KeyStore: the file contents are overwritten before removal. On SSDs and
// copy-on-write filesystems the overwrite is best-effort only.
func (f *FileKeyStore) Delete() error {
	if err := secureRemove(f.Path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w at %s", ErrKeyNotFound, f.Path)
		}
		return err
	}
	return nil
}

func secureRemove(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s for wipe: %w", path, err)
	}
	size := fi.Size()
	buf := make([]byte, size)
	for _, fill := range []func([]byte) error{
		func(b []byte) error { _, err := rand.Read(b); return err },
		func(b []byte) error { clear(b); return nil },
	} {
		if err := fill(buf); err != nil {
			_ = fh.Close()
			return err
		}
		if _, err := fh.WriteAt(buf, 0); err != nil {
			_ = fh.Close()
			return fmt.Errorf("wipe %s: %w", path, err)
		}
		if err := fh.Sync(); err != nil {
			_ = fh.Close()
			return fmt.Errorf("wipe %s: %w", path, err)
		}
	}
	if err := fh.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

func decodeSeed(s, where string) ([]byte, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decode key %s: %w", where, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid key length in %s: got %d want %d", where, len(seed), ed25519.SeedSize)
	}
	return seed, nil
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// LoadOrCreateSigner loads the signing key for path using the backend selected by
// NEXUS_KEY_BACKEND, generating and storing one if absent.
func LoadOrCreateSigner(path string) (*TokenSigner, error) {
	b, err := BackendFromEnv()
	if err != nil {
		return nil, err
	}
	s, _, err := LoadOrCreateSignerWith(path, b)
	return s, err
}

// LoadOrCreateSignerWith loads (or creates) the signing key for path in the given backend and
// returns the signer plus the name of the backend actually used.
//
// With BackendAuto: an existing key file wins (keys are never silently migrated), unless the
// keychain also holds a key for the same path, which is reported as a conflict; otherwise the
// keychain is used, falling back to a file (with a note on stderr) if it is unavailable.
func LoadOrCreateSignerWith(path string, backend Backend) (*TokenSigner, string, error) {
	store, err := selectStore(path, backend)
	if err != nil {
		return nil, "", err
	}
	seed, err := store.Load()
	switch {
	case err == nil:
	case errors.Is(err, ErrKeyNotFound):
		if store.Name() == string(BackendKeychain) && fileExists(path) {
			return nil, "", fmt.Errorf("no key in the keychain for %s but a key file exists there; run: nexus-cli keys migrate --to keychain", path)
		}
		seed, store, err = createKey(path, store, backend)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", err
	}
	s, err := newStoredSigner(seed, path, store)
	if err != nil {
		return nil, "", err
	}
	return s, store.Name(), nil
}

func createKey(path string, store KeyStore, backend Backend) ([]byte, KeyStore, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}
	seed := priv.Seed()
	if fs, ok := store.(*FileKeyStore); ok {
		if err := fs.create(seed); err != nil {
			if errors.Is(err, os.ErrExist) {
				// Lost a creation race; use the winner's key.
				existing, lerr := fs.Load()
				return existing, store, lerr
			}
			return nil, nil, fmt.Errorf("write key %s: %w", path, err)
		}
		return seed, store, nil
	}
	if err := store.Save(seed); err != nil {
		if backend == BackendAuto {
			noteFallback(path, err)
			fs := NewFileKeyStore(path)
			if cerr := fs.create(seed); cerr != nil {
				if errors.Is(cerr, os.ErrExist) {
					existing, lerr := fs.Load()
					return existing, fs, lerr
				}
				return nil, nil, fmt.Errorf("write key %s: %w", path, cerr)
			}
			return seed, fs, nil
		}
		return nil, nil, err
	}
	return seed, store, nil
}

// selectStore resolves backend to a concrete KeyStore for path.
func selectStore(path string, backend Backend) (KeyStore, error) {
	switch backend {
	case BackendFile:
		return NewFileKeyStore(path), nil
	case BackendKeychain:
		return NewKeychainKeyStore(path)
	case BackendAuto, "":
	default:
		return nil, fmt.Errorf("unknown key backend %q", backend)
	}
	kc, err := NewKeychainKeyStore(path)
	if err != nil {
		return nil, err
	}
	_, kerr := kc.Load()
	if fileExists(path) {
		if kerr == nil {
			return nil, fmt.Errorf("signing key for %s exists both as a file and in the OS keychain (account %q); "+
				"refusing to guess which is authoritative — remove the file if it was not created by you, "+
				"or set %s=file|keychain explicitly", path, kc.Account, KeyBackendEnv)
		}
		return NewFileKeyStore(path), nil
	}
	if kerr == nil || errors.Is(kerr, ErrKeyNotFound) {
		return kc, nil
	}
	noteFallback(path, kerr)
	return NewFileKeyStore(path), nil
}

func noteFallback(path string, err error) {
	fmt.Fprintf(noticeOut, "nexus-cli: OS keychain unavailable (%v); storing signing key in file %s\n", err, path)
}
