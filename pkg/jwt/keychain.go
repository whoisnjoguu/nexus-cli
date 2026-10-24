package jwt

import (
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/zalando/go-keyring"
)

// KeychainService is the OS credential-store service name under which signing seeds are stored.
const KeychainService = "nexus-cli"

// ErrKeychainUnavailable wraps failures to reach the OS credential store (no D-Bus/Secret
// Service, locked or declined access, or a call that did not answer in time).
var ErrKeychainUnavailable = errors.New("OS keychain unavailable")

// keyringAPI is the subset of go-keyring used here; swapped in tests.
type keyringAPI interface {
	Get(service, user string) (string, error)
	Set(service, user, password string) error
	Delete(service, user string) error
}

type osKeyring struct{}

func (osKeyring) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (osKeyring) Set(s, u, p string) error        { return keyring.Set(s, u, p) }
func (osKeyring) Delete(s, u string) error        { return keyring.Delete(s, u) }

var (
	keychainProvider keyringAPI = osKeyring{}
	// keychainTimeout bounds each credential-store call; D-Bus calls can hang indefinitely.
	keychainTimeout = 3 * time.Second
)

// KeychainKeyStore stores the base64 seed in the OS credential store.
type KeychainKeyStore struct {
	Service string
	Account string
}

// KeychainAccount derives the credential-store account for a key path, so alternate --key paths
// map to distinct entries.
func KeychainAccount(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve key path %s: %w", path, err)
	}
	return "ed25519:" + filepath.Clean(abs), nil
}

// NewKeychainKeyStore returns a keychain-backed KeyStore for the key path.
func NewKeychainKeyStore(path string) (*KeychainKeyStore, error) {
	acct, err := KeychainAccount(path)
	if err != nil {
		return nil, err
	}
	return &KeychainKeyStore{Service: KeychainService, Account: acct}, nil
}

// Name implements KeyStore.
func (k *KeychainKeyStore) Name() string { return string(BackendKeychain) }

// Load implements KeyStore.
func (k *KeychainKeyStore) Load() ([]byte, error) {
	var v string
	p := keychainProvider
	err := withTimeout(func() (err error) {
		v, err = p.Get(k.Service, k.Account)
		return err
	})
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, fmt.Errorf("%w in keychain (service %s, account %s)", ErrKeyNotFound, k.Service, k.Account)
		}
		return nil, err
	}
	return decodeSeed(v, "keychain account "+k.Account)
}

// Save implements KeyStore.
func (k *KeychainKeyStore) Save(seed []byte) error {
	enc := base64.StdEncoding.EncodeToString(seed)
	p := keychainProvider
	return withTimeout(func() error { return p.Set(k.Service, k.Account, enc) })
}

// Delete implements KeyStore.
func (k *KeychainKeyStore) Delete() error {
	p := keychainProvider
	err := withTimeout(func() error { return p.Delete(k.Service, k.Account) })
	if errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("%w in keychain (account %s)", ErrKeyNotFound, k.Account)
	}
	return err
}

// withTimeout runs fn, returning ErrKeychainUnavailable if it errors (other than not-found) or
// does not complete within keychainTimeout. A timed-out call is abandoned, not cancelled.
func withTimeout(fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	timer := time.NewTimer(keychainTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, keyring.ErrNotFound) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrKeychainUnavailable, err)
	case <-timer.C:
		return fmt.Errorf("%w: no response within %s", ErrKeychainUnavailable, keychainTimeout)
	}
}
