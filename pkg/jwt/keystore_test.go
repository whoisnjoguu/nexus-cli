package jwt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// freshKeychain resets the in-memory keyring mock and restores package hooks after the test.
func freshKeychain(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	prevP, prevT, prevN := keychainProvider, keychainTimeout, noticeOut
	t.Cleanup(func() {
		keychainProvider, keychainTimeout, noticeOut = prevP, prevT, prevN
		keyring.MockInit()
	})
}

func captureNotice(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	noticeOut = &buf
	return &buf
}

type hangingKeyring struct{ release chan struct{} }

func (h hangingKeyring) Get(string, string) (string, error) {
	<-h.release
	return "", keyring.ErrNotFound
}
func (h hangingKeyring) Set(string, string, string) error { <-h.release; return nil }
func (h hangingKeyring) Delete(string, string) error      { <-h.release; return nil }

type failingSetKeyring struct{}

func (failingSetKeyring) Get(string, string) (string, error) { return "", keyring.ErrNotFound }
func (failingSetKeyring) Set(string, string, string) error   { return errors.New("collection locked") }
func (failingSetKeyring) Delete(string, string) error        { return keyring.ErrNotFound }

func keyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "nexus", "ed25519.key")
}

func TestFileBackendCreateLoadPerms(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	s1, used, err := LoadOrCreateSignerWith(path, BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if used != "file" || s1.Backend() != "file" || s1.Location() != path {
		t.Fatalf("backend=%q location=%q", used, s1.Location())
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("key perms = %#o, want 0600", fi.Mode().Perm())
		}
		di, _ := os.Stat(filepath.Dir(path))
		if di.Mode().Perm() != 0o700 {
			t.Fatalf("dir perms = %#o, want 0700", di.Mode().Perm())
		}
	}
	s2, _, err := LoadOrCreateSignerWith(path, BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Kid() != s2.Kid() {
		t.Fatal("reload produced a different key")
	}
	if _, err := keyring.Get(KeychainService, mustAccount(t, path)); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("file backend must not touch the keychain: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestFileBackendRejectsInsecurePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	freshKeychain(t)
	path := keyPath(t)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, _, err := LoadOrCreateSignerWith(path, BackendFile)
		if err == nil || !strings.Contains(err.Error(), "chmod 600 "+path) {
			t.Fatalf("mode %#o: want insecure-permissions error with chmod hint, got %v", mode, err)
		}
	}
	_ = os.Chmod(path, 0o600)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatalf("0600 should load: %v", err)
	}
}

func TestFileBackendRejectsCorruptKey(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, []byte("bm90IGEgc2VlZA==\n"), 0o600)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err == nil || !strings.Contains(err.Error(), "invalid key length") {
		t.Fatalf("want length error, got %v", err)
	}
}

func TestLegacyKeyFileStillWorks(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, b := range []Backend{BackendAuto, BackendFile} {
		s, used, err := LoadOrCreateSignerWith(path, b)
		if err != nil {
			t.Fatal(err)
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if used != "file" || !s.PublicKey().Equal(pub) || len(s.RetiredKeys()) != 0 {
			t.Fatalf("%s: used=%s retired=%d", b, used, len(s.RetiredKeys()))
		}
		tok, _ := s.MintDualActorToken("a", "u", nil, time.Minute)
		if _, err := NewVerifier(pub).Verify(tok); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(RetiredPath(path)); !os.IsNotExist(err) {
		t.Fatal("loading must not create a retired list")
	}
}

func mustAccount(t *testing.T, path string) string {
	t.Helper()
	a, err := KeychainAccount(path)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestKeychainBackendCreateLoadDelete(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	s1, used, err := LoadOrCreateSignerWith(path, BackendKeychain)
	if err != nil {
		t.Fatal(err)
	}
	if used != "keychain" || !strings.Contains(s1.Location(), "nexus-cli") {
		t.Fatalf("used=%s location=%s", used, s1.Location())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("keychain backend must not write a key file")
	}
	stored, err := keyring.Get(KeychainService, mustAccount(t, path))
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := base64.StdEncoding.DecodeString(stored)
	if !ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey).Equal(s1.PublicKey()) {
		t.Fatal("keychain value is not the signer's seed")
	}
	s2, _, err := LoadOrCreateSignerWith(path, BackendKeychain)
	if err != nil || s2.Kid() != s1.Kid() {
		t.Fatalf("reload: %v", err)
	}
	ks, _ := NewKeychainKeyStore(path)
	if ks.Name() != "keychain" {
		t.Fatal(ks.Name())
	}
	if err := ks.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Load(); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := ks.Delete(); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestKeychainAccountDistinctPerPath(t *testing.T) {
	freshKeychain(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.key"), filepath.Join(dir, "b.key")
	if mustAccount(t, a) == mustAccount(t, b) {
		t.Fatal("distinct paths must map to distinct accounts")
	}
	if mustAccount(t, a) != mustAccount(t, filepath.Join(dir, ".", "x", "..", "a.key")) {
		t.Fatal("equivalent paths must map to the same account")
	}
	sa, _, _ := LoadOrCreateSignerWith(a, BackendKeychain)
	sb, _, _ := LoadOrCreateSignerWith(b, BackendKeychain)
	if sa.Kid() == sb.Kid() {
		t.Fatal("separate paths should get separate keys")
	}
}

func TestKeychainExplicitRefusesWhenOnlyFileExists(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadOrCreateSignerWith(path, BackendKeychain)
	if err == nil || !strings.Contains(err.Error(), "keys migrate --to keychain") {
		t.Fatalf("want migrate hint, got %v", err)
	}
}

func TestKeychainExplicitUnavailableErrors(t *testing.T) {
	freshKeychain(t)
	keyring.MockInitWithError(errors.New("no dbus"))
	path := keyPath(t)
	_, _, err := LoadOrCreateSignerWith(path, BackendKeychain)
	if !errors.Is(err, ErrKeychainUnavailable) {
		t.Fatalf("want ErrKeychainUnavailable, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("explicit keychain must not fall back to a file")
	}
}

func TestAutoExistingFileWins(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	f, _, err := LoadOrCreateSignerWith(path, BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	s, used, err := LoadOrCreateSignerWith(path, BackendAuto)
	if err != nil {
		t.Fatal(err)
	}
	if used != "file" || s.Kid() != f.Kid() {
		t.Fatalf("used=%s", used)
	}
	if _, err := keyring.Get(KeychainService, mustAccount(t, path)); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatal("auto must not silently migrate an existing file into the keychain")
	}
}

func TestAutoNoFileUsesKeychain(t *testing.T) {
	freshKeychain(t)
	note := captureNotice(t)
	path := keyPath(t)
	s1, used, err := LoadOrCreateSignerWith(path, BackendAuto)
	if err != nil {
		t.Fatal(err)
	}
	if used != "keychain" {
		t.Fatalf("used=%s", used)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no key file expected")
	}
	s2, used, err := LoadOrCreateSignerWith(path, BackendAuto)
	if err != nil || used != "keychain" || s2.Kid() != s1.Kid() {
		t.Fatalf("reload: used=%s err=%v", used, err)
	}
	if note.Len() != 0 {
		t.Fatalf("unexpected note: %q", note)
	}
}

func TestAutoConflictWhenBothExist(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	if _, _, err := LoadOrCreateSignerWith(path, BackendKeychain); err != nil {
		t.Fatal(err)
	}
	// Simulates an agent planting its own key file to take over signing.
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadOrCreateSignerWith(path, BackendAuto)
	if err == nil || !strings.Contains(err.Error(), "both as a file and in the OS keychain") {
		t.Fatalf("want conflict error, got %v", err)
	}
	if s, used, err := LoadOrCreateSignerWith(path, BackendKeychain); err != nil || used != "keychain" || s == nil {
		t.Fatalf("explicit keychain should still work: %v", err)
	}
}

func TestAutoKeychainErrorFallsBackToFile(t *testing.T) {
	freshKeychain(t)
	keyring.MockInitWithError(errors.New("org.freedesktop.DBus.Error.ServiceUnknown"))
	note := captureNotice(t)
	path := keyPath(t)
	s, used, err := LoadOrCreateSignerWith(path, BackendAuto)
	if err != nil {
		t.Fatal(err)
	}
	if used != "file" || s.Location() != path {
		t.Fatalf("used=%s", used)
	}
	if !strings.Contains(note.String(), "OS keychain unavailable") || strings.Count(note.String(), "\n") != 1 {
		t.Fatalf("want one-line note, got %q", note)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestAutoKeychainSaveFailureFallsBackToFile(t *testing.T) {
	freshKeychain(t)
	keychainProvider = failingSetKeyring{}
	note := captureNotice(t)
	path := keyPath(t)
	_, used, err := LoadOrCreateSignerWith(path, BackendAuto)
	if err != nil || used != "file" {
		t.Fatalf("used=%s err=%v", used, err)
	}
	if !strings.Contains(note.String(), "collection locked") {
		t.Fatalf("note = %q", note)
	}
}

func TestAutoHangingKeychainTimesOut(t *testing.T) {
	freshKeychain(t)
	h := hangingKeyring{release: make(chan struct{})}
	t.Cleanup(func() { close(h.release) })
	keychainProvider = h
	keychainTimeout = 50 * time.Millisecond
	note := captureNotice(t)
	path := keyPath(t)
	start := time.Now()
	_, used, err := LoadOrCreateSignerWith(path, BackendAuto)
	if err != nil {
		t.Fatal(err)
	}
	if used != "file" {
		t.Fatalf("used=%s", used)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("fallback took %v", el)
	}
	if !strings.Contains(note.String(), "no response within") {
		t.Fatalf("note = %q", note)
	}
	// Subsequent loads use the file; the keychain probe still times out but is not fatal.
	if _, used, err := LoadOrCreateSignerWith(path, BackendAuto); err != nil || used != "file" {
		t.Fatalf("reload used=%s err=%v", used, err)
	}
}

func TestBackendParsingAndEnv(t *testing.T) {
	for in, want := range map[string]Backend{"": BackendAuto, "auto": BackendAuto, " KEYCHAIN ": BackendKeychain, "file": BackendFile} {
		got, err := ParseBackend(in)
		if err != nil || got != want {
			t.Fatalf("ParseBackend(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseBackend("vault"); err == nil {
		t.Fatal("want error")
	}
	t.Setenv(KeyBackendEnv, "bogus")
	if _, err := BackendFromEnv(); err == nil || !strings.Contains(err.Error(), KeyBackendEnv) {
		t.Fatalf("want env error, got %v", err)
	}
	if _, err := LoadOrCreateSigner(keyPath(t)); err == nil {
		t.Fatal("LoadOrCreateSigner must reject an invalid backend")
	}
}

func TestLoadOrCreateSignerHonoursEnv(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	t.Setenv(KeyBackendEnv, "file")
	s, err := LoadOrCreateSigner(path)
	if err != nil || s.Backend() != "file" {
		t.Fatalf("err=%v", err)
	}
	path2 := keyPath(t)
	t.Setenv(KeyBackendEnv, "keychain")
	s2, err := LoadOrCreateSigner(path2)
	if err != nil || s2.Backend() != "keychain" {
		t.Fatalf("err=%v", err)
	}
}

func TestDefaultKeyPathHonoursNexusHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)
	p, err := DefaultKeyPath()
	if err != nil || p != filepath.Join(home, "ed25519.key") {
		t.Fatalf("got %q %v", p, err)
	}
	t.Setenv("NEXUS_HOME", "")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	p, err = DefaultKeyPath()
	if err != nil || p != filepath.Join(home, ".nexus", "ed25519.key") {
		t.Fatalf("got %q %v", p, err)
	}
}

func TestConcurrentFileCreateAgreesOnOneKey(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	const n = 8
	kids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, _, err := LoadOrCreateSignerWith(path, BackendFile)
			errs[i] = err
			if err == nil {
				kids[i] = s.Kid()
			}
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil || kids[i] != kids[0] {
			t.Fatalf("goroutine %d: kid=%s err=%v (want %s)", i, kids[i], errs[i], kids[0])
		}
	}
}

func TestFileDeleteWipesAndRemoves(t *testing.T) {
	path := keyPath(t)
	fs := NewFileKeyStore(path)
	if err := fs.Save(bytes.Repeat([]byte{1}, ed25519.SeedSize)); err != nil {
		t.Fatal(err)
	}
	if err := fs.Delete(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should be gone")
	}
	if err := fs.Delete(); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("got %v", err)
	}
	if err := fs.Save([]byte("short")); err == nil {
		t.Fatal("want seed length error")
	}
}
