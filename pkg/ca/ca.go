// Package ca manages the local certificate authority nexus-cli uses to intercept (MITM) TLS
// traffic from supervised agents, so that full policy can be applied to HTTPS requests.
package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	certFile   = "ca.crt"
	keyFile    = "ca.key"
	bundleFile = "bundle.pem"

	// CommonName is the subject CN of every nexus-cli local CA; trust-store removal keys off it.
	CommonName = "nexus-cli local CA"

	caValidity = 10 * 365 * 24 * time.Hour
)

// CA is a loaded local certificate authority able to mint short-lived leaf certificates.
type CA struct {
	dir     string
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey

	// now is the clock used for leaf validity; overridable in tests.
	now func() time.Time

	leafKeyOnce sync.Once
	leafKey     *ecdsa.PrivateKey
	leafKeyErr  error

	mu       sync.Mutex
	cache    map[string]*leafEntry
	order    []string // insertion order of cache keys, oldest first
	maxCache int
}

// DefaultDir returns $NEXUS_HOME/ca if NEXUS_HOME is set, else ~/.nexus/ca.
func DefaultDir() (string, error) {
	if h := os.Getenv("NEXUS_HOME"); h != "" {
		return filepath.Join(h, "ca"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".nexus", "ca"), nil
}

// LoadOrCreate loads the CA stored in dir, generating and persisting a new one if none exists.
func LoadOrCreate(dir string) (*CA, error) {
	c, err := Load(dir)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, cerr := os.Stat(filepath.Join(dir, certFile))
	_, kerr := os.Stat(filepath.Join(dir, keyFile))
	if cerr == nil || kerr == nil {
		// One half exists: refuse to silently overwrite it.
		return nil, err
	}
	return create(dir)
}

// Load reads an existing CA from dir. The returned error wraps os.ErrNotExist if it is missing.
func Load(dir string) (*CA, error) {
	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)

	certData, err := os.ReadFile(certPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, kerr := os.Stat(keyPath); kerr == nil {
				return nil, fmt.Errorf("incomplete CA in %s: %s present but %s missing (remove the directory to regenerate): %w", dir, keyFile, certFile, os.ErrNotExist)
			}
			return nil, fmt.Errorf("no CA in %s (run: nexus-cli ca init): %w", dir, os.ErrNotExist)
		}
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("incomplete CA in %s: %s present but %s missing (remove the directory to regenerate): %w", dir, certFile, keyFile, os.ErrNotExist)
		}
		return nil, fmt.Errorf("stat CA key: %w", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("CA key %s has insecure permissions %#o; run: chmod 600 %s", keyPath, fi.Mode().Perm(), keyPath)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	cert, err := parseCertPEM(certData)
	if err != nil {
		return nil, fmt.Errorf("CA certificate %s is corrupt: %w", certPath, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("CA certificate %s is not a CA certificate", certPath)
	}
	key, err := parseKeyPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("CA key %s is corrupt: %w", keyPath, err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("CA key %s does not match certificate %s", keyPath, certPath)
	}
	return newCA(dir, cert, key), nil
}

func newCA(dir string, cert *x509.Certificate, key *ecdsa.PrivateKey) *CA {
	return &CA{
		dir:      dir,
		cert:     cert,
		certPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		key:      key,
		now:      time.Now,
		cache:    make(map[string]*leafEntry),
		maxCache: defaultMaxCache,
	}
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PKCS#8 PRIVATE KEY PEM block found")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type %T (want ECDSA)", k)
	}
	return ek, nil
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func ownerOU() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	host := "localhost"
	if h, err := os.Hostname(); err == nil && h != "" {
		host = h
	}
	return name + "@" + host
}

func create(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create CA dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("chmod CA dir: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         CommonName,
			Organization:       []string{"nexus-cli"},
			OrganizationalUnit: []string{ownerOU()},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	// Key first: a crash leaves a lone key, which Load reports rather than overwriting.
	if err := writeFileAtomic(filepath.Join(dir, keyFile), keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}
	c := newCA(dir, cert, key)
	if err := writeFileAtomic(filepath.Join(dir, certFile), c.certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("write CA certificate: %w", err)
	}
	return c, nil
}

// writeFileAtomic writes data to a temp file in the destination directory and renames it into place.
func writeFileAtomic(dst string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	ok = true
	return nil
}

// Certificate returns the parsed CA certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// CertPEM returns the PEM-encoded CA certificate.
func (c *CA) CertPEM() []byte { return bytes.Clone(c.certPEM) }

// CertPath returns the path of the CA certificate file.
func (c *CA) CertPath() string { return filepath.Join(c.dir, certFile) }

// BundlePath returns the path WriteBundle conventionally writes to (<dir>/bundle.pem).
func (c *CA) BundlePath() string { return filepath.Join(c.dir, bundleFile) }

// Fingerprint returns the SHA-256 fingerprint of the CA certificate as colon-separated uppercase hex.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Pool returns a certificate pool containing only this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// ServerTLSConfig returns a server config that mints leaves on demand from the client's SNI,
// falling back to defaultHost when the client sends none (e.g. connecting by IP).
func (c *CA) ServerTLSConfig(defaultHost string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = defaultHost
			}
			return c.LeafFor(name)
		},
	}
}
