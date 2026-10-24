package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	defaultMaxCache = 1024
	leafValidity    = 7 * 24 * time.Hour
	leafBackdate    = time.Hour
	// leafRenewBefore is how close to expiry a cached leaf may get before it is re-minted.
	leafRenewBefore = time.Hour
)

// leafEntry is a cache slot; done is closed once cert/err are set, so concurrent callers for
// the same host wait on a single mint instead of each minting their own.
type leafEntry struct {
	done     chan struct{}
	cert     *tls.Certificate
	err      error
	notAfter time.Time
}

// normalizeHost strips any port (including the [v6]:port form) and lowercases the host.
func normalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if strings.HasPrefix(h, "[") {
		if sh, _, err := net.SplitHostPort(h); err == nil {
			h = sh
		} else {
			h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
		}
	} else if strings.Count(h, ":") == 1 {
		if sh, _, err := net.SplitHostPort(h); err == nil {
			h = sh
		}
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if i := strings.IndexByte(h, '%'); i >= 0 && net.ParseIP(h[:i]) != nil {
		h = h[:i] // drop IPv6 zone
	}
	if h == "" {
		return "", errors.New("ca: empty host")
	}
	return h, nil
}

// LeafFor returns a certificate for host (which may include a port) signed by this CA.
// Certificates are cached per host and re-minted when close to expiry.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	h, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	for {
		c.mu.Lock()
		e, ok := c.cache[h]
		if ok {
			select {
			case <-e.done:
				if e.err == nil && c.now().Before(e.notAfter.Add(-leafRenewBefore)) {
					c.mu.Unlock()
					return e.cert, nil
				}
				// Stale or failed: fall through and replace it.
			default:
				c.mu.Unlock()
				<-e.done
				if e.err != nil {
					return nil, e.err
				}
				return e.cert, nil
			}
		}
		e = &leafEntry{done: make(chan struct{})}
		c.putLocked(h, e, ok)
		c.mu.Unlock()

		e.cert, e.notAfter, e.err = c.mintLeaf(h)
		close(e.done)
		if e.err != nil {
			c.mu.Lock()
			if c.cache[h] == e {
				c.removeLocked(h)
			}
			c.mu.Unlock()
			return nil, e.err
		}
		return e.cert, nil
	}
}

func (c *CA) putLocked(h string, e *leafEntry, replacing bool) {
	if replacing {
		c.removeLocked(h)
	}
	c.cache[h] = e
	c.order = append(c.order, h)
	for len(c.cache) > c.maxCache && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.cache, oldest)
	}
}

func (c *CA) removeLocked(h string) {
	delete(c.cache, h)
	for i, k := range c.order {
		if k == h {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

func (c *CA) leafPrivateKey() (*ecdsa.PrivateKey, error) {
	c.leafKeyOnce.Do(func() {
		c.leafKey, c.leafKeyErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})
	return c.leafKey, c.leafKeyErr
}

func (c *CA) mintLeaf(host string) (*tls.Certificate, time.Time, error) {
	key, err := c.leafPrivateKey()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, err
	}
	now := c.now()
	notAfter := now.Add(leafValidity)
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"nexus-cli"}},
		NotBefore:             now.Add(-leafBackdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("sign leaf for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, notAfter, nil
}
