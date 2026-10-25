package ca

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// systemBundleCandidates lists well-known system CA bundle locations, in probe order.
var systemBundleCandidates = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo/Arch
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine, macOS
	"/usr/local/etc/openssl/cert.pem",                   // Homebrew (Intel)
	"/opt/homebrew/etc/openssl@3/cert.pem",              // Homebrew (Apple Silicon)
}

// SystemBundlePath returns the first existing system CA bundle, honouring SSL_CERT_FILE unless it
// points at a nexus-cli bundle.pem (which would happen inside `nexus-cli run`). Returns "" if none.
func SystemBundlePath() string {
	exclude := ""
	if d, err := DefaultDir(); err == nil {
		exclude = filepath.Join(d, bundleFile)
	}
	return systemBundlePath(exclude)
}

func systemBundlePath(exclude string) string {
	if env := os.Getenv("SSL_CERT_FILE"); env != "" && isRegularFile(env) && !isOwnBundle(env, exclude) {
		return env
	}
	for _, p := range systemBundleCandidates {
		if isRegularFile(p) && !isOwnBundle(p, exclude) {
			return p
		}
	}
	return ""
}

func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// isOwnBundle reports whether p is exclude, or any nexus-cli bundle.pem sitting next to a ca.crt.
func isOwnBundle(p, exclude string) bool {
	if exclude != "" && sameFile(p, exclude) {
		return true
	}
	if filepath.Base(p) == bundleFile && isRegularFile(filepath.Join(filepath.Dir(p), certFile)) {
		return true
	}
	return false
}

func sameFile(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// WriteBundle writes the system CA bundle (if one is found) followed by this CA to dst, atomically
// with mode 0644. Clients pointed at it trust both real hosts and intercepted ones.
func (c *CA) WriteBundle(dst string) error {
	var buf bytes.Buffer
	if sys := systemBundlePath(c.BundlePath()); sys != "" && !sameFile(sys, dst) {
		data, err := os.ReadFile(sys)
		if err != nil {
			return fmt.Errorf("read system bundle %s: %w", sys, err)
		}
		buf.Write(c.stripOwnCert(data))
		if buf.Len() > 0 && !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
			buf.WriteByte('\n')
		}
		buf.WriteByte('\n')
	}
	buf.Write(c.certPEM)
	if dir := filepath.Dir(dst); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create bundle dir: %w", err)
		}
	}
	if err := writeFileAtomic(dst, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}
	return nil
}

// stripOwnCert removes any PEM block equal to this CA from data, so the CA appears once even if
// the system bundle already contains it (e.g. after `ca install`).
func (c *CA) stripOwnCert(data []byte) []byte {
	var out bytes.Buffer
	found := false
	rest := data
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			out.Write(rest)
			break
		}
		consumed := rest[:len(rest)-len(r)]
		if b.Type == "CERTIFICATE" && bytes.Equal(b.Bytes, c.cert.Raw) {
			found = true
		} else {
			out.Write(consumed)
		}
		rest = r
	}
	if !found {
		return data
	}
	return out.Bytes()
}
