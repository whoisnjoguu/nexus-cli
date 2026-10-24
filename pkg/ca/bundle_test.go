package ca

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func countCert(data []byte, raw []byte) (n, total int) {
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return
		}
		total++
		if bytes.Equal(b.Bytes, raw) {
			n++
		}
	}
}

func TestWriteBundle(t *testing.T) {
	c := newTestCA(t)
	other := newTestCA(t)
	sys := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(sys, other.CertPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", sys)
	if got := systemBundlePath(c.BundlePath()); got != sys {
		t.Fatalf("systemBundlePath = %q, want %q", got, sys)
	}

	for _, dst := range []string{c.BundlePath(), filepath.Join(t.TempDir(), "sub", "out.pem")} {
		for i := 0; i < 3; i++ {
			if err := c.WriteBundle(dst); err != nil {
				t.Fatal(err)
			}
		}
		data, err := os.ReadFile(dst)
		if err != nil {
			t.Fatal(err)
		}
		if n, total := countCert(data, c.cert.Raw); n != 1 || total != 2 {
			t.Fatalf("%s: own CA x%d, total %d", dst, n, total)
		}
		if n, _ := countCert(data, other.cert.Raw); n != 1 {
			t.Fatalf("system cert missing from bundle")
		}
		if !bytes.HasSuffix(data, c.CertPEM()) {
			t.Fatal("CA should be appended last")
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o644 {
				t.Fatalf("bundle perm %#o", fi.Mode().Perm())
			}
		}
	}
}

func TestWriteBundleIgnoresOwnBundleInEnv(t *testing.T) {
	c := newTestCA(t)
	if err := c.WriteBundle(c.BundlePath()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", c.BundlePath())
	if got := systemBundlePath(c.BundlePath()); got == c.BundlePath() {
		t.Fatal("must ignore own bundle in SSL_CERT_FILE")
	}
	for i := 0; i < 3; i++ {
		if err := c.WriteBundle(c.BundlePath()); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := os.ReadFile(c.BundlePath())
	if n, _ := countCert(data, c.cert.Raw); n != 1 {
		t.Fatalf("own CA appears %d times", n)
	}
	// The exported variant also refuses any nexus bundle.pem sitting next to a ca.crt.
	if got := SystemBundlePath(); got == c.BundlePath() {
		t.Fatal("SystemBundlePath returned own bundle")
	}
}

func TestWriteBundleStripsOwnCertFromSystem(t *testing.T) {
	c := newTestCA(t)
	sys := filepath.Join(t.TempDir(), "system.pem")
	os.WriteFile(sys, append(append([]byte("# header\n"), c.CertPEM()...), newTestCA(t).CertPEM()...), 0o644)
	t.Setenv("SSL_CERT_FILE", sys)
	dst := filepath.Join(t.TempDir(), "b.pem")
	if err := c.WriteBundle(dst); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(dst)
	if n, total := countCert(data, c.cert.Raw); n != 1 || total != 2 {
		t.Fatalf("own=%d total=%d", n, total)
	}
}

func TestSystemBundleCandidates(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.pem"), filepath.Join(dir, "b.pem")
	os.WriteFile(b, []byte("x"), 0o644)
	old := systemBundleCandidates
	t.Cleanup(func() { systemBundleCandidates = old })
	systemBundleCandidates = []string{a, b}

	t.Setenv("SSL_CERT_FILE", "")
	if got := systemBundlePath(""); got != b {
		t.Fatalf("got %q want %q", got, b)
	}
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "missing.pem"))
	if got := systemBundlePath(""); got != b {
		t.Fatalf("missing SSL_CERT_FILE should be skipped, got %q", got)
	}
	systemBundleCandidates = []string{a}
	t.Setenv("SSL_CERT_FILE", "")
	if got := systemBundlePath(""); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
	c := newTestCA(t)
	if err := c.WriteBundle(c.BundlePath()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(c.BundlePath())
	if !bytes.Equal(data, c.CertPEM()) {
		t.Fatal("with no system bundle, bundle should be just the CA")
	}
}
