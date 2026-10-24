package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestCA(t *testing.T) *CA {
	t.Helper()
	c, err := LoadOrCreate(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return c
}

func TestDefaultDir(t *testing.T) {
	t.Setenv("NEXUS_HOME", "/x/nexus")
	d, err := DefaultDir()
	if err != nil || d != filepath.Join("/x/nexus", "ca") {
		t.Fatalf("DefaultDir with NEXUS_HOME = %q, %v", d, err)
	}
	t.Setenv("NEXUS_HOME", "")
	t.Setenv("HOME", "/home/someone")
	d, err = DefaultDir()
	if err != nil || d != filepath.Join("/home/someone", ".nexus", "ca") {
		t.Fatalf("DefaultDir default = %q, %v", d, err)
	}
}

func TestCreateLoadRoundtrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	c1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	cert := c1.Certificate()
	checks := []struct {
		name string
		ok   bool
	}{
		{"IsCA", cert.IsCA},
		{"BasicConstraintsValid", cert.BasicConstraintsValid},
		{"MaxPathLen 0", cert.MaxPathLen == 0 && cert.MaxPathLenZero},
		{"KeyUsage", cert.KeyUsage == x509.KeyUsageCertSign|x509.KeyUsageCRLSign},
		{"CN", cert.Subject.CommonName == "nexus-cli local CA"},
		{"O", reflect.DeepEqual(cert.Subject.Organization, []string{"nexus-cli"})},
		{"OU", len(cert.Subject.OrganizationalUnit) == 1 && strings.Contains(cert.Subject.OrganizationalUnit[0], "@")},
		{"P-256", func() bool { k, ok := cert.PublicKey.(*ecdsa.PublicKey); return ok && k.Curve == elliptic.P256() }()},
		{"~10y validity", cert.NotAfter.Sub(time.Now()) > 9*365*24*time.Hour},
		{"serial >0", cert.SerialNumber.Sign() > 0 && cert.SerialNumber.BitLen() <= 128},
		{"self-signed", cert.CheckSignatureFrom(cert) == nil},
	}
	for _, ch := range checks {
		if !ch.ok {
			t.Errorf("CA property %s failed", ch.name)
		}
	}

	c2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	c3, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c1.Fingerprint() != c2.Fingerprint() || c1.Fingerprint() != c3.Fingerprint() {
		t.Fatal("fingerprint changed across load")
	}
	fp := c1.Fingerprint()
	if len(fp) != 32*3-1 || strings.ToUpper(fp) != fp || strings.Count(fp, ":") != 31 {
		t.Fatalf("bad fingerprint format %q", fp)
	}
	if c1.CertPath() != filepath.Join(dir, "ca.crt") || c1.BundlePath() != filepath.Join(dir, "bundle.pem") {
		t.Fatal("unexpected paths")
	}
	if b, _ := pem.Decode(c1.CertPEM()); b == nil || !bytes.Equal(b.Bytes, cert.Raw) {
		t.Fatal("CertPEM mismatch")
	}
	keyData, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
	if b, _ := pem.Decode(keyData); b == nil || b.Type != "PRIVATE KEY" {
		t.Fatal("key not PKCS8 PEM")
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want ErrNotExist, got %v", err)
	}
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := filepath.Join(t.TempDir(), "ca")
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want os.FileMode
	}{
		{dir, 0o700},
		{filepath.Join(dir, "ca.key"), 0o600},
		{filepath.Join(dir, "ca.crt"), 0o644},
	} {
		fi, err := os.Stat(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != tc.want {
			t.Errorf("%s perm = %#o, want %#o", tc.path, fi.Mode().Perm(), tc.want)
		}
	}
}

func TestInsecureKeyPermsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o666} {
		t.Run(fmt.Sprintf("%#o", mode), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "ca")
			if _, err := LoadOrCreate(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(dir, "ca.key"), mode); err != nil {
				t.Fatal(err)
			}
			for _, fn := range []func(string) (*CA, error){Load, LoadOrCreate} {
				_, err := fn(dir)
				if err == nil || !strings.Contains(err.Error(), "chmod 600") {
					t.Fatalf("want chmod 600 error, got %v", err)
				}
			}
		})
	}
}

func TestCorruptAndMismatched(t *testing.T) {
	otherKey := func() []byte {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	cases := []struct {
		name    string
		mutate  func(dir string)
		wantSub string
	}{
		{"corrupt cert", func(d string) { os.WriteFile(filepath.Join(d, "ca.crt"), []byte("garbage"), 0o644) }, "corrupt"},
		{"bad cert DER", func(d string) {
			os.WriteFile(filepath.Join(d, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("xx")}), 0o644)
		}, "corrupt"},
		{"corrupt key", func(d string) { os.WriteFile(filepath.Join(d, "ca.key"), []byte("garbage"), 0o600) }, "corrupt"},
		{"mismatched key", func(d string) { os.WriteFile(filepath.Join(d, "ca.key"), otherKey(), 0o600) }, "does not match"},
		{"missing key", func(d string) { os.Remove(filepath.Join(d, "ca.key")) }, "incomplete"},
		{"missing cert", func(d string) { os.Remove(filepath.Join(d, "ca.crt")) }, "incomplete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "ca")
			if _, err := LoadOrCreate(dir); err != nil {
				t.Fatal(err)
			}
			tc.mutate(dir)
			for _, fn := range []func(string) (*CA, error){Load, LoadOrCreate} {
				_, err := fn(dir)
				if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
				}
			}
		})
	}
}

func TestLeafVerifies(t *testing.T) {
	c := newTestCA(t)
	cases := []struct {
		in, verifyName string
		wantIP         bool
	}{
		{"example.com", "example.com", false},
		{"API.Example.COM", "api.example.com", false},
		{"example.com:443", "example.com", false},
		{"127.0.0.1", "127.0.0.1", true},
		{"10.1.2.3:8443", "10.1.2.3", true},
		{"::1", "::1", true},
		{"[::1]:443", "::1", true},
		{"[2001:db8::1]", "2001:db8::1", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			lc, err := c.LeafFor(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			leaf := lc.Leaf
			if tc.wantIP != (len(leaf.IPAddresses) == 1 && len(leaf.DNSNames) == 0) {
				t.Fatalf("SANs: ips=%v dns=%v", leaf.IPAddresses, leaf.DNSNames)
			}
			if !reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
				t.Fatal("missing ServerAuth EKU")
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: tc.verifyName, Roots: c.Pool()}); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if leaf.NotAfter.After(time.Now().Add(7*24*time.Hour+time.Minute)) || leaf.NotBefore.After(time.Now().Add(-59*time.Minute)) {
				t.Fatalf("validity window %v..%v", leaf.NotBefore, leaf.NotAfter)
			}
		})
	}
	if _, err := c.LeafFor(""); err == nil {
		t.Fatal("empty host should error")
	}
}

func TestLeafKeyReused(t *testing.T) {
	c := newTestCA(t)
	a, _ := c.LeafFor("a.test")
	b, _ := c.LeafFor("b.test")
	if a.PrivateKey != b.PrivateKey {
		t.Fatal("leaf key should be reused per CA")
	}
}

func TestLeafCacheHit(t *testing.T) {
	c := newTestCA(t)
	a, err := c.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"example.com", "EXAMPLE.com:443", "example.com."} {
		b, err := c.LeafFor(h)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Fatalf("%s: expected cached cert", h)
		}
	}
}

func TestLeafRegeneratedNearExpiry(t *testing.T) {
	c := newTestCA(t)
	var mu sync.Mutex
	now := time.Now()
	c.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	a, _ := c.LeafFor("example.com")
	advance(6 * 24 * time.Hour)
	if b, _ := c.LeafFor("example.com"); b != a {
		t.Fatal("should still be cached with >1h left")
	}
	advance(23*time.Hour + 30*time.Minute) // 30m left
	b, _ := c.LeafFor("example.com")
	if b == a {
		t.Fatal("should regenerate within 1h of expiry")
	}
	if !b.Leaf.NotAfter.After(a.Leaf.NotAfter) {
		t.Fatal("new leaf should expire later")
	}
}

func TestLeafNotAfterCappedByCA(t *testing.T) {
	c := newTestCA(t)
	c.now = func() time.Time { return c.cert.NotAfter.Add(-48 * time.Hour) }
	lc, err := c.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !lc.Leaf.NotAfter.Equal(c.cert.NotAfter) {
		t.Fatalf("leaf NotAfter %v, want CA NotAfter %v", lc.Leaf.NotAfter, c.cert.NotAfter)
	}
}

func TestLeafConcurrent(t *testing.T) {
	c := newTestCA(t)
	const n = 64
	certs := make([]*tls.Certificate, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lc, err := c.LeafFor("same.example")
			if err != nil {
				t.Error(err)
			}
			certs[i] = lc
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if certs[i] != certs[0] {
			t.Fatal("concurrent first requests minted multiple certs")
		}
	}

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := fmt.Sprintf("h%d.example:443", i%16)
			lc, err := c.LeafFor(h)
			if err != nil {
				t.Error(err)
				return
			}
			if lc.Leaf.DNSNames[0] != fmt.Sprintf("h%d.example", i%16) {
				t.Errorf("wrong cert for %s", h)
			}
		}(i)
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) != 17 || len(c.order) != 17 {
		t.Fatalf("cache size %d/%d, want 17", len(c.cache), len(c.order))
	}
}

func TestLeafCacheBounded(t *testing.T) {
	c := newTestCA(t)
	c.maxCache = 4
	first, _ := c.LeafFor("h0.test")
	for i := 1; i < 10; i++ {
		if _, err := c.LeafFor(fmt.Sprintf("h%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	size, order := len(c.cache), append([]string(nil), c.order...)
	c.mu.Unlock()
	if size != 4 || !reflect.DeepEqual(order, []string{"h6.test", "h7.test", "h8.test", "h9.test"}) {
		t.Fatalf("size=%d order=%v", size, order)
	}
	again, _ := c.LeafFor("h0.test")
	if again == first {
		t.Fatal("evicted entry should be re-minted")
	}
	if defaultMaxCache != 1024 {
		t.Fatal("default cache bound should be 1024")
	}
}

func TestTLSHandshake(t *testing.T) {
	c := newTestCA(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", c.ServerTLSConfig("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
				_, _ = conn.Write([]byte("ok"))
			}()
		}
	}()
	addr := ln.Addr().String()

	cases := []struct {
		name       string
		serverName string
		roots      *x509.CertPool
		wantOK     bool
	}{
		{"SNI with CA pool", "intercepted.example", c.Pool(), true},
		{"no SNI falls back to default host", "", c.Pool(), true},
		{"empty roots", "intercepted.example", x509.NewCertPool(), false},
		{"system roots", "intercepted.example", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tls.Config{RootCAs: tc.roots, ServerName: tc.serverName}
			if tc.serverName == "" {
				cfg.ServerName = "127.0.0.1" // IP: Go sends no SNI, verifies against IP SAN
			}
			conn, err := tls.Dial("tcp", addr, cfg)
			if tc.wantOK != (err == nil) {
				t.Fatalf("dial err = %v, wantOK %v", err, tc.wantOK)
			}
			if err != nil {
				return
			}
			defer conn.Close()
			st := conn.ConnectionState()
			if st.NegotiatedProtocol != "" && st.NegotiatedProtocol != "http/1.1" {
				t.Fatalf("ALPN %q", st.NegotiatedProtocol)
			}
			b, _ := io.ReadAll(conn)
			if string(b) != "ok" {
				t.Fatalf("read %q", b)
			}
		})
	}
	cfg := c.ServerTLSConfig("x")
	if cfg.MinVersion != tls.VersionTLS12 || !reflect.DeepEqual(cfg.NextProtos, []string{"http/1.1"}) {
		t.Fatal("server config defaults wrong")
	}
}
