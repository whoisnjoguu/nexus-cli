package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < 3; i++ {
		if err := l.Log(Entry{Agent: "a", ActAs: "u", Tool: "GET", Target: "/x", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := Verify(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("verified %d entries, want 3", n)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_ = l.Log(Entry{Agent: "a", ActAs: "u", Decision: "allow"})
	_ = l.Log(Entry{Agent: "a", ActAs: "u", Decision: "deny"})
	l.Close()

	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"decision":"allow"`, `"decision":"deny"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); err == nil {
		t.Fatal("expected verify to detect tampering")
	}
}

func TestChainResumesAcrossOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l1, _ := Open(path)
	_ = l1.Log(Entry{Agent: "a", Decision: "allow"})
	l2, _ := Open(path)
	_ = l2.Log(Entry{Agent: "b", Decision: "deny"})
	_ = l1.Log(Entry{Agent: "c", Decision: "deny"}) // l1 must notice l2's write
	l1.Close()
	l2.Close()
	res, err := VerifyWithOptions(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("chain should survive reopen: %v", err)
	}
	if res.Entries != 3 || res.HeadSeq != 3 {
		t.Fatalf("got %+v", res)
	}
}

// legacy.jsonl was written by the pre-signature implementation; it must keep verifying.
func TestLegacyFixtureVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	data, err := os.ReadFile("testdata/legacy.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyWithOptions(path, VerifyOptions{})
	if err != nil {
		t.Fatalf("legacy log must verify: %v", err)
	}
	if res.Entries != 5 || res.Unsigned != 5 || res.HeadSeq != 5 {
		t.Fatalf("legacy result %+v", res)
	}
	if res.Head != "b7e9e1916e5b31c528a01959f7b9dbc2949c8a66ca0522a1ac6cbbaae1b783a8" {
		t.Fatalf("legacy head changed: %s", res.Head)
	}

	// New entries (signed, with optional fields) continue the legacy chain.
	priv := testKey(t)
	l, err := OpenWithOptions(path, Options{SigningKey: priv})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Entry{Agent: "a", Decision: "allow", Session: "s1", Rule: "allow GET *", Source: "policy", ArgsHash: HashArgs([]byte(`{"x":1}`))}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	res, err = VerifyWithOptions(path, VerifyOptions{PublicKeys: []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 6 || res.Signed != 1 || res.HeadSeq != 6 {
		t.Fatalf("after append %+v", res)
	}
	got, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(got), string(data)) {
		t.Fatal("legacy lines must be left untouched")
	}
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func writeSigned(t *testing.T, n int) (string, ed25519.PrivateKey) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	priv := testKey(t)
	l, err := OpenWithOptions(path, Options{SigningKey: priv, Fsync: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		dec := "allow"
		if i%2 == 1 {
			dec = "deny"
		}
		if err := l.Log(Entry{Agent: fmt.Sprintf("agent-%d", i%3), ActAs: "u", Tool: "GET", Target: fmt.Sprintf("/r/%d", i), Decision: dec}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return path, priv
}

func TestSignedRoundtrip(t *testing.T) {
	path, priv := writeSigned(t, 5)
	res, err := VerifyWithOptions(path, VerifyOptions{PublicKeys: []ed25519.PublicKey{pubOf(priv)}, RequireSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 5 || res.Signed != 5 || res.Unsigned != 0 || !res.SigsChecked || res.Files != 1 {
		t.Fatalf("result %+v", res)
	}
	es, _ := ReadAll(path)
	for i, e := range es {
		if e.Seq != uint64(i+1) || e.KeyID != KeyID(pubOf(priv)) || e.Sig == "" {
			t.Fatalf("entry %d: %+v", i, e)
		}
	}
	// Signatures present but no keys supplied: chain still verifies, sigs unchecked.
	res, err = VerifyWithOptions(path, VerifyOptions{})
	if err != nil || res.SigsChecked {
		t.Fatalf("unchecked verify: %+v %v", res, err)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func stripSig(t *testing.T, line string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "sig")
	b, _ := json.Marshal(m)
	return string(b)
}

func TestTamperDetection(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(t *testing.T, lines []string) []string
		opts    func(pub ed25519.PublicKey) VerifyOptions
		wantErr string
	}{
		{"edit field", func(t *testing.T, l []string) []string {
			l[2] = strings.Replace(l[2], `"target":"/r/2"`, `"target":"/r/X"`, 1)
			return l
		}, nil, "entry 3"},
		{"delete middle line", func(t *testing.T, l []string) []string {
			return append(l[:2:2], l[3:]...)
		}, nil, "broken chain"},
		{"reorder lines", func(t *testing.T, l []string) []string {
			l[1], l[2] = l[2], l[1]
			return l
		}, nil, "broken chain"},
		{"truncate mid-line", func(t *testing.T, l []string) []string {
			l[len(l)-1] = l[len(l)-1][:20]
			return l
		}, nil, "invalid json"},
		{"strip later signatures (downgrade)", func(t *testing.T, l []string) []string {
			for i := 3; i < len(l); i++ {
				l[i] = stripSig(t, l[i])
			}
			return l
		}, nil, "downgrade"},
		{"wrong pubkey", nil, func(ed25519.PublicKey) VerifyOptions {
			other := testKey(t)
			return VerifyOptions{PublicKeys: []ed25519.PublicKey{pubOf(other)}}
		}, "unknown key"},
		{"forged signature", func(t *testing.T, l []string) []string {
			var e Entry
			_ = json.Unmarshal([]byte(l[1]), &e)
			var o Entry
			_ = json.Unmarshal([]byte(l[2]), &o)
			e.Sig = o.Sig
			b, _ := json.Marshal(e)
			l[1] = string(b)
			return l
		}, nil, "signature mismatch"},
		{"require signed on unsigned log", func(t *testing.T, l []string) []string {
			for i := range l {
				l[i] = stripSig(t, l[i])
			}
			return l
		}, func(pub ed25519.PublicKey) VerifyOptions {
			return VerifyOptions{PublicKeys: []ed25519.PublicKey{pub}, RequireSigned: true}
		}, "signatures required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, priv := writeSigned(t, 6)
			if tc.mutate != nil {
				writeLines(t, path, tc.mutate(t, readLines(t, path)))
			}
			opts := VerifyOptions{PublicKeys: []ed25519.PublicKey{pubOf(priv)}}
			if tc.opts != nil {
				opts = tc.opts(pubOf(priv))
			}
			_, err := VerifyWithOptions(path, opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestAnchor(t *testing.T) {
	path, priv := writeSigned(t, 6)
	es, _ := ReadAll(path)
	anchor := es[3].Hash
	keys := []ed25519.PublicKey{pubOf(priv)}

	res, err := VerifyWithOptions(path, VerifyOptions{PublicKeys: keys, Anchor: anchor})
	if err != nil || res.AnchorSeq != 4 {
		t.Fatalf("anchor present: %+v %v", res, err)
	}
	if _, err := VerifyWithOptions(path, VerifyOptions{Anchor: strings.Repeat("0", 64)}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("absent anchor should fail: %v", err)
	}
	// Truncating whole lines keeps the chain valid but loses the anchored entry.
	lines := readLines(t, path)
	writeLines(t, path, lines[:3])
	if _, err := Verify(path); err != nil {
		t.Fatalf("truncated chain is self-consistent: %v", err)
	}
	if _, err := VerifyWithOptions(path, VerifyOptions{PublicKeys: keys, Anchor: anchor}); err == nil {
		t.Fatal("truncation past the anchor must be detected")
	}
}

func TestFilePermsAndFsync(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := filepath.Join(t.TempDir(), "nested")
	path := filepath.Join(dir, "audit.jsonl")
	l, err := OpenWithOptions(path, Options{Fsync: true, MaxBytes: 200})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ { // also exercises fsync + directory sync on rotation
		if err := l.Log(Entry{Agent: "a", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := Files(path)
	if len(files) < 2 {
		t.Fatalf("expected rotation, got %v", files)
	}
	for _, f := range append(files, path+".lock") {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s perm %v, want 0600", f, fi.Mode().Perm())
		}
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir perm %v", fi.Mode().Perm())
	}
	if err := l.Log(Entry{}); err != ErrClosed {
		t.Fatalf("log after close: %v", err)
	}
}

func TestConcurrentLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenWithOptions(path, Options{SigningKey: testKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := l.Log(Entry{Agent: fmt.Sprintf("g%d", g), Decision: "allow"}); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	l.Close()
	res, err := VerifyWithOptions(path, VerifyOptions{RequireSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 1000 || res.HeadSeq != 1000 {
		t.Fatalf("%+v", res)
	}
}

func TestTornLineRepairedOnOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_ = l.Log(Entry{Agent: "a", Decision: "allow"})
	l.Close()
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"seq":2,"ts":"20`) // simulated crash mid-write
	f.Close()
	if _, err := Verify(path); err == nil {
		t.Fatal("torn line should fail verification")
	}
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Log(Entry{Agent: "b", Decision: "deny"})
	l.Close()
	if n, err := Verify(path); err != nil || n != 2 {
		t.Fatalf("after repair: %d %v", n, err)
	}
}

func TestInvalidUTF8RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_ = l.Log(Entry{Agent: "a\xff", Target: "<&>\u2028", Decision: "allow", Scopes: []string{"x\xfe"}})
	l.Close()
	if _, err := Verify(path); err != nil {
		t.Fatal(err)
	}
}

func TestHashArgs(t *testing.T) {
	if HashArgs(nil) != "" {
		t.Fatal("empty args should hash to empty")
	}
	if got := HashArgs([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal(got)
	}
}

func TestDefaultPathsHonourNexusHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)
	p, _ := DefaultPath()
	k, _ := DefaultKeyPath()
	pub, _ := DefaultPubKeyPath()
	if p != filepath.Join(home, "audit.jsonl") || k != filepath.Join(home, "audit.key") || pub != filepath.Join(home, "audit.pub") {
		t.Fatal(p, k, pub)
	}
	t.Setenv("NEXUS_HOME", "")
	p, _ = DefaultPath()
	if !strings.HasSuffix(p, filepath.Join(".nexus", "audit.jsonl")) {
		t.Fatal(p)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	dir := t.TempDir()
	kp := filepath.Join(dir, "audit.key")
	k1, err := LoadOrCreateKey(kp)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateKey(kp)
	if err != nil || !k1.Equal(k2) {
		t.Fatal("key should persist", err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(kp); fi.Mode().Perm() != 0o600 {
			t.Fatalf("key perm %v", fi.Mode().Perm())
		}
	}
	pubs, err := LoadPublicKeys(filepath.Join(dir, "audit.pub"))
	if err != nil || len(pubs) != 1 || !pubs[0].Equal(pubOf(k1)) {
		t.Fatalf("pub: %v %v", pubs, err)
	}
	// Rotating the key appends to audit.pub so old history stays verifiable.
	os.Remove(kp)
	k3, _ := LoadOrCreateKey(kp)
	pubs, _ = LoadPublicKeys(filepath.Join(dir, "audit.pub"))
	if len(pubs) != 2 || !pubs[1].Equal(pubOf(k3)) {
		t.Fatalf("expected appended key, got %d", len(pubs))
	}
	if err := os.WriteFile(kp, []byte("not base64!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(kp); err == nil {
		t.Fatal("corrupt key should error")
	}
}

func TestEntryTimeNormalizedToUTC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	_ = l.Log(Entry{Time: time.Date(2026, 1, 1, 12, 0, 0, 0, time.FixedZone("X", 3600)), Decision: "allow"})
	l.Close()
	es, _ := ReadAll(path)
	if es[0].Time.Location() != time.UTC || es[0].Time.Hour() != 11 {
		t.Fatal(es[0].Time)
	}
}
