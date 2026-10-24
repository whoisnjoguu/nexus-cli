package audit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fuzzKey is a fixed audit signing key so saved corpus entries stay meaningful across runs.
var fuzzKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))

// buildChain writes a small signed chain and returns its bytes.
func buildChain(tb testing.TB, dir string) []byte {
	tb.Helper()
	path := filepath.Join(dir, "chain.jsonl")
	l, err := OpenWithOptions(path, Options{SigningKey: fuzzKey, MaxBytes: -1})
	if err != nil {
		tb.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 9, 0, 0, 123456789, time.UTC)
	for i, e := range []Entry{
		{JTI: "jti-1", Agent: "agent-x", ActAs: "alice@example.com", Tool: "GET", Target: "api.github.com/repos", Scopes: []string{"repo:read"}, Decision: "allow", Reason: "matched rule"},
		{Agent: "agent-x", ActAs: "alice", Tool: "POST", Target: "evil.com/?a=1&b=<2>", Decision: "deny", Reason: `no rule "quoted"`, Source: "policy"},
		{Agent: "mcp", Tool: "write_file", Target: "fs", Decision: "deny", Session: "s1", Rule: "tools[0]", ArgsHash: HashArgs([]byte(`{"path":"x"}`)), Source: "guard"},
		{Agent: "ünïcode", ActAs: "\u2028", Tool: "CONNECT", Target: "x:443", Decision: "allow"},
	} {
		e.Time = base.Add(time.Duration(i) * time.Second)
		if err := l.Log(e); err != nil {
			tb.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		tb.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func parseLines(b []byte) ([]Entry, bool) {
	var out []Entry
	for _, line := range bytes.Split(b, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		var e Entry
		if json.Unmarshal(line, &e) != nil {
			return nil, false
		}
		out = append(out, e)
	}
	return out, true
}

// FuzzVerifyTamper flips bytes in a valid signed chain. Verification must fail unless the edit
// left every entry semantically identical (e.g. a JSON key's letter case, which encoding/json
// ignores, or base64 padding bits): what an entry says can never change undetected.
func FuzzVerifyTamper(f *testing.F) {
	dir := f.TempDir()
	orig := buildChain(f, dir)
	origEntries, ok := parseLines(orig)
	if !ok {
		f.Fatal("chain does not parse")
	}
	path := filepath.Join(dir, "tampered.jsonl")
	opts := VerifyOptions{PublicKeys: []ed25519.PublicKey{fuzzKey.Public().(ed25519.PublicKey)}}

	if err := os.WriteFile(path, orig, 0o600); err != nil {
		f.Fatal(err)
	}
	if _, err := VerifyWithOptions(path, opts); err != nil {
		f.Fatalf("untampered chain fails: %v", err)
	}

	for _, s := range []struct {
		pos  uint
		xor  byte
		pos2 uint
	}{{0, 1, 0}, {10, 0x20, 0}, {100, 1, 200}, {300, 0x01, 301}, {uint(len(orig) - 1), 0x03, 0}, {uint(len(orig) / 2), 0xff, 0}} {
		f.Add(s.pos, s.xor, s.pos2)
	}
	f.Fuzz(func(t *testing.T, pos uint, xor byte, pos2 uint) {
		if xor == 0 {
			return
		}
		b := bytes.Clone(orig)
		b[pos%uint(len(b))] ^= xor
		if pos2 != 0 {
			b[pos2%uint(len(b))] ^= xor
		}
		if bytes.Equal(b, orig) {
			return
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyWithOptions(path, opts); err != nil {
			return
		}
		got, ok := parseLines(b)
		if !ok || len(got) != len(origEntries) {
			t.Fatalf("tampered chain verified with %d entries (want %d)", len(got), len(origEntries))
		}
		for i := range got {
			if hashEntry(got[i]) != hashEntry(origEntries[i]) {
				t.Fatalf("entry %d changed undetected:\n%+v\n%+v", i, origEntries[i], got[i])
			}
			s1, _ := base64.StdEncoding.DecodeString(origEntries[i].Sig)
			s2, _ := base64.StdEncoding.DecodeString(got[i].Sig)
			if bytes.Equal(s1, s2) {
				continue
			}
			// A stripped signature (e.g. a mangled "sig" key) leaves the entry's content
			// authenticated by the hash chain; only RequireSigned can and must notice it.
			if got[i].Sig != "" {
				t.Fatalf("entry %d signature changed undetected", i)
			}
			if _, err := VerifyWithOptions(path, VerifyOptions{PublicKeys: opts.PublicKeys, RequireSigned: true}); err == nil {
				t.Fatalf("entry %d signature stripped but RequireSigned verification passed", i)
			}
		}
	})
}

// FuzzVerifyArbitrary feeds arbitrary bytes to the readers and verifier: no panics, and an
// accepted file is consistent with what ReadAll and the exporters see.
func FuzzVerifyArbitrary(f *testing.F) {
	dir := f.TempDir()
	chain := buildChain(f, dir)
	f.Add(chain)
	if legacy, err := os.ReadFile(filepath.Join("testdata", "legacy.jsonl")); err == nil {
		f.Add(legacy)
	}
	f.Add([]byte("{}\n"))
	f.Add([]byte(`{"seq":1,"ts":"bad","prev_hash":"","hash":""}`))
	f.Add([]byte("\n\n\r\n"))
	f.Add([]byte(`{"sig":"!!!","key_id":"x","prev_hash":"","hash":"x"}` + "\n"))
	f.Add([]byte(`{"seq":18446744073709551615,"prev_hash":"","hash":""}`))
	f.Add([]byte(`[1,2,3]`))
	path := filepath.Join(dir, "audit.jsonl")
	keys := []ed25519.PublicKey{fuzzKey.Public().(ed25519.PublicKey)}
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyWithOptions(path, VerifyOptions{})
		_, _ = VerifyWithOptions(path, VerifyOptions{PublicKeys: keys, RequireSigned: true, Anchor: "x"})
		n, verr := Verify(path)
		if (err == nil) != (verr == nil) || (err == nil && n != res.Entries) {
			t.Fatalf("Verify and VerifyWithOptions disagree: %v / %v", err, verr)
		}
		entries, rerr := ReadAll(path)
		if err == nil {
			if rerr != nil || len(entries) != res.Entries {
				t.Fatalf("verified %d entries but ReadAll gave %d (%v)", res.Entries, len(entries), rerr)
			}
			if res.Signed+res.Unsigned != res.Entries {
				t.Fatalf("signed %d + unsigned %d != %d", res.Signed, res.Unsigned, res.Entries)
			}
		}
		_ = WriteCSV(io.Discard, entries)
		_ = WriteJSONL(io.Discard, entries)
		_ = Filter{Agent: "agent-x", Decision: "deny"}.Apply(entries)
	})
}

func FuzzParseSince(f *testing.F) {
	for _, s := range []string{"1h", "2d", "3w", "2026-10-01", "2026-10-01T09:00:00Z", "", "-1d", "9999999999999d", "1.5h"} {
		f.Add(s)
	}
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseSince(s, now)
	})
}
