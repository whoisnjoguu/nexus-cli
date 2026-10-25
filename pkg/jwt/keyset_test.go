package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/zalando/go-keyring"
)

func TestThumbprintRFC7638Vector(t *testing.T) {
	// RFC 8037 Appendix A.2/A.3 Ed25519 public key and its RFC 7638 thumbprint.
	x, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	if got := Thumbprint(ed25519.PublicKey(x)); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint = %s", got)
	}
}

func TestKidDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	a, b := signerFromSeed(seed), signerFromSeed(seed)
	if a.Kid() == "" || a.Kid() != b.Kid() || a.Kid() != Thumbprint(a.PublicKey()) {
		t.Fatalf("kid not deterministic: %s vs %s", a.Kid(), b.Kid())
	}
	other, _ := NewTokenSigner()
	if other.Kid() == a.Kid() {
		t.Fatal("different keys must have different kids")
	}
}

func headerOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestMintSetsKid(t *testing.T) {
	s, _ := NewTokenSigner()
	tok, err := s.Mint(MintOptions{AgentID: "a", UserID: "u", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	h := headerOf(t, tok)
	if h["kid"] != s.Kid() || h["alg"] != "EdDSA" {
		t.Fatalf("header = %v", h)
	}
}

// mintRaw signs claims with priv and an optional kid header, bypassing TokenSigner.
func mintRaw(t *testing.T, priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	now := time.Now()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, DualActorClaims{
		AgentID: "a", ActAs: "u",
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer: "nexus-cli-local", Audience: gojwt.ClaimStrings{"nexus-gateway"},
			IssuedAt: gojwt.NewNumericDate(now), ExpiresAt: gojwt.NewNumericDate(now.Add(time.Minute)),
		},
	})
	if kid != "" {
		tok.Header["kid"] = kid
	}
	out, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifierKidSelection(t *testing.T) {
	a, _ := NewTokenSigner()
	b, _ := NewTokenSigner()
	v := a.Verifier()

	if _, err := v.Verify(mintRaw(t, a.privKey, "")); err != nil {
		t.Fatalf("kid-less token from current key must verify: %v", err)
	}
	tokB, _ := b.MintDualActorToken("a", "u", nil, time.Minute)
	if _, err := v.Verify(tokB); err == nil || !strings.Contains(err.Error(), "unknown signing key id") {
		t.Fatalf("want unknown kid error, got %v", err)
	}
	// Forged: signed by b but claiming a's kid.
	if _, err := v.Verify(mintRaw(t, b.privKey, a.Kid())); err == nil {
		t.Fatal("token signed by another key must not verify under a's kid")
	}
	// kid-less from b must not verify (current key only).
	if _, err := v.Verify(mintRaw(t, b.privKey, "")); err == nil {
		t.Fatal("kid-less token from another key must fail")
	}
	if _, err := NewVerifier(a.PublicKey()).Verify(mintRaw(t, a.privKey, a.Kid())); err != nil {
		t.Fatalf("NewVerifier must accept its own kid: %v", err)
	}
}

func TestKeySetVerifier(t *testing.T) {
	a, _ := NewTokenSigner()
	b, _ := NewTokenSigner()
	v := NewKeySetVerifier(map[string]ed25519.PublicKey{a.Kid(): a.PublicKey(), b.Kid(): b.PublicKey()})
	for _, s := range []*TokenSigner{a, b} {
		tok, _ := s.MintDualActorToken("a", "u", nil, time.Minute)
		if _, err := v.Verify(tok); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.Verify(mintRaw(t, a.privKey, "")); err == nil {
		t.Fatal("multi-key verifier has no default key; kid-less token must fail")
	}
	c, _ := NewTokenSigner()
	tokC, _ := c.MintDualActorToken("a", "u", nil, time.Minute)
	if _, err := v.Verify(tokC); err == nil {
		t.Fatal("unknown kid must fail")
	}
	if got := len(v.JWKS().Keys); got != 2 {
		t.Fatalf("JWKS keys = %d", got)
	}
	single := NewKeySetVerifier(map[string]ed25519.PublicKey{a.Kid(): a.PublicKey()})
	if _, err := single.Verify(mintRaw(t, a.privKey, "")); err != nil {
		t.Fatalf("single-key set should accept kid-less token: %v", err)
	}
}

func TestJWKSFields(t *testing.T) {
	s, _ := NewTokenSigner()
	set := s.JWKS()
	if len(set.Keys) != 1 {
		t.Fatal(len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kid != s.Kid() || k.Use != "sig" || k.Alg != "EdDSA" || k.Kty != "OKP" || k.Crv != "Ed25519" {
		t.Fatalf("jwk = %+v", k)
	}
	if v := s.Verifier().JWKS(); len(v.Keys) != 1 || v.Keys[0].Kid != s.Kid() {
		t.Fatalf("verifier jwks = %+v", v)
	}
}

func TestRotateKeepsOldTokensValid(t *testing.T) {
	for _, backend := range []Backend{BackendFile, BackendKeychain} {
		t.Run(string(backend), func(t *testing.T) {
			freshKeychain(t)
			path := keyPath(t)
			old, _, err := LoadOrCreateSignerWith(path, backend)
			if err != nil {
				t.Fatal(err)
			}
			oldTok, _ := old.MintDualActorToken("a", "u", nil, time.Hour)

			res, err := Rotate(path, backend)
			if err != nil {
				t.Fatal(err)
			}
			if res.OldKid != old.Kid() || res.NewKid == old.Kid() || res.Backend != string(backend) {
				t.Fatalf("res = %+v", res)
			}
			cur, used, err := LoadOrCreateSignerWith(path, backend)
			if err != nil {
				t.Fatal(err)
			}
			if used != string(backend) || cur.Kid() != res.NewKid {
				t.Fatalf("reload used=%s kid=%s", used, cur.Kid())
			}
			if backend == BackendKeychain {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("rotation must stay in the keychain")
				}
			}
			if _, err := cur.Verifier().Verify(oldTok); err != nil {
				t.Fatalf("old token must still verify after rotation: %v", err)
			}
			newTok, _ := cur.MintDualActorToken("a", "u", nil, time.Hour)
			if headerOf(t, newTok)["kid"] != res.NewKid {
				t.Fatal("new tokens must carry the new kid")
			}
			if _, err := old.Verifier().Verify(newTok); err == nil {
				t.Fatal("old verifier must not know the new key")
			}
			// kid-less tokens are checked against the current key only.
			if _, err := cur.Verifier().Verify(mintRaw(t, old.privKey, "")); err == nil {
				t.Fatal("kid-less token from a retired key must fail")
			}
			set := cur.JWKS()
			if len(set.Keys) != 2 || set.Keys[0].Kid != res.NewKid || set.Keys[1].Kid != res.OldKid {
				t.Fatalf("jwks = %+v", set)
			}
			if r := cur.RetiredKeys(); len(r) != 1 || r[0].Kid != old.Kid() || r[0].RetiredAt.IsZero() {
				t.Fatalf("retired = %+v", r)
			}
			data, _ := os.ReadFile(RetiredPath(path))
			if strings.Contains(string(data), base64.StdEncoding.EncodeToString(old.privKey.Seed())) {
				t.Fatal("retired list must hold public keys only")
			}

			// A second rotation retires the second key too.
			res2, err := Rotate(path, backend)
			if err != nil {
				t.Fatal(err)
			}
			cur2, _, _ := LoadOrCreateSignerWith(path, backend)
			if len(cur2.RetiredKeys()) != 2 || cur2.Kid() != res2.NewKid {
				t.Fatalf("retired after 2 rotations = %d", len(cur2.RetiredKeys()))
			}
			for _, tok := range []string{oldTok, newTok} {
				if _, err := cur2.Verifier().Verify(tok); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRotateWithoutKeyFails(t *testing.T) {
	freshKeychain(t)
	if _, err := Rotate(keyPath(t), BackendFile); err == nil || !strings.Contains(err.Error(), "no signing key") {
		t.Fatalf("got %v", err)
	}
}

func TestPruneRetired(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	first, _, _ := LoadOrCreateSignerWith(path, BackendFile)
	firstTok, _ := first.MintDualActorToken("a", "u", nil, time.Hour)
	if _, err := Rotate(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	cur, _, _ := LoadOrCreateSignerWith(path, BackendFile)

	if n, err := cur.PruneRetired(time.Hour); err != nil || n != 0 {
		t.Fatalf("recent key must be kept: n=%d err=%v", n, err)
	}
	n, err := cur.pruneRetiredAt(24*time.Hour, time.Now().Add(48*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if _, err := cur.Verifier().Verify(firstTok); err == nil || !strings.Contains(err.Error(), "unknown signing key id") {
		t.Fatalf("token from pruned key must be rejected, got %v", err)
	}
	reloaded, _, err := LoadOrCreateSignerWith(path, BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.RetiredKeys()) != 0 || len(reloaded.JWKS().Keys) != 1 {
		t.Fatal("prune must persist")
	}
	if _, err := reloaded.Verifier().Verify(firstTok); err == nil {
		t.Fatal("pruned key must stay rejected after reload")
	}
	eph, _ := NewTokenSigner()
	if _, err := eph.PruneRetired(0); err == nil {
		t.Fatal("ephemeral signer has nothing to persist to")
	}
}

func TestRetiredListTamperRejected(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	rpath := RetiredPath(path)
	orig, _ := os.ReadFile(rpath)

	// Attacker appends its own public key to the list without the signing key.
	attacker, _ := NewTokenSigner()
	var f retiredFile
	_ = json.Unmarshal(orig, &f)
	var keys []RetiredKey
	_ = json.Unmarshal(f.Keys, &keys)
	keys = append(keys, RetiredKey{Kid: attacker.Kid(), X: base64.RawURLEncoding.EncodeToString(attacker.PublicKey()), RetiredAt: time.Now()})
	f.Keys, _ = json.Marshal(keys)
	tampered, _ := json.Marshal(f)
	_ = os.WriteFile(rpath, tampered, 0o600)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err == nil || !strings.Contains(err.Error(), "not signed by the current signing key") {
		t.Fatalf("want tamper error, got %v", err)
	}

	// Attacker re-signs the list with its own key.
	if err := saveRetired(rpath, keys, attacker.privKey); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err == nil {
		t.Fatal("list signed by a foreign key must be rejected")
	}

	// Restoring the genuine (re-indented) file works.
	_ = os.WriteFile(rpath, orig, 0o600)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatalf("genuine list must load: %v", err)
	}
}

func TestRetiredPath(t *testing.T) {
	for in, want := range map[string]string{
		"/x/ed25519.key": "/x/ed25519.retired.json",
		"/x/alt.pem":     "/x/alt.retired.json",
		"/x/noext":       "/x/noext.retired.json",
	} {
		if got := RetiredPath(in); got != strings.ReplaceAll(want, "/", string(os.PathSeparator)) && got != want {
			t.Fatalf("RetiredPath(%s) = %s", in, got)
		}
	}
}

func TestMigrateRoundTrip(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	orig, _, err := LoadOrCreateSignerWith(path, BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	cur, _, _ := LoadOrCreateSignerWith(path, BackendFile)
	tok, _ := orig.MintDualActorToken("a", "u", nil, time.Hour)

	res, err := Migrate(path, BackendKeychain)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "file" || res.To != "keychain" || res.Kid != cur.Kid() {
		t.Fatalf("res = %+v", res)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("key file must be removed after migrating to keychain")
	}
	s, used, err := LoadOrCreateSignerWith(path, BackendAuto)
	if err != nil || used != "keychain" || s.Kid() != cur.Kid() {
		t.Fatalf("auto after migrate: used=%s err=%v", used, err)
	}
	if _, err := s.Verifier().Verify(tok); err != nil {
		t.Fatalf("retired list must survive migration: %v", err)
	}
	if _, err := Migrate(path, BackendKeychain); err == nil || !strings.Contains(err.Error(), "already in the keychain") {
		t.Fatalf("second migrate: %v", err)
	}

	res, err = Migrate(path, BackendFile)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "keychain" || res.To != "file" || res.Kid != cur.Kid() {
		t.Fatalf("res = %+v", res)
	}
	if _, err := keyring.Get(KeychainService, mustAccount(t, path)); err != keyring.ErrNotFound {
		t.Fatalf("keychain entry must be deleted: %v", err)
	}
	s, used, err = LoadOrCreateSignerWith(path, BackendAuto)
	if err != nil || used != "file" || s.Kid() != cur.Kid() {
		t.Fatalf("auto after migrate back: used=%s err=%v", used, err)
	}
}

func TestMigrateRefusals(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	if _, err := Migrate(path, BackendKeychain); err == nil || !strings.Contains(err.Error(), "nothing to migrate") {
		t.Fatalf("got %v", err)
	}
	if _, err := Migrate(path, BackendAuto); err == nil {
		t.Fatal("auto is not a migration target")
	}
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateSignerWith(path+".other", BackendKeychain); err != nil {
		t.Fatal(err)
	}
	// Put a different key in the keychain slot for path.
	kc, _ := NewKeychainKeyStore(path)
	other := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(other)
	_ = kc.Save(other)
	if _, err := Migrate(path, BackendKeychain); err == nil || !strings.Contains(err.Error(), "different signing key") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("source must be left intact on refusal")
	}
}

func TestMigrateKeychainUnavailableLeavesFile(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	keyring.MockInitWithError(os.ErrPermission)
	if _, err := Migrate(path, BackendKeychain); err == nil {
		t.Fatal("want error")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("file must survive a failed migration")
	}
}

// lyingKeyring reports "not found" once, accepts Set, then returns a different seed.
type lyingKeyring struct{ gets *int }

func (l lyingKeyring) Get(string, string) (string, error) {
	*l.gets++
	if *l.gets == 1 {
		return "", keyring.ErrNotFound
	}
	return base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)), nil
}
func (lyingKeyring) Set(string, string, string) error { return nil }
func (lyingKeyring) Delete(string, string) error      { return nil }

func TestMigrateVerifiesRoundTrip(t *testing.T) {
	freshKeychain(t)
	path := keyPath(t)
	if _, _, err := LoadOrCreateSignerWith(path, BackendFile); err != nil {
		t.Fatal(err)
	}
	keychainProvider = lyingKeyring{gets: new(int)}
	if _, err := Migrate(path, BackendKeychain); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatal("mismatching destination must fail")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("file must survive a failed verification")
	}
}
