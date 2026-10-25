package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/zalando/go-keyring"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
)

// Every test in this package uses go-keyring's in-memory mock so command tests that resolve a
// signing key in auto mode never touch the developer's real OS keychain.
func init() { keyring.MockInit() }

func runKeys(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	// Reset package-level flag variables so values don't leak between runs.
	for _, fs := range []*pflag.FlagSet{keysCmd.PersistentFlags(), keysRotateCmd.Flags(), keysMigrateCmd.Flags(), keysPruneCmd.Flags()} {
		fs.VisitAll(func(f *pflag.Flag) {
			if err := f.Value.Set(f.DefValue); err != nil {
				t.Fatalf("reset --%s: %v", f.Name, err)
			}
			f.Changed = false
		})
	}
	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	rootCmd.SetIn(strings.NewReader(stdin))
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetIn(nil); rootCmd.SetArgs(nil) })
	rootCmd.SetArgs(append([]string{"keys"}, args...))
	err := rootCmd.Execute()
	return out.String(), err
}

func keysEnv(t *testing.T, backend string) string {
	t.Helper()
	keyring.MockInit()
	t.Cleanup(keyring.MockInit)
	home := t.TempDir()
	t.Setenv("NEXUS_HOME", home)
	t.Setenv(jwt.KeyBackendEnv, backend)
	return home
}

func showField(t *testing.T, out, field string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, field+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("no %q in output:\n%s", field, out)
	return ""
}

func jwksKids(t *testing.T, out string) []string {
	t.Helper()
	var set jwt.JWKS
	if err := json.Unmarshal([]byte(out), &set); err != nil {
		t.Fatalf("jwks output: %v\n%s", err, out)
	}
	var kids []string
	for _, k := range set.Keys {
		if k.Use != "sig" || k.Alg != "EdDSA" {
			t.Fatalf("jwk = %+v", k)
		}
		kids = append(kids, k.Kid)
	}
	return kids
}

func TestKeysShowFileBackend(t *testing.T) {
	home := keysEnv(t, "file")
	out, err := runKeys(t, "", "show")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "ed25519.key")
	if showField(t, out, "backend") != "file" || showField(t, out, "location") != path {
		t.Fatalf("out:\n%s", out)
	}
	if !strings.HasPrefix(showField(t, out, "retired"), "0 key(s)") {
		t.Fatalf("out:\n%s", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("key file should exist under NEXUS_HOME")
	}
	jw, err := runKeys(t, "", "jwks")
	if err != nil {
		t.Fatal(err)
	}
	if kids := jwksKids(t, jw); len(kids) != 1 || kids[0] != showField(t, out, "kid") {
		t.Fatalf("jwks kids = %v", kids)
	}
}

func TestKeysShowKeychainBackendAndAltKey(t *testing.T) {
	home := keysEnv(t, "auto")
	out, err := runKeys(t, "", "show")
	if err != nil {
		t.Fatal(err)
	}
	if showField(t, out, "backend") != "keychain" || !strings.Contains(showField(t, out, "location"), "nexus-cli") {
		t.Fatalf("out:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, "ed25519.key")); !os.IsNotExist(err) {
		t.Fatal("no key file expected with a working keychain")
	}
	alt, err := runKeys(t, "", "show", "--key", filepath.Join(home, "alt.key"))
	if err != nil {
		t.Fatal(err)
	}
	if showField(t, alt, "kid") == showField(t, out, "kid") {
		t.Fatal("--key must select a distinct keychain entry")
	}
}

func TestKeysRotate(t *testing.T) {
	keysEnv(t, "file")
	before, err := runKeys(t, "", "show")
	if err != nil {
		t.Fatal(err)
	}
	oldKid := showField(t, before, "kid")

	if _, err := runKeys(t, "n\n", "rotate"); err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("declined prompt must abort: %v", err)
	}
	if after, _ := runKeys(t, "", "show"); showField(t, after, "kid") != oldKid {
		t.Fatal("aborted rotation changed the key")
	}

	out, err := runKeys(t, "", "rotate", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	newKid := showField(t, out, "new kid")
	if newKid == oldKid || !strings.Contains(out, oldKid) || !strings.Contains(out, "JWKS consumers") {
		t.Fatalf("out:\n%s", out)
	}
	after, _ := runKeys(t, "", "show")
	if showField(t, after, "kid") != newKid || !strings.HasPrefix(showField(t, after, "retired"), "1 key(s)") {
		t.Fatalf("show after rotate:\n%s", after)
	}
	jw, _ := runKeys(t, "", "jwks")
	if kids := jwksKids(t, jw); len(kids) != 2 || kids[0] != newKid || kids[1] != oldKid {
		t.Fatalf("jwks kids = %v", kids)
	}

	if _, err := runKeys(t, "yes\n", "rotate"); err != nil {
		t.Fatalf("confirmed prompt must rotate: %v", err)
	}
	after, _ = runKeys(t, "", "show")
	if !strings.HasPrefix(showField(t, after, "retired"), "2 key(s)") {
		t.Fatalf("show:\n%s", after)
	}
}

func TestKeysPrune(t *testing.T) {
	keysEnv(t, "file")
	if _, err := runKeys(t, "", "rotate", "-y"); err == nil || !strings.Contains(err.Error(), "no signing key") {
		t.Fatalf("rotate without a key must fail: %v", err)
	}
	if _, err := runKeys(t, "", "show"); err != nil {
		t.Fatal(err)
	}
	if _, err := runKeys(t, "", "rotate", "-y"); err != nil {
		t.Fatal(err)
	}
	out, err := runKeys(t, "", "prune")
	if err != nil || !strings.Contains(out, "pruned 0") {
		t.Fatalf("default 720h must keep a fresh key: %v\n%s", err, out)
	}
	out, err = runKeys(t, "", "prune", "--older-than", "0s")
	if err != nil || !strings.Contains(out, "pruned 1 retired key(s); 0 remain") {
		t.Fatalf("%v\n%s", err, out)
	}
	jw, _ := runKeys(t, "", "jwks")
	if kids := jwksKids(t, jw); len(kids) != 1 {
		t.Fatalf("jwks kids = %v", kids)
	}
	if _, err := runKeys(t, "", "prune", "--older-than", "-1h"); err == nil {
		t.Fatal("negative duration must fail")
	}
}

func TestKeysMigrateRoundTrip(t *testing.T) {
	home := keysEnv(t, "auto")
	path := filepath.Join(home, "ed25519.key")
	t.Setenv(jwt.KeyBackendEnv, "file")
	before, err := runKeys(t, "", "show")
	if err != nil {
		t.Fatal(err)
	}
	kid := showField(t, before, "kid")
	t.Setenv(jwt.KeyBackendEnv, "auto")

	out, err := runKeys(t, "", "migrate", "--to", "keychain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "from file to keychain") || !strings.Contains(out, kid) {
		t.Fatalf("out:\n%s", out)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("key file must be removed")
	}
	show, _ := runKeys(t, "", "show")
	if showField(t, show, "backend") != "keychain" || showField(t, show, "kid") != kid {
		t.Fatalf("show:\n%s", show)
	}

	out, err = runKeys(t, "", "migrate", "--to", "file")
	if err != nil || !strings.Contains(out, "from keychain to file") {
		t.Fatalf("%v\n%s", err, out)
	}
	show, _ = runKeys(t, "", "show")
	if showField(t, show, "backend") != "file" || showField(t, show, "kid") != kid {
		t.Fatalf("show:\n%s", show)
	}

	if _, err := runKeys(t, "", "migrate", "--to", "auto"); err == nil {
		t.Fatal("--to auto must be rejected")
	}
	if _, err := runKeys(t, "", "migrate"); err == nil {
		t.Fatal("--to is required")
	}
}

func TestKeysInvalidBackendEnv(t *testing.T) {
	keysEnv(t, "vault")
	if _, err := runKeys(t, "", "show"); err == nil || !strings.Contains(err.Error(), jwt.KeyBackendEnv) {
		t.Fatalf("got %v", err)
	}
}
