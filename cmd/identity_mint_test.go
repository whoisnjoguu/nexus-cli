package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/whoisnjoguu/nexus-cli/pkg/jwt"
)

// resetFlags restores every flag of the given flag set to its default so package-level flag
// variables don't leak between command runs.
func resetFlags(t *testing.T, fs *pflag.FlagSet) {
	t.Helper()
	fs.VisitAll(func(f *pflag.Flag) {
		if err := f.Value.Set(f.DefValue); err != nil {
			t.Fatalf("reset --%s: %v", f.Name, err)
		}
		f.Changed = false
	})
}

func runMint(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	resetFlags(t, identityMintCmd.Flags())
	t.Cleanup(func() { resetFlags(t, identityMintCmd.Flags()) })
	var out, errb bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errb)
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	rootCmd.SetArgs(append([]string{"identity", "mint"}, args...))
	err = rootCmd.Execute()
	return out.String(), errb.String(), err
}

func TestMintQuietPrintsOnlyVerifiableToken(t *testing.T) {
	key := filepath.Join(t.TempDir(), "ed25519.key")
	out, _, err := runMint(t, "--key", key, "-a", "agent-x", "-u", "alice", "-q")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("quiet output should be exactly one line, got %q", out)
	}
	tok := strings.TrimSpace(out)
	if strings.Count(tok, ".") != 2 || strings.ContainsAny(tok, " \t") {
		t.Fatalf("quiet output is not a bare JWT: %q", out)
	}
	signer, err := jwt.LoadOrCreateSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := signer.Verifier().Verify(tok)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.AgentID != "agent-x" || claims.ActAs != "alice" || claims.SingleUse {
		t.Fatalf("claims = %+v", claims)
	}
	ttl := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if ttl != 900*time.Second {
		t.Fatalf("default ttl = %v, want 900s", ttl)
	}
}

func TestMintSingleUseSetsClaim(t *testing.T) {
	key := filepath.Join(t.TempDir(), "ed25519.key")
	out, _, err := runMint(t, "--key", key, "-a", "agent-x", "-u", "alice", "--single-use", "-q", "--ttl", "60")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := jwt.LoadOrCreateSigner(key)
	claims, err := signer.Verifier().Verify(strings.TrimSpace(out))
	if err != nil {
		t.Fatal(err)
	}
	if !claims.SingleUse {
		t.Fatal("--single-use did not set the single_use claim")
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != time.Minute {
		t.Fatalf("ttl = %v, want 60s", got)
	}

	// Flags must not leak into the next run.
	out, _, err = runMint(t, "--key", key, "-a", "agent-x", "-u", "alice", "-q")
	if err != nil {
		t.Fatal(err)
	}
	claims, _ = signer.Verifier().Verify(strings.TrimSpace(out))
	if claims == nil || claims.SingleUse {
		t.Fatalf("single_use leaked into next run: %+v", claims)
	}
}

func TestMintVerboseOutput(t *testing.T) {
	key := filepath.Join(t.TempDir(), "ed25519.key")
	out, _, err := runMint(t, "--key", key, "-a", "agent-x", "-u", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Micro-JWT:") || !strings.Contains(out, "reusable until expiry") {
		t.Fatalf("verbose output = %q", out)
	}
}

func TestMintRejectsNonPositiveTTL(t *testing.T) {
	key := filepath.Join(t.TempDir(), "ed25519.key")
	for _, ttl := range []string{"0", "-5"} {
		if _, _, err := runMint(t, "--key", key, "-a", "agent-x", "-u", "alice", "--ttl", ttl); err == nil || !strings.Contains(err.Error(), "--ttl") {
			t.Fatalf("--ttl %s: err = %v, want ttl validation error", ttl, err)
		}
	}
}

func TestPrincipalCapCanEmptyScopes(t *testing.T) {
	got := (&principalCap{[]string{"read"}}).cap([]string{"admin"})
	if len(got) != 0 {
		t.Fatalf("cap = %v, want empty", got)
	}
}
