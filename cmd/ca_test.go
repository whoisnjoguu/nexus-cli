package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whoisnjoguu/nexus-cli/pkg/ca"
)

func runCA(t *testing.T, args ...string) (string, error) {
	t.Helper()
	caDir, caPathBundle, caInstallRun, caUninstallRun = "", false, false, false
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(append([]string{"ca"}, args...))
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		caDir, caPathBundle, caInstallRun, caUninstallRun = "", false, false, false
	})
	err := rootCmd.Execute()
	return out.String(), err
}

func TestCACommands(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	t.Setenv("SSL_CERT_FILE", "")

	if _, err := runCA(t, "path", "--dir", dir); err == nil || !strings.Contains(err.Error(), "nexus-cli ca init") {
		t.Fatalf("path before init should hint init, got %v", err)
	}
	if _, err := runCA(t, "fingerprint", "--dir", dir); err == nil {
		t.Fatal("fingerprint before init should fail")
	}

	out, err := runCA(t, "init", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ca.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{c.CertPath(), c.Fingerprint(), "nexus-cli ca install", "nexus-cli run"} {
		if !strings.Contains(out, want) {
			t.Errorf("init output missing %q:\n%s", want, out)
		}
	}

	out, err = runCA(t, "init", "--dir", dir)
	if err != nil || !strings.Contains(out, c.Fingerprint()) {
		t.Fatalf("re-init should reuse CA: %v\n%s", err, out)
	}

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"path", "--dir", dir}, c.CertPath()},
		{[]string{"fingerprint", "--dir", dir}, c.Fingerprint()},
		{[]string{"path", "--bundle", "--dir", dir}, c.BundlePath()},
		{[]string{"path", "--dir", dir}, c.CertPath()}, // --bundle must not leak between runs
	}
	for _, tc := range cases {
		out, err := runCA(t, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if strings.TrimSpace(out) != tc.want {
			t.Fatalf("%v: got %q want %q", tc.args, out, tc.want)
		}
	}
	data, err := os.ReadFile(c.BundlePath())
	if err != nil || !bytes.Contains(data, c.CertPEM()) {
		t.Fatalf("bundle not written: %v", err)
	}

	for _, sub := range []string{"install", "uninstall"} {
		out, err := runCA(t, sub, "--dir", dir)
		if err != nil {
			t.Fatalf("%s: %v", sub, err)
		}
		if !strings.Contains(out, "--run") || !strings.Contains(out, "Firefox") {
			t.Fatalf("%s output:\n%s", sub, out)
		}
	}
}

func TestShellJoin(t *testing.T) {
	got := shellJoin([]string{"security", "delete-certificate", "-c", "nexus-cli local CA", "it's"})
	want := `security delete-certificate -c 'nexus-cli local CA' 'it'\''s'`
	if got != want {
		t.Fatalf("got %s", got)
	}
}
