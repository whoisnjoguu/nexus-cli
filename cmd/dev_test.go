package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whoisnjoguu/nexus-cli/pkg/ca"
	"github.com/whoisnjoguu/nexus-cli/pkg/control"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8075": true,
		"[::1]:8075":     true,
		"localhost:8075": true,
		"0.0.0.0:8075":   false,
		"[::]:8075":      false,
		":8075":          false,
		"10.0.0.5:8075":  false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestDevFlagDefaults(t *testing.T) {
	if f := devCmd.Flags().Lookup("listen"); f == nil || f.DefValue != "" {
		t.Fatalf("--listen default = %+v, want empty", f)
	}
	if f := devCmd.Flags().Lookup("single-use"); f == nil || f.DefValue != "false" {
		t.Fatalf("--single-use default = %+v, want false", f)
	}
}

func TestDevServesHealthAndShutsDown(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetFlags(t, devCmd.Flags())
	t.Cleanup(func() { resetFlags(t, devCmd.Flags()) })
	dir := t.TempDir()

	out := &syncBuffer{}
	errb := &syncBuffer{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(errb)
	rootCmd.SetArgs([]string{"dev", "--port", "0", "--no-audit",
		"--key", filepath.Join(dir, "k"), "--policy", filepath.Join(dir, "none.yaml")})
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rootCmd.ExecuteContext(ctx) }()

	re := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`)
	var addr string
	deadline := time.Now().Add(5 * time.Second)
	for addr == "" && time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			addr = m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		cancel()
		t.Fatalf("dev did not report a loopback listen address; out=%q err=%q", out.String(), errb.String())
	}
	if errb.String() != "" {
		t.Fatalf("unexpected warning for loopback bind: %q", errb.String())
	}

	resp, err := http.Get("http://" + addr + "/_nexus/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("dev returned %v on shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dev did not shut down")
	}
}

func TestDevWarnsOnNonLoopbackListen(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	resetFlags(t, devCmd.Flags())
	t.Cleanup(func() { resetFlags(t, devCmd.Flags()) })
	dir := t.TempDir()

	out := &syncBuffer{}
	errb := &syncBuffer{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(errb)
	rootCmd.SetArgs([]string{"dev", "--listen", "0.0.0.0:0", "--no-audit",
		"--key", filepath.Join(dir, "k"), "--policy", filepath.Join(dir, "none.yaml")})
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rootCmd.ExecuteContext(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for !regexp.MustCompile(`listening on`).MatchString(out.String()) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`WARNING: proxy is listening on non-loopback address`).MatchString(errb.String()) {
		t.Fatalf("missing non-loopback warning; stderr=%q", errb.String())
	}
}

func TestDevNewFlagDefaults(t *testing.T) {
	if f := devCmd.Flags().Lookup("approval-timeout"); f == nil || f.DefValue != "1m0s" {
		t.Fatalf("--approval-timeout default = %+v, want 1m0s", f)
	}
	if f := devCmd.Flags().Lookup("mitm"); f == nil || f.DefValue != "auto" {
		t.Fatalf("--mitm default = %+v, want auto", f)
	}
}

// startDev runs `nexus-cli dev` with an isolated HOME/NEXUS_HOME and returns the bound address,
// stdout and a stop function that waits for shutdown.
func startDev(t *testing.T, extra ...string) (addr string, out *syncBuffer, stop func() error) {
	t.Helper()
	resetFlags(t, devCmd.Flags())
	t.Cleanup(func() { resetFlags(t, devCmd.Flags()) })
	dir := t.TempDir()
	out, errb := &syncBuffer{}, &syncBuffer{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(errb)
	rootCmd.SetArgs(append([]string{"dev", "--port", "0", "--no-audit",
		"--key", filepath.Join(dir, "k"), "--policy", filepath.Join(dir, "none.yaml")}, extra...))
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	// cobra only sets a subcommand's context when it has none, so a cancelled one from an
	// earlier Execute would otherwise stick.
	devCmd.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- rootCmd.ExecuteContext(ctx) }()
	stop = func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatal("dev did not shut down")
			return nil
		}
	}
	re := regexp.MustCompile(`listening on (127\.0\.0\.1:\d+)`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(out.String()); m != nil && regexp.MustCompile(`approvals:`).MatchString(out.String()) {
			return m[1], out, stop
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = stop()
	t.Fatalf("dev did not start; out=%q err=%q", out.String(), errb.String())
	return "", nil, nil
}

func devHealth(t *testing.T, addr string) map[string]string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/_nexus/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var h map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestDevMITMModes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	nexusHome := t.TempDir()
	t.Setenv("NEXUS_HOME", nexusHome)
	caDir := filepath.Join(nexusHome, "ca")

	for _, mode := range []string{"off", "auto"} {
		addr, out, stop := startDev(t, "--mitm", mode)
		if h := devHealth(t, addr); h["mitm"] != "off" {
			t.Errorf("--mitm %s without a CA: health mitm = %q", mode, h["mitm"])
		}
		if !strings.Contains(out.String(), "HTTPS interception: off") {
			t.Errorf("--mitm %s: missing off status in %q", mode, out.String())
		}
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(caDir); err == nil {
			t.Fatalf("--mitm %s created a CA", mode)
		}
	}

	addr, out, stop := startDev(t, "--mitm", "on")
	c, err := ca.Load(caDir)
	if err != nil {
		t.Fatalf("--mitm on did not create the CA: %v", err)
	}
	h := devHealth(t, addr)
	if h["mitm"] != "on" || h["ca_fingerprint"] != c.Fingerprint() {
		t.Errorf("health = %v, want mitm on with fingerprint %s", h, c.Fingerprint())
	}
	if !strings.Contains(out.String(), "HTTPS interception: on (CA: "+c.CertPath()+", 0 passthrough") {
		t.Errorf("missing on status in %q", out.String())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	// auto picks up the CA that now exists.
	addr, _, stop = startDev(t)
	if h := devHealth(t, addr); h["mitm"] != "on" {
		t.Errorf("--mitm auto with an existing CA: health mitm = %q", h["mitm"])
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

func TestDevRejectsBadMITMMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NEXUS_HOME", t.TempDir())
	resetFlags(t, devCmd.Flags())
	t.Cleanup(func() { resetFlags(t, devCmd.Flags()) })
	rootCmd.SetOut(&syncBuffer{})
	rootCmd.SetErr(&syncBuffer{})
	rootCmd.SetArgs([]string{"dev", "--port", "0", "--no-audit", "--mitm", "sometimes"})
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	if err := rootCmd.Execute(); err == nil || !strings.Contains(err.Error(), "mitm") {
		t.Fatalf("err = %v", err)
	}
}

func TestDevRegistersControlEndpoint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("NEXUS_HOME", t.TempDir())
	addr, out, stop := startDev(t, "--mitm", "off")
	if !strings.Contains(out.String(), "approvals: ") || !strings.Contains(out.String(), "nexus-cli approve") {
		t.Errorf("missing approvals hint: %q", out.String())
	}
	infos, err := control.Discover()
	if err != nil || len(infos) != 1 || infos[0].Kind != "dev" || infos[0].Listen != addr {
		t.Fatalf("control endpoints while running = %+v (err %v), want one dev endpoint for %s", infos, err, addr)
	}
	files, _ := filepath.Glob(filepath.Join(os.Getenv("NEXUS_HOME"), "control", "*"))
	if len(files) == 0 {
		t.Fatal("no control discovery file written")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if infos, _ := control.Discover(); len(infos) != 0 {
		t.Fatalf("control endpoint not removed on shutdown: %+v", infos)
	}
	if files, _ := filepath.Glob(filepath.Join(os.Getenv("NEXUS_HOME"), "control", "*")); len(files) != 0 {
		t.Fatalf("control files left behind: %v", files)
	}
}
