package cmd

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"
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
