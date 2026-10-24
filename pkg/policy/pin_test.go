package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "home", "policy.pin")
	a, b := filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")
	if pinned, err := CheckPin(pinFile, a, []byte("x")); pinned || err != nil {
		t.Fatalf("no pin file: pinned=%v err=%v", pinned, err)
	}
	if err := WritePin(pinFile, a, Sum([]byte("A"))); err != nil {
		t.Fatal(err)
	}
	if err := WritePin(pinFile, b, Sum([]byte("B"))); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(pinFile); err != nil || (os.PathSeparator == '/' && fi.Mode().Perm() != 0o600) {
		t.Fatalf("pin file: %v %v", fi, err)
	}
	if pinned, err := CheckPin(pinFile, a, []byte("A")); !pinned || err != nil {
		t.Fatalf("a: pinned=%v err=%v", pinned, err)
	}
	_, err := CheckPin(pinFile, b, []byte("B2"))
	var mm *PinMismatchError
	if !errors.As(err, &mm) || mm.Pinned != Sum([]byte("B")) || mm.Actual != Sum([]byte("B2")) {
		t.Fatalf("b mismatch: %v", err)
	}
	if !strings.Contains(err.Error(), "--accept-policy-change") {
		t.Fatalf("message = %v", err)
	}
	// Relative and absolute forms are the same pin.
	wd, _ := os.Getwd()
	rel, _ := filepath.Rel(wd, a)
	if sum, ok, _ := ReadPin(pinFile, rel); !ok || sum != Sum([]byte("A")) {
		t.Fatalf("relative lookup: %v %v", sum, ok)
	}
	if err := WritePin(pinFile, a, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := ReadPin(pinFile, a); ok {
		t.Fatal("pin not removed")
	}
	if _, ok, _ := ReadPin(pinFile, b); !ok {
		t.Fatal("other pin lost")
	}
}

func TestPinMalformed(t *testing.T) {
	pinFile := filepath.Join(t.TempDir(), "policy.pin")
	if err := os.WriteFile(pinFile, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadPin(pinFile, "x"); err == nil {
		t.Fatal("malformed pin accepted")
	}
}

func TestPinPathUsesNexusHome(t *testing.T) {
	t.Setenv("NEXUS_HOME", "/somewhere")
	if p, err := PinPath(); err != nil || p != filepath.Join("/somewhere", "policy.pin") {
		t.Fatalf("PinPath = %q %v", p, err)
	}
}
