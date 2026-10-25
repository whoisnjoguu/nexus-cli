//go:build unix || windows

package fslock

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Two independently opened handles on the same lock file exclude each other, as two processes would.
func TestAcquireExcludesSecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	release, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || (os.PathSeparator == '/' && fi.Mode().Perm() != 0o600) {
		t.Fatalf("lock file: %v %v", fi, err)
	}

	got := make(chan func(), 1)
	go func() {
		r, err := Acquire(path)
		if err != nil {
			t.Error(err)
			r = func() {}
		}
		got <- r
	}()
	select {
	case <-got:
		t.Fatal("second Acquire succeeded while the lock was held")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case r := <-got:
		r()
	case <-time.After(10 * time.Second):
		t.Fatal("second Acquire never got the lock after release")
	}
}

func TestLockUnlockOnOpenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "y.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Lock(f); err != nil {
		t.Fatal(err)
	}
	Unlock(f)
	// Released: Acquire must not block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if r, err := Acquire(path); err == nil {
			r()
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("lock not released by Unlock")
	}
}

func TestAcquireErrors(t *testing.T) {
	if _, err := Acquire(filepath.Join(t.TempDir(), "missing", "dir", "z.lock")); err == nil {
		t.Fatal("Acquire in a missing directory succeeded")
	}
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := Lock(f); err == nil {
		t.Fatal("Lock on a closed file succeeded")
	}
}
