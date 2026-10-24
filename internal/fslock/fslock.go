// Package fslock provides advisory, exclusive, cross-process file locks (flock on unix,
// LockFileEx on Windows; a no-op elsewhere, where only a single process is safe).
package fslock

import (
	"fmt"
	"os"
)

// Lock blocks until it holds an exclusive lock on f.
func Lock(f *os.File) error { return lock(f) }

// Unlock releases a lock taken with Lock.
func Unlock(f *os.File) { unlock(f) }

// Acquire opens (creating with mode 0600) the lock file at path, locks it and returns a release
// function that unlocks and closes it.
func Acquire(path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	if err := lock(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		unlock(f)
		_ = f.Close()
	}, nil
}
