//go:build !unix && !windows

package fslock

import "os"

// No advisory locking on this platform: only a single writing process is safe.
func lock(*os.File) error { return nil }

func unlock(*os.File) {}
