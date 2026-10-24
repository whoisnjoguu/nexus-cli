//go:build !unix && !windows

package audit

import "os"

// No advisory locking on this platform: only a single writing process is safe.
func lockFile(*os.File) error { return nil }

func unlockFile(*os.File) {}
