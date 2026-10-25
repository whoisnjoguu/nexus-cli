package audit

import (
	"os"

	"github.com/whoisnjoguu/nexus-cli/internal/fslock"
)

func lockFile(f *os.File) error { return fslock.Lock(f) }

func unlockFile(f *os.File) { fslock.Unlock(f) }
